//! `Persist` wrapper that puts the secrets behind the PIN.
//!
//! * The 32-byte master seed lives in the vault (src/vault.rs), wrapped under the PIN with
//!   Argon2id once a PIN is set. After a correct PIN the seed is kept in RAM ONLY as XOR shares
//!   (src/ram_guard.rs, src/guard.rs), refreshed every millisecond and around every key use, until
//!   `lock_now()` (USB reset / suspend / unplug) or power-off. The 128 bytes OpenSK's key store
//!   uses are derived from the seed on demand and wiped right after.
//!   OpenSK's default key store (`key_store::Helper`) reads those bytes through
//!   `key_store_bytes()`, which is overridden here: the master is never written to the
//!   key-value store, and while locked every credential-ID operation fails.
//! * Resident credentials (CREDENTIALS key range) are encrypted + authenticated under keys
//!   derived from the master. Everything else (RP IDs of non-resident credentials are never
//!   stored; counters, large blobs, settings) stays in clear.
//! * PIN verification: the Argon2 tag is the verifier. The stored PIN "hash" is all zeros. The
//!   patched `verify_pin_hash_enc` (third_party/opensk-harden.patch) calls `unlock_with_pin`.
//! * The PIN retry counter is the vault's power-cut-safe counter, not OpenSK's.
use alloc::vec::Vec;
use core::cell::RefCell;
use defmt::{error, warn};
use portable_atomic::{AtomicBool, Ordering};
use hmac::{Hmac, Mac};
use opensk::api::persist::{keys, Persist, PersistIter};
use opensk::ctap::secret::Secret;
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::PicoPersist;
use crate::guard;
use crate::puf::{Puf, Status as PufStatus};
use crate::keys::fill_random;
use crate::store::{Record, Replaced, Vault, TRIES_MAX};
use crate::vault::FlashVault;
use crate::wrap;

/// True while the vault record is PIN-wrapped, i.e. while forgetting the seed is a real lock.
static WRAPPED: AtomicBool = AtomicBool::new(false);

/// Forgets the seed immediately when a PIN protects it (no-op without a PIN). Callable from any
/// context: the USB handler calls it on reset / suspend / disconnect, so an operation that is
/// still running cannot start another key use.
pub fn lock_now() {
    if WRAPPED.load(Ordering::Relaxed) {
        guard::clear_seed();
    }
}

const NONCE: usize = 16;
const TAG: usize = 32;

struct State {
    vault: FlashVault,
    /// `None`: the vault is unusable (damaged / unreadable) until a CTAP reset.
    rec: Option<Record>,
    /// Retry-counter page of the PIN attempt in progress.
    pending: Option<usize>,
}

pub struct HardenPersist {
    raw: PicoPersist,
    st: RefCell<State>,
    /// SRAM PUF (src/puf.rs). Its key is derived on demand and never stored.
    puf: Puf,
}

type Hm = Hmac<Sha256>;

fn mac(key: &[u8], parts: &[&[u8]]) -> Hm {
    let mut m = <Hm as Mac>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m
}

fn sub_key(master: &[u8; 128], label: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(mac(master, &[label]).finalize().into_bytes().into())
}

fn xor_stream(k_enc: &[u8; 32], nonce: &[u8], data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(32).enumerate() {
        let mut ks: [u8; 32] = mac(k_enc, &[nonce, &(i as u32).to_le_bytes()])
            .finalize()
            .into_bytes()
            .into();
        for (d, k) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= k;
        }
        ks.zeroize();
    }
}

fn tag(k_mac: &[u8; 32], key: usize, nonce: &[u8], ct: &[u8]) -> Hm {
    mac(k_mac, &[b"cred", &(key as u32).to_le_bytes(), nonce, ct])
}

fn seal(master: &[u8; 128], key: usize, plain: &[u8]) -> Vec<u8> {
    let k_enc = sub_key(master, b"harden-cred-enc");
    let k_mac = sub_key(master, b"harden-cred-mac");
    let mut nonce = [0u8; NONCE];
    fill_random(&mut nonce);
    let mut out = Vec::with_capacity(NONCE + plain.len() + TAG);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(plain);
    xor_stream(&k_enc, &nonce, &mut out[NONCE..]);
    let t = tag(&k_mac, key, &nonce, &out[NONCE..]).finalize().into_bytes();
    out.extend_from_slice(&t);
    out
}

fn open(master: &[u8; 128], key: usize, blob: &[u8]) -> CtapResult<Vec<u8>> {
    if blob.len() < NONCE + TAG {
        return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
    }
    let k_enc = sub_key(master, b"harden-cred-enc");
    let k_mac = sub_key(master, b"harden-cred-mac");
    let (nonce, rest) = blob.split_at(NONCE);
    let (ct, t) = rest.split_at(rest.len() - TAG);
    let expect = tag(&k_mac, key, nonce, ct).finalize().into_bytes();
    if !bool::from(expect.as_slice().ct_eq(t)) {
        return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
    }
    let mut plain = ct.to_vec();
    xor_stream(&k_enc, nonce, &mut plain);
    Ok(plain)
}

fn hw_fail() -> Ctap2StatusCode {
    Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE
}

/// Clears the retry counter or fails; one retry for a transient flash error. A failure must reach
/// the caller: a counter that stays full would block the (new) PIN for good.
fn clear_tries_checked(v: &mut FlashVault) -> CtapResult<()> {
    for _ in 0..2 {
        if v.clear_tries().is_ok() {
            return Ok(());
        }
    }
    error!("vault: retry counter could not be cleared");
    Err(hw_fail())
}

/// A plain record keeps the seed in `body`; the seed lives in the guard, so the RAM copy of the
/// record is scrubbed (a wrapped record only holds ciphertext and stays as is).
fn scrubbed(mut rec: Record) -> Record {
    if !rec.wrapped {
        rec.body.zeroize();
    }
    rec
}

impl HardenPersist {
    pub fn new(raw: PicoPersist, vault: FlashVault, rec: Option<Record>, mut puf: Puf) -> Self {
        let mut st = State {
            vault,
            rec: None,
            pending: None,
        };
        // First boot with the PUF feature: enrol now (only a power-on reset can).
        if puf.status() == PufStatus::Blank {
            puf.enroll();
        }
        let key = puf.key();
        if let Some(r) = rec {
            WRAPPED.store(r.wrapped, Ordering::Relaxed);
            if r.puf && key.is_none() {
                // Bound to the PUF but this boot cannot recover the key: do not guess, do not
                // count it as a wrong PIN, do not touch the record.
                error!("puf: record is PUF-bound but the key is unavailable - unplug for 10 s, or CTAP reset");
                WRAPPED.store(false, Ordering::Relaxed);
            } else if !r.wrapped {
                // Without a PIN the seed is available right away (unmasked with the PUF key).
                let kref = if r.puf { key.as_ref().map(|k| &**k) } else { None };
                match wrap::plain_seed(&r, kref) {
                    Some(seed) if guard::store_seed(&seed) => {
                        let mut keep = r;
                        // Not yet bound, but a PUF key exists: bind the plain seed now.
                        if !keep.puf {
                            if let Some(k) = key.as_ref() {
                                let up = wrap::plain_puf(&seed, &**k);
                                match st.vault.replace(&up) {
                                    Replaced::New(s) => {
                                        if !s.old_wiped && !matches!(st.vault.purge_stale(), Ok(true)) {
                                            warn!("puf: the unbound record could not be wiped");
                                        }
                                        keep = up;
                                    }
                                    Replaced::Kept(_) => warn!("puf: could not bind the seed, keeping the unbound record"),
                                    Replaced::NoKey | Replaced::Unknown => {
                                        st.fail_closed();
                                        return HardenPersist { raw, st: RefCell::new(st), puf };
                                    }
                                }
                            }
                        }
                        st.rec = Some(scrubbed(keep));
                    }
                    _ => error!("guard: could not store the seed"),
                }
            } else {
                st.rec = Some(scrubbed(r));
            }
        }
        HardenPersist {
            raw,
            st: RefCell::new(st),
            puf,
        }
    }

    /// Forgets the master key (the next use needs the PIN again). No-op without a PIN.
    pub fn lock(&mut self) {
        lock_now();
    }

    /// Derives the 128-byte key-store master from the masked seed. The shares are refreshed
    /// before and right after the reveal, and every plaintext temporary is wiped on drop.
    fn master(&self) -> CtapResult<Zeroizing<[u8; 128]>> {
        if self.st.borrow().rec.is_none() {
            return Err(hw_fail());
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        if !guard::reveal_seed_into(&mut seed) {
            return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
        }
        let mut m = Zeroizing::new([0u8; 128]);
        wrap::expand_into(&seed, &mut m);
        Ok(m)
    }
}

impl State {
    /// The state after a failed vault update whose outcome is unknown: no key is usable until a
    /// CTAP reset (same as a damaged vault at boot).
    fn fail_closed(&mut self) {
        error!("vault: unknown flash state - locking until reset");
        self.rec = None;
        self.pending = None;
        WRAPPED.store(false, Ordering::Relaxed);
        guard::clear_seed();
    }
}

impl Persist for HardenPersist {
    fn find(&self, key: usize) -> CtapResult<Option<Vec<u8>>> {
        let value = self.raw.find(key)?;
        match value {
            Some(blob) if keys::CREDENTIALS.contains(&key) => {
                let m = self.master()?;
                Ok(Some(open(&m, key, &blob)?))
            }
            other => Ok(other),
        }
    }

    fn insert(&mut self, key: usize, value: &[u8]) -> CtapResult<()> {
        if keys::CREDENTIALS.contains(&key) {
            let m = self.master()?;
            let blob = seal(&m, key, value);
            self.raw.insert(key, &blob)
        } else {
            self.raw.insert(key, value)
        }
    }

    fn remove(&mut self, key: usize) -> CtapResult<()> {
        self.raw.remove(key)
    }

    fn iter(&self) -> CtapResult<PersistIter<'_>> {
        self.raw.iter()
    }

    // ---- master key: served from RAM, never written to the key-value store -------------------

    fn key_store_bytes(&self) -> CtapResult<Option<Secret<[u8]>>> {
        let m = self.master()?;
        let mut s = Secret::new(128);
        s.copy_from_slice(&m[..]);
        Ok(Some(s))
    }

    fn write_key_store_bytes(&mut self, _bytes: &[u8]) -> CtapResult<()> {
        // Only reachable if `key_store_bytes` returned None, which it never does.
        Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
    }

    // ---- PIN ---------------------------------------------------------------------------------

    /// Called by the patched `verify_pin_hash_enc`. Argon2 tag = verifier (compared in constant
    /// time in `wrap::unwrap`).
    fn unlock_with_pin(&mut self, pin_hash: &[u8; 16]) -> CtapResult<Option<bool>> {
        let st = self.st.get_mut();
        let rec = st.rec.clone().ok_or_else(hw_fail)?;
        if !rec.wrapped {
            // OpenSK believes a PIN is set but the vault has none (interrupted setPIN):
            // nobody can unlock this, a CTAP reset is needed.
            return Ok(Some(false));
        }
        // PUF key, derived now and wiped on drop. A PUF-bound record cannot be checked without
        // it, and that is not a wrong PIN: the attempt already counted is refunded.
        let key = self.puf.key();
        if rec.puf && key.is_none() {
            if let Some(page) = st.pending.take() {
                let _ = st.vault.finish_try(page);
            }
            error!("puf: key unavailable - unplug for 10 s and retry (not counted as a wrong PIN)");
            return Err(hw_fail());
        }
        let kref = if rec.puf { key.as_ref().map(|k| &**k) } else { None };
        guard::refresh_now();
        let ok = match wrap::unwrap(&rec, pin_hash, kref) {
            Some(seed) => {
                if !guard::store_seed(&seed) {
                    return Err(hw_fail());
                }
                // Record not yet PUF-bound but a key exists: bind it now that the PIN is at hand.
                if !rec.puf {
                    if let Some(k) = key.as_ref() {
                        let mut salt = [0u8; 16];
                        fill_random(&mut salt);
                        if let Some(up) = wrap::wrap(&seed, pin_hash, salt, Some(&**k)) {
                            match st.vault.replace(&up) {
                                Replaced::New(s) => {
                                    if !s.old_wiped && !matches!(st.vault.purge_stale(), Ok(true)) {
                                        warn!("puf: the unbound record could not be wiped");
                                    }
                                    st.rec = Some(up);
                                }
                                Replaced::Kept(_) => warn!("puf: could not bind the PIN record, keeping the unbound one"),
                                Replaced::NoKey | Replaced::Unknown => {
                                    st.fail_closed();
                                    return Err(hw_fail());
                                }
                            }
                        }
                    }
                }
                true
            }
            None => false,
        };
        guard::refresh_now();
        Ok(Some(ok))
    }

    fn set_pin(&mut self, pin_hash: &[u8; 16], pin_code_point_length: u8) -> CtapResult<()> {
        let key = self.puf.key();
        {
            let st = self.st.get_mut();
            if !guard::has_seed() {
                return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
            }
            if key.is_none() && st.rec.as_ref().map_or(false, |r| r.puf) {
                error!("set_pin: PUF key unavailable");
                return Err(hw_fail());
            }
            // 1. Counter first. The caller is authenticated (no PIN yet, or the old PIN was just
            //    verified), so clearing it early gives nothing away, and a failure here changes
            //    nothing at all.
            clear_tries_checked(&mut st.vault)?;
            // 2. Wrap the seed under the new PIN.
            let rec = {
                let mut seed = Zeroizing::new([0u8; 32]);
                if !guard::reveal_seed_into(&mut seed) {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
                }
                let mut salt = [0u8; 16];
                fill_random(&mut salt);
                wrap::wrap(&seed, pin_hash, salt, key.as_ref().map(|k| &**k)).ok_or_else(hw_fail)?
            };
            guard::refresh_now();
            // 3. Commit. Only a record that is durable AND whose predecessor was verified wiped
            //    counts as success.
            match st.vault.replace(&rec) {
                Replaced::New(saved) => {
                    st.rec = Some(rec);
                    st.pending = None;
                    WRAPPED.store(true, Ordering::Relaxed);
                    if !saved.old_wiped && !matches!(st.vault.purge_stale(), Ok(true)) {
                        // The new record wins on every boot, but the previous (plain or
                        // old-PIN) record may still be readable: do NOT report success. The seed
                        // stays usable in RAM, so setting the PIN again in this session retries
                        // the erase (the next save targets exactly that slot); after a lock or
                        // power cycle a CTAP reset is needed.
                        error!("set_pin: previous record could not be wiped - PIN setup failed");
                        return Err(hw_fail());
                    }
                }
                // Nothing changed: the old record is still the newest one.
                Replaced::Kept(_) => return Err(hw_fail()),
                // The flash state is unknown or empty: stop using any key.
                Replaced::NoKey | Replaced::Unknown => {
                    st.fail_closed();
                    return Err(hw_fail());
                }
            }
        }
        // The stored PIN "hash" is zeros: the real check is the Argon2 tag in the vault.
        let mut props = [0u8; 17];
        props[0] = pin_code_point_length;
        self.raw.insert(keys::PIN_PROPERTIES, &props)?;
        // If power fails between these 2 transactions, PIN has to be set again.
        self.raw.remove(keys::FORCE_PIN_CHANGE)
    }

    fn pin_fails(&self) -> CtapResult<u8> {
        self.st
            .borrow_mut()
            .vault
            .tries_used()
            .map_err(|_| hw_fail())
    }

    fn incr_pin_fails(&mut self) -> CtapResult<()> {
        let st = self.st.get_mut();
        if st.vault.tries_used().map_err(|_| hw_fail())? as usize >= TRIES_MAX {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
        }
        // Written BEFORE the PIN is evaluated, so cutting power cannot undo the attempt.
        let page = st.vault.begin_try().map_err(|_| hw_fail())?;
        st.pending = Some(page);
        Ok(())
    }

    fn reset_pin_retries(&mut self) -> CtapResult<()> {
        let st = self.st.get_mut();
        match st.pending.take() {
            Some(page) => st.vault.finish_try(page).map_err(|_| hw_fail()),
            None => st.vault.clear_tries().map_err(|_| hw_fail()),
        }
    }

    // ---- factory reset -----------------------------------------------------------------------

    fn reset(&mut self) -> CtapResult<()> {
        // Marker first: if anything fails below, `init` repeats the whole reset on the next boot.
        self.raw.insert(keys::RESET_COMPLETION, &[])?;
        let mut seed = Zeroizing::new([0u8; 32]);
        fill_random(&mut seed[..]);
        // Bind the new seed to the PUF. Without a usable key, (re-)enrol first: a reset wipes
        // everything that depended on the old key anyway. That needs a power-on reset; if there
        // is none, the new seed is stored unbound and gets bound at a later boot.
        if !matches!(self.puf.status(), PufStatus::Ready | PufStatus::Disabled) {
            self.puf.enroll();
        }
        let key = self.puf.key();
        let rec = match key.as_ref() {
            Some(k) => wrap::plain_puf(&seed, &**k),
            None => Record::plain(*seed),
        };
        {
            let st = self.st.get_mut();
            match st.vault.replace(&rec) {
                Replaced::New(saved) => {
                    // The old seed must not stay readable after a factory reset either.
                    let wiped = saved.old_wiped || matches!(st.vault.purge_stale(), Ok(true));
                    st.rec = Some(scrubbed(rec));
                    st.pending = None;
                    WRAPPED.store(false, Ordering::Relaxed);
                    if !guard::store_seed(&seed) {
                        st.fail_closed();
                        return Err(hw_fail());
                    }
                    if !wiped {
                        error!("reset: previous record could not be wiped");
                        return Err(hw_fail());
                    }
                    // The new seed is durable, so the old counter is meaningless: a counter that
                    // cannot be cleared must fail the reset (marker stays, boot repeats it)
                    // instead of leaving a fresh PIN blocked.
                    clear_tries_checked(&mut st.vault)?;
                }
                Replaced::Kept(_) => {
                    error!("reset: vault could not be re-initialised");
                    return Err(hw_fail());
                }
                Replaced::NoKey | Replaced::Unknown => {
                    st.fail_closed();
                    return Err(hw_fail());
                }
            }
        }
        // Removes every non-persistent key (credentials, PIN, counters ...) and the marker.
        Persist::reset(&mut self.raw)
    }
}
