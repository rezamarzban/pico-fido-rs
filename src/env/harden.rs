//! `Persist` wrapper that puts the secrets behind the PIN.
//!
//! * The 32-byte master seed lives in the vault (src/vault.rs), wrapped under the PIN with
//!   Argon2id once a PIN is set. After a correct PIN it is expanded to the 128 bytes OpenSK's key
//!   store uses and kept in RAM until `lock()` (USB reset / suspend) or power-off.
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
use portable_atomic::AtomicBool;
use defmt::{error, warn};
use hmac::{Hmac, Mac};
use opensk::api::persist::{keys, Persist, PersistIter};
use opensk::ctap::secret::Secret;
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::PicoPersist;
use crate::keys::fill_random;
use crate::store::{Record, Replaced, Vault, TRIES_MAX};
use crate::vault::FlashVault;
use crate::wrap;

/// Set by the USB handler (reset / disabled / suspend); the main loop then calls `lock()`.
pub static LOCK_REQUEST: AtomicBool = AtomicBool::new(false);

const NONCE: usize = 16;
const TAG: usize = 32;

struct State {
    vault: FlashVault,
    /// `None`: the vault is unusable (damaged / unreadable) until a CTAP reset.
    rec: Option<Record>,
    seed: Option<Zeroizing<[u8; 32]>>,
    master: Option<Zeroizing<[u8; 128]>>,
    /// Retry-counter page of the PIN attempt in progress.
    pending: Option<usize>,
}

pub struct HardenPersist {
    raw: PicoPersist,
    st: RefCell<State>,
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
        let ks = mac(k_enc, &[nonce, &(i as u32).to_le_bytes()]).finalize().into_bytes();
        for (d, k) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= k;
        }
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
    tag(&k_mac, key, nonce, ct)
        .verify_slice(t)
        .map_err(|_| Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
    let mut plain = ct.to_vec();
    xor_stream(&k_enc, nonce, &mut plain);
    Ok(plain)
}

fn hw_fail() -> Ctap2StatusCode {
    Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE
}

impl HardenPersist {
    pub fn new(raw: PicoPersist, vault: FlashVault, rec: Option<Record>) -> Self {
        let mut st = State {
            vault,
            rec,
            seed: None,
            master: None,
            pending: None,
        };
        // Without a PIN the seed is stored in clear, so it is available right away.
        if let Some(r) = &st.rec {
            if !r.wrapped {
                st.set_seed(r.body);
            }
        }
        HardenPersist {
            raw,
            st: RefCell::new(st),
        }
    }

    /// Forgets the master key (the next use needs the PIN again). No-op without a PIN.
    pub fn lock(&mut self) {
        let st = self.st.get_mut();
        if matches!(&st.rec, Some(r) if r.wrapped) {
            st.seed = None;
            st.master = None;
        }
    }

    fn master(&self) -> CtapResult<Zeroizing<[u8; 128]>> {
        let st = self.st.borrow();
        if st.rec.is_none() {
            return Err(hw_fail());
        }
        st.master
            .clone()
            .ok_or(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)
    }
}

impl State {
    fn set_seed(&mut self, seed: [u8; 32]) {
        self.master = Some(Zeroizing::new(wrap::expand(&seed)));
        self.seed = Some(Zeroizing::new(seed));
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

    /// Called by the patched `verify_pin_hash_enc`. Argon2 tag = verifier.
    fn unlock_with_pin(&mut self, pin_hash: &[u8; 16]) -> CtapResult<Option<bool>> {
        let st = self.st.get_mut();
        let rec = st.rec.clone().ok_or_else(hw_fail)?;
        if !rec.wrapped {
            // OpenSK believes a PIN is set but the vault has none (interrupted setPIN):
            // nobody can unlock this, a CTAP reset is needed.
            return Ok(Some(false));
        }
        match wrap::unwrap(&rec, pin_hash) {
            Some(seed) => {
                st.set_seed(seed);
                Ok(Some(true))
            }
            None => Ok(Some(false)),
        }
    }

    fn set_pin(&mut self, pin_hash: &[u8; 16], pin_code_point_length: u8) -> CtapResult<()> {
        {
            let st = self.st.get_mut();
            let seed = st
                .seed
                .clone()
                .ok_or(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)?;
            let mut salt = [0u8; 16];
            fill_random(&mut salt);
            let rec = wrap::wrap(&seed, pin_hash, salt).ok_or_else(hw_fail)?;
            match st.vault.replace(&rec) {
                Replaced::New(saved) => {
                    if !saved.old_wiped {
                        warn!("set_pin: the previous record could not be wiped");
                    }
                }
                _ => return Err(hw_fail()),
            }
            st.rec = Some(rec);
            st.pending = None;
            let _ = st.vault.clear_tries();
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
        // Marker first: if power fails below, `init` repeats the whole reset on the next boot.
        self.raw.insert(keys::RESET_COMPLETION, &[])?;
        let mut seed = Zeroizing::new([0u8; 32]);
        fill_random(&mut seed[..]);
        let rec = Record::plain(*seed);
        {
            let st = self.st.get_mut();
            match st.vault.replace(&rec) {
                Replaced::New(_) => {}
                _ => {
                    error!("reset: vault could not be re-initialised");
                    return Err(hw_fail());
                }
            }
            let _ = st.vault.clear_tries();
            st.rec = Some(rec);
            st.pending = None;
            st.set_seed(*seed);
        }
        // Removes every non-persistent key (credentials, PIN, counters ...) and the marker.
        Persist::reset(&mut self.raw)
    }
}
