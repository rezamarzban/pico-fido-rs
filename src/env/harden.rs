//! `Persist` wrapper that puts the secrets behind the PIN.
//!
//! * The 32-byte master seed lives in the vault (src/vault.rs), wrapped under the PIN with
//!   Argon2id once a PIN is set. After a correct PIN the seed is kept in RAM ONLY as XOR shares
//!   (src/ram_guard.rs, src/guard.rs), refreshed (adaptively, every 0.5 to 2 ms while a seed is held) and around every key use, until
//!   `lock_now()` (USB reset / suspend / unplug) or power-off. The 128 bytes OpenSK's key store
//!   uses are derived from the seed on demand and wiped right after.
//!   OpenSK's default key store (`key_store::Helper`) reads those bytes through
//!   `key_store_bytes()`, which is overridden here: the master is never written to the
//!   key-value store, and while locked every credential-ID operation fails.
//! * Resident credentials (CREDENTIALS key range) are encrypted + authenticated (AES-256-GCM) under keys
//!   derived from the master. Everything else (RP IDs of non-resident credentials are never
//!   stored; counters, large blobs, settings) stays in clear.
//! * PIN verification in TWO STAGES, because the host PIN and the IR PIN are separate:
//!   1. host PIN, in the host's own PIN dialog (`unlock_with_pin`, called by the patched
//!      `verify_pin_hash_enc`): checked against the host verifier in the vault record (Argon2id), nothing else
//!      is asked, the host gets its PIN token at once. The hash is kept (RAM guard) for stage 2.
//!   2. IR PIN, at the physical-button stage of the first command that needs the key: the IR PIN entry
//!      and the button press are one step (`ir_pin.rs`, `user_presence.rs`, or `ir_stage` below when the
//!      key is needed first). Host PIN + IR PIN + PUF secret -> Argon2id -> 256-bit key -> AES-256-GCM
//!      opens the seed. A wrong IR PIN is detected by the GCM tag. Afterwards EVERY physical-button
//!      confirmation of the session needs the IR PIN again (compared with the proven digest in RAM).
//!   The stored PIN "hash" in OpenSK's storage is all zeros.
//! * The PIN retry counter is the vault's power-cut-safe counter, not OpenSK's. Both stages count.
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use alloc::vec::Vec;
use core::cell::RefCell;
use defmt::{error, warn};
use portable_atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use hmac::{Hmac, Mac};
use opensk::api::persist::{keys, Persist, PersistIter};
use opensk::ctap::secret::Secret;
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "ir")]
use super::hid;
use super::PicoPersist;
use crate::guard;
use crate::puf::{self, Puf, Status as PufStatus};
use crate::keys::fill_random;
use crate::store::{Record, Replaced, Vault, TRIES_MAX};
use crate::vault::FlashVault;
use crate::wrap;

/// True while the vault record is PIN-wrapped, i.e. while forgetting the seed is a real lock.
static WRAPPED: AtomicBool = AtomicBool::new(false);

/// Where the IR PIN stands (see `ir_mode`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IrMode {
    /// No IR PIN involved: no PIN set, or built without the `ir` feature.
    None,
    /// A PIN is set but protected by the host PIN alone: the IR PIN is enrolled at the next
    /// physical-button stage.
    Enroll,
    /// An IR PIN protects the seed and it has not been entered in this session yet.
    Verify,
    /// The IR PIN was proven in this session: every physical-button confirmation asks for it again and
    /// compares it with the proven one.
    Session,
}

static IR_MODE: AtomicU8 = AtomicU8::new(0);

fn set_mode(m: IrMode) {
    IR_MODE.store(
        match m {
            IrMode::None => 0,
            IrMode::Enroll => 1,
            IrMode::Verify => 2,
            IrMode::Session => 3,
        },
        Ordering::Release,
    );
}

pub fn ir_mode() -> IrMode {
    match IR_MODE.load(Ordering::Acquire) {
        1 => IrMode::Enroll,
        2 => IrMode::Verify,
        3 => IrMode::Session,
        _ => IrMode::None,
    }
}

/// The mode of a freshly loaded / written PIN record.
fn mode_of(rec: &Record) -> IrMode {
    if !rec.wrapped || !cfg!(feature = "ir") {
        IrMode::None
    } else if rec.ir {
        IrMode::Verify
    } else {
        IrMode::Enroll
    }
}

/// A PIN-wrapped vault is loaded (for the display).
pub fn pin_set() -> bool {
    WRAPPED.load(Ordering::Relaxed)
}

/// Forgets the seed, the host PIN hash and the IR PIN digest immediately when a PIN protects the
/// seed (no-op without a PIN). Callable from any context: the USB handler calls it on reset /
/// suspend / disconnect, so an operation that is still running cannot start another key use.
pub fn lock_now() {
    if WRAPPED.load(Ordering::Relaxed) {
        guard::clear_seed();
        guard::clear_host();
        guard::clear_ir();
        // A session that had proven the IR PIN needs it again.
        let _ = IR_MODE.compare_exchange(3, 2, Ordering::AcqRel, Ordering::Acquire);
    }
}

// ---- IR PIN helpers shared with the physical-button stage (user_presence.rs) ----------------------

/// Wrong IR PINs entered in a row at the physical-button stage of an open session.
#[allow(dead_code)]
static SESSION_FAILS: AtomicU8 = AtomicU8::new(0);
/// A wrong IR PIN three times in a row locks the session (the host PIN and the counted IR stage are needed
/// again).
#[allow(dead_code)]
const SESSION_FAILS_MAX: u8 = 3;
/// When the candidate IR digest was stored (ms, 0 = none) and how long it stays valid.
#[allow(dead_code)]
static CAND_MS: AtomicU32 = AtomicU32::new(0);
#[allow(dead_code)]
const CAND_VALID_MS: u32 = 15_000;

#[allow(dead_code)]
fn now_ms() -> u32 {
    embassy_time::Instant::now().as_millis() as u32
}

/// Open session: does the IR PIN just entered match the proven one? (constant time)
#[cfg(feature = "ir")]
pub fn session_matches(d: &[u8; 32]) -> bool {
    let mut proven = Zeroizing::new([0u8; 32]);
    if !guard::reveal_ir_into(&mut proven) {
        return false;
    }
    bool::from(proven[..].ct_eq(&d[..]))
}

#[cfg(feature = "ir")]
pub fn session_ok() {
    SESSION_FAILS.store(0, Ordering::Relaxed);
}

/// A wrong IR PIN in an open session; the third one in a row locks it.
#[cfg(feature = "ir")]
pub fn session_fail() {
    let n = SESSION_FAILS.load(Ordering::Relaxed).saturating_add(1);
    if n >= SESSION_FAILS_MAX {
        SESSION_FAILS.store(0, Ordering::Relaxed);
        warn!("ir: wrong IR PIN {} times - session locked", n);
        lock_now();
    } else {
        SESSION_FAILS.store(n, Ordering::Relaxed);
    }
}

/// Physical-button stage came first: keeps the IR digest entered there until the key is used (the
/// next `ir_stage` verifies it with the counted attempt).
#[cfg(feature = "ir")]
pub fn store_candidate(d: &[u8; 32]) -> bool {
    let ok = guard::store_ir(d);
    CAND_MS.store(now_ms().max(1), Ordering::Release);
    ok
}

#[allow(dead_code)]
fn take_candidate() -> Option<Zeroizing<[u8; 32]>> {
    let t = CAND_MS.swap(0, Ordering::AcqRel);
    if t == 0 {
        return None;
    }
    let mut d = Zeroizing::new([0u8; 32]);
    let fresh = now_ms().wrapping_sub(t) <= CAND_VALID_MS;
    let ok = fresh && guard::reveal_ir_into(&mut d);
    guard::clear_ir();
    if ok {
        Some(d)
    } else {
        None
    }
}

const NONCE: usize = 12;
const TAG: usize = 16;

#[allow(dead_code)] // the IR fields are only used with the `ir` feature
struct State {
    vault: FlashVault,
    /// `None`: the vault is unusable (damaged / unreadable) until a CTAP reset.
    rec: Option<Record>,
    /// Retry-counter page of the PIN attempt in progress.
    pending: Option<usize>,
    /// The last host PIN check (stage 1) was right but the IR PIN is still to be proven: the attempt
    /// stays counted, `reset_pin_retries` must not forgive earlier failures (they may be IR failures).
    partial: bool,
    /// Wrong IR PINs of the current USB session, and the session (epoch) they belong to.
    ir_fails: u8,
    ir_fail_epoch: u32,
    /// While `hid::epoch()` equals this, the IR stage refuses (three wrong IR PINs: reset / replug).
    blocked_epoch: Option<u32>,
    /// Serial of the operation in which an IR entry failed or was cancelled: the same operation does
    /// not ask again (OpenSK may try several credentials).
    denied_serial: u32,
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

fn internal() -> Ctap2StatusCode {
    Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR
}

/// Associated data of a resident credential: the key-value store key it lives under.
fn cred_aad(key: usize) -> [u8; 8] {
    let mut a = [0u8; 8];
    a[..4].copy_from_slice(b"cred");
    a[4..].copy_from_slice(&(key as u32).to_le_bytes());
    a
}

/// AES-256-GCM: `nonce(12) || ciphertext || tag(16)`, key derived from the master.
fn seal(master: &[u8; 128], key: usize, plain: &[u8]) -> CtapResult<Vec<u8>> {
    let k = sub_key(master, b"harden-cred-aead-v2");
    let cipher = Aes256Gcm::new_from_slice(&k[..]).map_err(|_| internal())?;
    let mut nonce = [0u8; NONCE];
    fill_random(&mut nonce);
    let mut out = Vec::with_capacity(NONCE + plain.len() + TAG);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(plain);
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &cred_aad(key), &mut out[NONCE..])
        .map_err(|_| internal())?;
    out.extend_from_slice(&tag);
    Ok(out)
}

fn open(master: &[u8; 128], key: usize, blob: &[u8]) -> CtapResult<Vec<u8>> {
    if blob.len() < NONCE + TAG {
        return Err(internal());
    }
    let k = sub_key(master, b"harden-cred-aead-v2");
    let cipher = Aes256Gcm::new_from_slice(&k[..]).map_err(|_| internal())?;
    let (nonce, rest) = blob.split_at(NONCE);
    let (ct, t) = rest.split_at(rest.len() - TAG);
    let mut plain = ct.to_vec();
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce), &cred_aad(key), &mut plain, Tag::from_slice(t))
        .map_err(|_| internal())?;
    Ok(plain)
}

fn hw_fail() -> Ctap2StatusCode {
    Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE
}

#[allow(dead_code)]
/// Marks a PIN attempt as done (forgives earlier failures). A failure is logged; the attempt then
/// simply stays counted, which is the safe direction.
fn finish_try_logged(v: &mut FlashVault, page: usize) {
    // One retry for a transient flash error, like `clear_tries_checked`.
    if v.finish_try(page).is_err() && v.finish_try(page).is_err() {
        warn!("vault: could not mark the PIN attempt as done; it stays counted");
    }
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

/// Records the PUF helper slot in a PUF-bound record (see `Puf::select` / `Puf::commit`).
fn bind_slot(mut rec: Record, puf: &Puf) -> Record {
    if rec.puf {
        rec.puf_slot = puf.slot();
    }
    rec
}

/// Before an IR stage: refuses while three wrong IR PINs blocked this USB session, and (when the attempt
/// will be counted) when the retry counter is used up.
#[cfg(feature = "ir")]
fn ir_precheck(st: &mut State, count: bool) -> CtapResult<()> {
    if st.blocked_epoch == Some(hid::epoch()) {
        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_BLOCKED);
    }
    if count && st.vault.tries_used().map_err(|_| hw_fail())? as usize >= TRIES_MAX {
        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
    }
    Ok(())
}

/// Evaluates an IR PIN against an IR record: one counted attempt (written before the evaluation), forgiven
/// only by a right IR PIN. Needs the host PIN hash of this session (guard). Returns the seed.
#[cfg(feature = "ir")]
fn ir_check(
    st: &mut State,
    rec: &Record,
    kref: Option<&[u8; 32]>,
    digest: &[u8; 32],
    serial: u32,
) -> CtapResult<Zeroizing<[u8; 32]>> {
    let mut host = Zeroizing::new([0u8; 16]);
    if !guard::reveal_host_into(&mut host) {
        return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
    }
    let page = st.vault.begin_try().map_err(|_| hw_fail())?;
    guard::refresh_now();
    let res = wrap::open_ir(rec, &host, digest, kref);
    guard::refresh_now();
    match res {
        Some(seed) => {
            finish_try_logged(&mut st.vault, page);
            st.ir_fails = 0;
            Ok(seed)
        }
        None => {
            // Stays counted. Three in a row end the USB session's chance (like OpenSK's 3 mismatches).
            let e = hid::epoch();
            if st.ir_fail_epoch != e {
                st.ir_fail_epoch = e;
                st.ir_fails = 0;
            }
            st.ir_fails = st.ir_fails.saturating_add(1);
            if st.ir_fails >= 3 {
                st.blocked_epoch = Some(e);
            }
            st.denied_serial = serial;
            guard::clear_ir();
            crate::LED_FLASH.signal(crate::LedFlash::Bad);
            if st.vault.tries_used().map_or(false, |u| u as usize >= TRIES_MAX) {
                Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED)
            } else {
                Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID)
            }
        }
    }
}

impl HardenPersist {
    /// Boot-time repair of a power cut inside `set_pin` (see there). Only acts on a loaded record.
    fn reconcile_pin_metadata(&mut self) -> CtapResult<()> {
        let Some(wrapped) = self.st.get_mut().rec.as_ref().map(|r| r.wrapped) else {
            return Ok(());
        };
        let has_props = self.raw.find(keys::PIN_PROPERTIES)?.is_some();
        match (wrapped, has_props) {
            (false, true) => {
                // set_pin was cut before its vault commit: no PIN exists, the seed is intact.
                warn!("init: PIN metadata without a PIN-wrapped vault - removed");
                self.raw.remove(keys::PIN_PROPERTIES)?;
            }
            (true, false) => {
                // A PIN-wrapped vault must come with metadata (only older firmware could cut
                // between the two). The real length is unknown: use the enforced minimum.
                warn!("init: PIN-wrapped vault without PIN metadata - restored");
                let mut props = [0u8; 17];
                props[0] = 10; // default_min_pin_length (src/env/mod.rs)
                self.raw.insert(keys::PIN_PROPERTIES, &props)?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn new(
        raw: PicoPersist,
        vault: FlashVault,
        rec: Option<Record>,
        blank: bool,
        mut puf: Puf,
    ) -> Self {
        let mut st = State {
            vault,
            rec: None,
            pending: None,
            partial: false,
            ir_fails: 0,
            ir_fail_epoch: 0,
            blocked_epoch: None,
            denied_serial: 0,
        };
        set_mode(IrMode::None);
        // A PUF-bound record names the helper slot it belongs to (two can be valid until a
        // re-enrolment is committed).
        if let Some(r) = rec.as_ref() {
            if r.puf {
                puf.select(r.puf_slot);
            }
        }
        // First boot with the PUF feature: enrol now (only a power-on reset can).
        // A blank helper sector only means "new device" when the vault holds no PUF-bound seed.
        // If a PUF-bound record exists (or the vault is damaged / unreadable), enrolling would
        // create a different PUF secret and silently orphan the existing seed: stay locked and
        // let the user decide (CTAP reset on a power-on reset).
        if puf.status() == PufStatus::Blank {
            let bound_or_unknown = match rec.as_ref() {
                Some(r) => r.puf,
                None => !blank,
            };
            if bound_or_unknown {
                error!("puf: helper data missing but the vault holds a PUF-bound or unreadable record - not enrolling");
            } else {
                if !puf.enroll() {
                    // `enroll` logged the reason (not a power-on reset, unusable RAM sample, ...).
                    warn!("puf: first-boot enrolment did not happen - device stays locked");
                }
            }
        }
        let key = puf.key();
        // With `sram_puf` the key is REQUIRED: without it nothing is created, bound or used. No
        // plain or unbound seed record is ever written because of a PUF failure; the device stays
        // locked (LED fault pattern) until a boot with a working key, a CTAP reset on a power-on
        // reset, or a build without `sram_puf`.
        if puf.required() && key.is_none() {
            error!("puf: REQUIRED but no key (status {}) - device locked, no record created or used", puf.status());
            puf::set_fault(true);
            WRAPPED.store(false, Ordering::Relaxed);
            return HardenPersist { raw, st: RefCell::new(st), puf };
        }
        puf::set_fault(false);
        // Blank vault, PUF required: create the first seed already bound to the PUF key.
        if blank {
            if let Some(k) = key.as_ref() {
                let mut seed = Zeroizing::new([0u8; 32]);
                fill_random(&mut seed[..]);
                let new_rec = bind_slot(wrap::plain_puf(&seed, k), &puf);
                match st.vault.replace(&new_rec) {
                    Replaced::New(_) if guard::store_seed(&seed) => {
                        WRAPPED.store(false, Ordering::Relaxed);
                        st.rec = Some(scrubbed(new_rec));
                    }
                    _ => {
                        error!("vault: could not create the first PUF-bound record");
                        st.fail_closed();
                    }
                }
            }
            return HardenPersist { raw, st: RefCell::new(st), puf };
        }
        if let Some(r) = rec {
            WRAPPED.store(r.wrapped, Ordering::Relaxed);
            if r.puf && key.is_none() {
                // Bound to the PUF but this boot cannot recover the key: do not guess, do not
                // count it as a wrong PIN, do not touch the record.
                error!("puf: record is PUF-bound but the key is unavailable - unplug for 10 s, or CTAP reset");
                WRAPPED.store(false, Ordering::Relaxed);
                puf::set_fault(true);
            } else if !r.wrapped {
                // Without a PIN the seed is available right away (unmasked with the PUF key).
                let kref = if r.puf { key.as_ref().map(|k| &**k) } else { None };
                match wrap::plain_seed(&r, kref) {
                    Some(seed) if guard::store_seed(&seed) => {
                        let mut keep = r;
                        // Not yet bound, but a PUF key exists: bind the plain seed now.
                        if !keep.puf {
                            if let Some(k) = key.as_ref() {
                                let up = bind_slot(wrap::plain_puf(&seed, k), &puf);
                                match st.vault.replace(&up) {
                                    Replaced::New(s) => {
                                        if !st.old_gone(s.old_wiped) {
                                            // The old seed (unmasked) is still readable in flash:
                                            // the binding does not protect anything yet.
                                            error!("puf: the unbound record could not be wiped - device locked");
                                            st.fail_closed();
                                            return HardenPersist { raw, st: RefCell::new(st), puf };
                                        }
                                        keep = up;
                                    }
                                    // Kept = the unbound record is still the current one. With the
                                    // PUF required it must not be used: fail closed.
                                    Replaced::Kept(_) | Replaced::NoKey | Replaced::Unknown => {
                                        error!("puf: could not bind the seed record - device locked");
                                        puf::set_fault(true);
                                        st.fail_closed();
                                        return HardenPersist { raw, st: RefCell::new(st), puf };
                                    }
                                }
                            }
                        }
                        else if wrap::legacy_plain_puf(&keep) {
                            // Seal an old PUF-masked record with its authentication tag.
                            if let Some(k) = key.as_ref() {
                                let up = bind_slot(wrap::plain_puf(&seed, k), &puf);
                                match st.vault.replace(&up) {
                                    Replaced::New(s) => {
                                        if !st.old_gone(s.old_wiped) {
                                            error!("puf: the untagged record could not be wiped - device locked");
                                            st.fail_closed();
                                            return HardenPersist { raw, st: RefCell::new(st), puf };
                                        }
                                        keep = up;
                                    }
                                    // The untagged record cannot detect a wrong PUF key: it is
                                    // not used until the authenticated record is durable (the
                                    // next boot retries).
                                    Replaced::Kept(_) | Replaced::NoKey | Replaced::Unknown => {
                                        error!("puf: could not seal the record with its tag - device locked");
                                        st.fail_closed();
                                        return HardenPersist { raw, st: RefCell::new(st), puf };
                                    }
                                }
                            }
                        }
                        st.rec = Some(scrubbed(keep));
                    }
                    _ => {
                        error!("guard: could not store the seed");
                        puf::set_fault(true);
                    }
                }
            } else if puf.required() && !r.puf {
                // A PIN record written by a build without the PUF: opening it would need its PIN(s),
                // and binding it to the PUF needs both PINs. Not supported: do a CTAP reset.
                error!("vault: PIN record without PUF binding while the PUF is required - CTAP reset needed");
                WRAPPED.store(false, Ordering::Relaxed);
                puf::set_sec_fault(true);
            } else {
                set_mode(mode_of(&r));
                st.rec = Some(scrubbed(r));
            }
        } else if !blank {
            // Damaged vault or read error (`vault::open` returned no record): the device stays
            // locked, but show the LED fault pattern instead of failing silently. No halt: a CTAP
            // reset must still be possible to recover.
            puf::set_sec_fault(true);
        }
        // Boot after an interrupted re-enrolment: the unreferenced helper is obsolete.
        if st.rec.as_ref().map_or(false, |r| r.puf) {
            puf.commit();
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
    ///
    /// Writes into the caller's buffer instead of returning it: a by-value return of 128 bytes
    /// can leave a copy in the callee's dead stack frame.
    fn master_into(&self, m: &mut Zeroizing<[u8; 128]>) -> CtapResult<()> {
        if self.st.borrow().rec.is_none() {
            return Err(hw_fail());
        }
        self.ensure_unlocked()?;
        let mut seed = Zeroizing::new([0u8; 32]);
        if !guard::reveal_seed_into(&mut seed) {
            return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
        }
        wrap::expand_into(&seed, m);
        Ok(())
    }

    /// The key may be used: the seed is open and, if an IR PIN protects it, the IR PIN has been
    /// proven in this session. If only the IR PIN is missing (the host PIN was checked in the host's
    /// dialog), the IR stage runs now: entry of the IR PIN and the physical-button press are one step.
    fn ensure_unlocked(&self) -> CtapResult<()> {
        let mode = ir_mode();
        if guard::has_seed() && matches!(mode, IrMode::None | IrMode::Session) {
            return Ok(());
        }
        #[cfg(feature = "ir")]
        {
            if matches!(mode, IrMode::Enroll | IrMode::Verify) && guard::has_host() {
                return self.ir_stage(mode);
            }
        }
        Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)
    }

    /// Stage 2 of the PIN check, see the module header. `Enroll`: the record has no IR PIN yet, the
    /// seed is open (stage 1 opened it): the IR PIN is entered twice and the record is rewritten with
    /// the IR PIN as part of the key. `Verify`: the IR PIN opens the seed (one counted attempt).
    #[cfg(feature = "ir")]
    fn ir_stage(&self, mode: IrMode) -> CtapResult<()> {
        use crate::ir_pin::{self, Outcome, Purpose};
        let mut cell = self.st.borrow_mut();
        let st = &mut *cell;
        let serial = hid::op_serial();
        let enroll = mode == IrMode::Enroll;
        ir_precheck(st, !enroll)?;
        if serial != 0 && st.denied_serial == serial {
            return Err(Ctap2StatusCode::CTAP2_ERR_OPERATION_DENIED);
        }
        let rec = st.rec.clone().ok_or_else(hw_fail)?;
        if !rec.wrapped {
            return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
        }
        if enroll && !guard::has_seed() {
            return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
        }
        let key = self.puf.key();
        if rec.puf && key.is_none() {
            puf::set_fault(true);
            error!("puf: key unavailable - unplug for 10 s and retry (not counted as a wrong PIN)");
            return Err(hw_fail());
        }
        let kref = if rec.puf { key.as_ref().map(|k| &**k) } else { None };
        // The IR digest: already entered at the physical-button stage, or entered now (the confirming
        // press is then the user presence of this command).
        let (digest, pressed_now) = match take_candidate() {
            Some(d) => (d, false),
            None => match ir_pin::collect(if enroll { Purpose::Enroll } else { Purpose::Verify }) {
                Outcome::Pin(d, _) => (d, true),
                Outcome::TimedOut => {
                    st.denied_serial = serial;
                    return Err(Ctap2StatusCode::CTAP2_ERR_USER_ACTION_TIMEOUT);
                }
                Outcome::Cancelled | Outcome::Keep => {
                    st.denied_serial = serial;
                    return Err(Ctap2StatusCode::CTAP2_ERR_OPERATION_DENIED);
                }
            },
        };
        if enroll {
            let mut host = Zeroizing::new([0u8; 16]);
            if !guard::reveal_host_into(&mut host) {
                return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
            }
            let mut seed = Zeroizing::new([0u8; 32]);
            if !guard::reveal_seed_into(&mut seed) {
                return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
            }
            let mut salt = [0u8; 16];
            fill_random(&mut salt);
            let new = bind_slot(
                wrap::wrap_full(&seed, &host, &digest, salt, kref).ok_or_else(hw_fail)?,
                &self.puf,
            );
            guard::refresh_now();
            match st.vault.replace(&new) {
                Replaced::New(saved) => {
                    st.rec = Some(new);
                    if !st.old_gone(saved.old_wiped) {
                        // The host-only record (without the IR PIN) is still readable: lock until it
                        // is gone (every boot retries the wipe).
                        error!("ir: the record without the IR PIN could not be wiped - device locked");
                        st.fail_closed();
                        return Err(hw_fail());
                    }
                }
                Replaced::Kept(_) => return Err(hw_fail()),
                Replaced::NoKey | Replaced::Unknown => {
                    st.fail_closed();
                    return Err(hw_fail());
                }
            }
        } else {
            let seed = ir_check(st, &rec, kref, &digest, serial)?;
            if !guard::store_seed(&seed) {
                return Err(hw_fail());
            }
        }
        guard::store_ir(&digest);
        set_mode(IrMode::Session);
        SESSION_FAILS.store(0, Ordering::Relaxed);
        if pressed_now {
            super::user_presence::grant_credit();
        }
        Ok(())
    }

    /// Key-value store figures for the display: (used, total, erase budget used, total), words.
    pub fn store_stats(&self) -> Option<(u32, u32, u32, u32)> {
        self.raw.stats()
    }
}

impl State {
    /// True when the older record is confirmed unreadable: wiped by the update itself or by a
    /// retry now. A PUF migration is only protective once this holds; otherwise the caller locks.
    fn old_gone(&mut self, old_wiped: bool) -> bool {
        old_wiped || matches!(self.vault.purge_stale(), Ok(true))
    }

    /// The state after a failed vault update whose outcome is unknown: no key is usable until a
    /// CTAP reset (same as a damaged vault at boot).
    fn fail_closed(&mut self) {
        error!("vault: unknown flash state - locking until reset");
        // Every locked state shows the LED fault pattern (cleared by a completed reset). Separate
        // from the PUF-key fault, which `init` treats specially.
        puf::set_sec_fault(true);
        self.rec = None;
        self.pending = None;
        self.partial = false;
        WRAPPED.store(false, Ordering::Relaxed);
        guard::clear_seed();
        guard::clear_host();
        guard::clear_ir();
        set_mode(IrMode::None);
    }
}

impl Persist for HardenPersist {
    fn find(&self, key: usize) -> CtapResult<Option<Vec<u8>>> {
        let value = self.raw.find(key)?;
        match value {
            Some(blob) if keys::CREDENTIALS.contains(&key) => {
                let mut m = Zeroizing::new([0u8; 128]);
                self.master_into(&mut m)?;
                Ok(Some(open(&m, key, &blob)?))
            }
            other => Ok(other),
        }
    }

    fn insert(&mut self, key: usize, value: &[u8]) -> CtapResult<()> {
        if keys::CREDENTIALS.contains(&key) {
            let mut m = Zeroizing::new([0u8; 128]);
            self.master_into(&mut m)?;
            let blob = seal(&m, key, value)?;
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
        let mut m = Zeroizing::new([0u8; 128]);
        self.master_into(&mut m)?;
        let mut s = Secret::new(128);
        s.copy_from_slice(&m[..]);
        Ok(Some(s))
    }

    fn write_key_store_bytes(&mut self, _bytes: &[u8]) -> CtapResult<()> {
        // Only reachable if `key_store_bytes` returned None, which it never does.
        Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
    }

    // ---- PIN ---------------------------------------------------------------------------------

    /// Stage 1 of the PIN check: the host PIN, called by the patched `verify_pin_hash_enc`. The host
    /// verifier in the vault record (Argon2id, PUF-bound) tells right from wrong; the IR PIN is NOT asked
    /// here: the host gets its answer at once and the IR PIN is part of the physical-button stage.
    fn unlock_with_pin(&mut self, pin_hash: &[u8; 16]) -> CtapResult<Option<bool>> {
        let st = self.st.get_mut();
        let rec = match st.rec.clone() {
            Some(r) => r,
            // Locked closed. `incr_pin_fails` already refuses before counting; no refund here:
            // `finish_try` would forgive earlier failures.
            None => return Err(hw_fail()),
        };
        if !rec.wrapped {
            // OpenSK believes a PIN is set but the vault has none (interrupted setPIN):
            // nobody can unlock this, a CTAP reset is needed.
            return Ok(Some(false));
        }
        // PUF key, derived now and wiped on drop. `incr_pin_fails` already refused to count an
        // attempt without it, so this is only a safeguard (and must not refund: that would
        // forgive earlier failures).
        let key = self.puf.key();
        if rec.puf && key.is_none() {
            puf::set_fault(true);
            error!("puf: key unavailable - unplug for 10 s and retry (not counted as a wrong PIN)");
            return Err(hw_fail());
        }
        let kref = if rec.puf { key.as_ref().map(|k| &**k) } else { None };
        guard::refresh_now();
        st.partial = false;
        let ok = match wrap::host_stage(&rec, pin_hash, kref) {
            wrap::Host::Wrong => false,
            wrap::Host::Verified => {
                // The record also needs the IR PIN: keep the host PIN hash for stage 2.
                if !guard::store_host(pin_hash) {
                    return Err(hw_fail());
                }
                if ir_mode() != IrMode::Session {
                    set_mode(IrMode::Verify);
                    st.partial = true;
                }
                true
            }
            wrap::Host::Seed(seed) => {
                // No IR PIN yet: the host PIN opened the seed. With the `ir` feature the IR PIN is
                // enrolled at the next physical-button stage.
                if !guard::store_seed(&seed) || !guard::store_host(pin_hash) {
                    return Err(hw_fail());
                }
                set_mode(if cfg!(feature = "ir") { IrMode::Enroll } else { IrMode::None });
                true
            }
        };
        guard::refresh_now();
        Ok(Some(ok))
    }

    fn set_pin(&mut self, pin_hash: &[u8; 16], pin_code_point_length: u8) -> CtapResult<()> {
        let key = self.puf.key();
        let mut wipe_failed = false;
        {
            let st = self.st.get_mut();
            if !guard::has_seed() {
                return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
            }
            if key.is_none() && (self.puf.required() || st.rec.as_ref().map_or(false, |r| r.puf)) {
                // Never wrap a seed without PUF binding while the PUF is required.
                puf::set_fault(true);
                error!("set_pin: PUF key unavailable - PIN not set");
                return Err(hw_fail());
            }
            // 0. PIN CHANGE of an IR-protected record: the old host PIN was just verified by OpenSK (stage 1,
            //    its hash is in the guard). Now prove the current IR PIN (counted attempt) and take the new
            //    IR PIN (the button alone keeps the current one). A first PIN (no record yet) and a
            //    host-only record need nothing here: the IR PIN is enrolled at the next button stage.
            #[cfg(feature = "ir")]
            let ir_digest: Option<Zeroizing<[u8; 32]>> =
                match st.rec.clone().filter(|r| r.wrapped && r.ir) {
                    Some(old) => {
                        use crate::ir_pin::{self, Outcome, Purpose};
                        ir_precheck(st, true)?;
                        let serial = hid::op_serial();
                        let old_key = if old.puf { key.as_ref().map(|k| &**k) } else { None };
                        let current = match ir_pin::collect(Purpose::Verify) {
                            Outcome::Pin(d, _) => d,
                            Outcome::TimedOut => {
                                return Err(Ctap2StatusCode::CTAP2_ERR_USER_ACTION_TIMEOUT)
                            }
                            Outcome::Cancelled | Outcome::Keep => {
                                return Err(Ctap2StatusCode::CTAP2_ERR_OPERATION_DENIED)
                            }
                        };
                        // Proves the current IR PIN; the opened seed is not needed (it is in the guard).
                        let _ = ir_check(st, &old, old_key, &current, serial)?;
                        match ir_pin::collect(Purpose::Change) {
                            Outcome::Pin(d, _) => Some(d),
                            Outcome::Keep => Some(current),
                            Outcome::TimedOut => {
                                return Err(Ctap2StatusCode::CTAP2_ERR_USER_ACTION_TIMEOUT)
                            }
                            Outcome::Cancelled => {
                                return Err(Ctap2StatusCode::CTAP2_ERR_OPERATION_DENIED)
                            }
                        }
                    }
                    None => None,
                };
            // 1. Counter first. The caller is authenticated (no PIN yet, or the old PIN was just
            //    verified), so clearing it early gives nothing away, and a failure here changes
            //    nothing at all.
            clear_tries_checked(&mut st.vault)?;
            // 2. Wrap the seed under the new host PIN (and the IR PIN of a PIN change).
            let rec = {
                let mut seed = Zeroizing::new([0u8; 32]);
                if !guard::reveal_seed_into(&mut seed) {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
                }
                let mut salt = [0u8; 16];
                fill_random(&mut salt);
                let kref = key.as_ref().map(|k| &**k);
                #[cfg(feature = "ir")]
                let built = match &ir_digest {
                    Some(d) => wrap::wrap_full(&seed, pin_hash, d, salt, kref),
                    None => wrap::wrap_host(&seed, pin_hash, salt, kref),
                };
                #[cfg(not(feature = "ir"))]
                let built = wrap::wrap_host(&seed, pin_hash, salt, kref);
                bind_slot(built.ok_or_else(hw_fail)?, &self.puf)
            };
            guard::refresh_now();
            // 3. PIN metadata BEFORE the vault commit. The only inconsistent states a power cut can
            //    leave are then "metadata says PIN, vault has no PIN" (undone by `init`, the
            //    seed is untouched) and "old PIN record + new length" (harmless). The reverse
            //    (PIN-wrapped vault, no metadata) cannot be produced any more.
            let was_wrapped = st.rec.as_ref().is_some_and(|r| r.wrapped);
            // The stored PIN "hash" is zeros: the real check is the verifier / GCM tag in the vault.
            let mut props = [0u8; 17];
            props[0] = pin_code_point_length;
            self.raw.insert(keys::PIN_PROPERTIES, &props)?;
            // 4. Commit. Only a record that is durable AND whose predecessor was verified wiped
            //    counts as success.
            match st.vault.replace(&rec) {
                Replaced::New(saved) => {
                    let mode = mode_of(&rec);
                    st.rec = Some(rec);
                    st.pending = None;
                    st.partial = false;
                    WRAPPED.store(true, Ordering::Relaxed);
                    // Session after the change: the new host PIN hash stays for stage 2 / the next
                    // change; a record with an IR PIN has just had it proven, a host-only one asks
                    // for the IR PIN at the next button stage.
                    if !guard::store_host(pin_hash) {
                        warn!("set_pin: host PIN hash not kept - the host PIN is asked again");
                    }
                    #[cfg(feature = "ir")]
                    {
                        match &ir_digest {
                            Some(d) => {
                                guard::store_ir(d);
                                set_mode(IrMode::Session);
                            }
                            None => {
                                guard::clear_ir();
                                set_mode(mode);
                            }
                        }
                    }
                    #[cfg(not(feature = "ir"))]
                    {
                        set_mode(mode);
                    }
                    if !st.old_gone(saved.old_wiped) {
                        // The new record wins on every boot, but the previous (plain or
                        // old-PIN) record may still be readable: do NOT report success. The seed
                        // stays usable in RAM, so setting the PIN again in this session retries
                        // the erase (the next save targets exactly that slot); after a lock or
                        // power cycle a CTAP reset is needed.
                        // The new record is durable, so the PIN metadata below is still written
                        // (otherwise a reboot would find a PIN-wrapped vault without PIN
                        // properties); the error is reported afterwards.
                        error!("set_pin: previous record could not be wiped - PIN setup failed");
                        wipe_failed = true;
                    }
                }
                // Nothing changed: the old record is still the newest one.
                Replaced::Kept(_) => {
                    if !was_wrapped {
                        // Undo the metadata, otherwise a PIN would be expected that never existed.
                        let _ = self.raw.remove(keys::PIN_PROPERTIES);
                    }
                    return Err(hw_fail());
                }
                // The flash state is unknown or empty: stop using any key.
                Replaced::NoKey | Replaced::Unknown => {
                    st.fail_closed();
                    return Err(hw_fail());
                }
            }
        }
        // Last: if power fails here the PIN is set and a PIN change is merely still requested.
        self.raw.remove(keys::FORCE_PIN_CHANGE)?;
        if wipe_failed {
            return Err(hw_fail());
        }
        Ok(())
    }

    fn pin_fails(&self) -> CtapResult<u8> {
        self.st
            .borrow_mut()
            .vault
            .tries_used()
            .map_err(|_| hw_fail())
    }

    fn incr_pin_fails(&mut self) -> CtapResult<()> {
        // Closed vault or missing PUF key: refuse BEFORE counting and without touching the
        // counter. (A "refund" would call `finish_try`, which forgives all earlier failures and
        // would let anyone who can make the key unavailable reset the retry counter.)
        if self.st.get_mut().rec.is_none() {
            return Err(hw_fail());
        }
        if self.puf.required() && self.puf.key().is_none() {
            puf::set_fault(true);
            return Err(hw_fail());
        }
        let st = self.st.get_mut();
        if st.vault.tries_used().map_err(|_| hw_fail())? as usize >= TRIES_MAX {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
        }
        // Written BEFORE the PIN is evaluated, so cutting power cannot undo the attempt.
        let page = st.vault.begin_try().map_err(|_| hw_fail())?;
        st.pending = Some(page);
        st.partial = false;
        Ok(())
    }

    fn reset_pin_retries(&mut self) -> CtapResult<()> {
        let st = self.st.get_mut();
        if st.partial {
            // Host PIN right, IR PIN still to prove: nothing is forgiven now. The attempt stays counted
            // and is wiped by the right IR PIN (`ir_check`), so earlier IR failures cannot be reset by
            // typing the (possibly well-known) host PIN.
            st.partial = false;
            st.pending = None;
            return Ok(());
        }
        match st.pending.take() {
            Some(page) => st.vault.finish_try(page).map_err(|_| hw_fail()),
            None => st.vault.clear_tries().map_err(|_| hw_fail()),
        }
    }

    // ---- factory reset -----------------------------------------------------------------------

    /// Like the default, but a pending reset that only the missing PUF key blocks must not abort
    /// the boot (`CtapState::new` unwraps `init`): the device stays locked, the LED shows the
    /// fault, and a reset on a power-on reset repairs it.
    fn init(&mut self) -> CtapResult<()> {
        if self.find(keys::RESET_COMPLETION)?.is_some() {
            if self.reset().is_err() {
                // Postpone only when the missing PUF key is what blocks the reset; any other failure
                // (vault, flash) is reported as it is.
                if self.puf.required() && self.puf.key().is_none() {
                    warn!("init: pending reset postponed, PUF key unavailable");
                } else {
                    // Do not abort the boot (`CtapState::new` unwraps `init`): stay locked with
                    // the LED fault pattern; the marker stays, so the next boot repeats the reset
                    // and a CTAP reset can be issued meanwhile.
                    error!("init: pending reset failed - locked, will retry at the next boot");
                    self.st.get_mut().fail_closed();
                }
                return Ok(());
            }
            return Ok(());
        }
        self.reconcile_pin_metadata()
    }

    fn reset(&mut self) -> CtapResult<()> {
        // With the PUF required, a usable key comes first. If there is none, try to (re-)enrol (a
        // reset wipes everything that depended on the old key anyway; needs a power-on reset).
        // If that fails, refuse: nothing is touched, no marker is written, and above all no plain
        // or unbound seed record is created.
        if self.puf.required() {
            if self.puf.status() != PufStatus::Ready && !self.puf.enroll() {
                // `enroll` logged the reason (not a power-on reset, unusable RAM sample, ...).
                warn!("reset: PUF (re-)enrolment did not happen");
            }
            if self.puf.key().is_none() {
                puf::set_fault(true);
                error!("reset: PUF key unavailable - reset refused (unplug for 10 s and retry)");
                return Err(hw_fail());
            }
        }
        // Marker next: if anything fails below, `init` repeats the whole reset on the next boot.
        self.raw.insert(keys::RESET_COMPLETION, &[])?;
        let mut seed = Zeroizing::new([0u8; 32]);
        fill_random(&mut seed[..]);
        let key = self.puf.key();
        let rec = match key.as_ref() {
            Some(k) => bind_slot(wrap::plain_puf(&seed, k), &self.puf),
            None if !self.puf.required() => Record::plain(*seed),
            None => {
                puf::set_fault(true);
                return Err(hw_fail());
            }
        };
        {
            let st = self.st.get_mut();
            match st.vault.replace(&rec) {
                Replaced::New(saved) => {
                    // The old seed must not stay readable after a factory reset either.
                    let wiped = saved.old_wiped || matches!(st.vault.purge_stale(), Ok(true));
                    st.rec = Some(scrubbed(rec));
                    st.pending = None;
                    st.partial = false;
                    st.blocked_epoch = None;
                    WRAPPED.store(false, Ordering::Relaxed);
                    guard::clear_host();
                    guard::clear_ir();
                    set_mode(IrMode::None);
                    if !guard::store_seed(&seed) {
                        st.fail_closed();
                        return Err(hw_fail());
                    }
                    if !wiped {
                        error!("reset: previous record could not be wiped");
                        puf::set_sec_fault(true);
                        return Err(hw_fail());
                    }
                    // The new record (bound to the new helper slot) is durable: the previous
                    // helper is obsolete now.
                    self.puf.commit();
                    // The new seed is durable, so the old counter is meaningless: a counter that
                    // cannot be cleared must fail the reset (marker stays, boot repeats it)
                    // instead of leaving a fresh PIN blocked.
                    clear_tries_checked(&mut st.vault)?;
                }
                Replaced::Kept(_) => {
                    error!("reset: vault could not be re-initialised");
                    puf::set_sec_fault(true);
                    return Err(hw_fail());
                }
                Replaced::NoKey | Replaced::Unknown => {
                    st.fail_closed();
                    return Err(hw_fail());
                }
            }
        }
        // Removes every non-persistent key (credentials, PIN, counters ...) and the marker.
        Persist::reset(&mut self.raw)?;
        // New seed durable and in RAM, old data gone: the device is usable again. The LED fault
        // pattern is cleared only here, never while a step above could still have failed.
        puf::set_fault(false);
        puf::set_sec_fault(false);
        Ok(())
    }
}
