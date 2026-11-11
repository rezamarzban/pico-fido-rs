//! OpenSK `Ecdsa` whose private keys never leave the ATECC608A.
//!
//! * One key per relying party (RP). Which RP owns which credential slot is recorded in a small
//!   directory that lives in the **Pico's flash** (`DirStore`, implemented by `env/dir_flash.rs`);
//!   nothing but the keys themselves is stored in the chip. `random()` works like this:
//!   1. the RP already has a slot in the directory and that slot holds a key: use it again (no
//!      slot is consumed, accounts at the same site then share one public key);
//!   2. otherwise the first credential slot that is NOT owned by another RP and already HOLDS a
//!      private key is taken over for this RP (its key is used as it is, no GenKey);
//!   3. otherwise the first slot that holds no key (its public key cannot be read) gets a new key
//!      with GenKey.
//!   Either way the RP is written to the directory before the key is handed out. A key that is
//!   owned by an RP is never touched, regenerated or overwritten. When every slot belongs to
//!   another RP `random()` panics, so the registration fails and the existing keys stay. The RP
//!   comes from OpenSK through `Rng::take_rp_id_hash` (third_party/opensk-rp-hint.patch); without
//!   it (`None`), or without an installed directory, nothing is adopted or recorded and every call
//!   takes a fresh (empty) slot.
//! * `export()` is a 32-byte *handle*: [version][slot][6-byte public-key fingerprint][zeros].
//!   OpenSK stores it inside the encrypted credential ID, exactly like a wrapped software key.
//! * `import()` checks that the slot still holds the key the handle was made for (fingerprint).
//! * The attestation key lives in slot `ATTEST_SLOT` and is created once at provisioning
//!   (atecc608a/tools/make_attest_cert.py). OpenSK's attestation store holds its handle
//!   (version 2) where a software firmware would hold the 32-byte private key.
//! * `sign()` hashes the message (SHA-256) and lets the chip sign the digest. Signatures are
//!   unlimited: nothing is counted (Counter 0 is not used any more; the chip config has no
//!   LimitedUse bit either).

use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use critical_section::Mutex;
use opensk::api::crypto::ec_signing::{EcPublicKey, EcSecretKey, EcSignature, Ecdsa};
use opensk::api::crypto::EC_FIELD_SIZE;
use opensk::api::rng::Rng;
use sha2::{Digest, Sha256};

use super::chip::ChipOps;
use super::proto::{ChipInfo, Error};

/// Slot map of the reference config (atecc608a/out/atecc608a_general_config.bin): slots 0-9 are
/// ECC P-256 private-key slots with GenKey enabled. Slot 0 holds the attestation key (made once,
/// never overwritten by the firmware); slots 1..=9 are credential slots. Slots 10-15 are not used.
pub const ATTEST_SLOT: u8 = 0;
pub const FIRST_CRED_SLOT: u8 = 1;
/// Number of credential slots (a registration at a 10th site is refused: keys are never overwritten).
pub const SLOTS: u8 = 9;
/// Directory entry of one credential slot: the first `DIR_ENTRY` bytes of the SHA-256 of the RP ID
/// it belongs to (all zero = no RP recorded). The directory has one entry per credential slot, in
/// slot order, and is kept by a `DirStore` (the Pico's flash), never in the chip.
pub const DIR_ENTRY: usize = 7;
pub const DIR_LEN: usize = SLOTS as usize * DIR_ENTRY;

/// Where the site directory is kept. `load` returns the whole directory image (zeros when nothing
/// is stored); `save` stores the whole image and must be power-fail safe (an interrupted `save`
/// leaves the old or the new directory, or an empty one: never a wrong one).
pub trait DirStore {
    fn load(&mut self) -> [u8; DIR_LEN];
    fn save(&mut self, dir: &[u8; DIR_LEN]) -> Result<(), ()>;
}

/// Handle of a credential key (slot < SLOTS) / of the attestation key (slot == ATTEST_SLOT).
pub const HANDLE_CRED: u8 = 1;
pub const HANDLE_ATTEST: u8 = 2;
const HANDLE_LEN: usize = 32;
const FP_LEN: usize = 6;
/// Counter 0 value at which the chip refuses to count further (datasheet maximum). Only the
/// provisioning tools and the host-test chip model still refer to it: the firmware does not
/// count signatures.
pub const COUNTER_MAX: u32 = 2_097_151;

type Chip = &'static mut (dyn ChipOps + Send);
type Dir = &'static mut (dyn DirStore + Send);

static CHIP: Mutex<RefCell<Option<Chip>>> = Mutex::new(RefCell::new(None));
static DIR: Mutex<RefCell<Option<Dir>>> = Mutex::new(RefCell::new(None));
/// Chip status of GenKey(public) on a slot without a private key (execution error).
const STATUS_EMPTY_SLOT: u8 = 0x0F;
/// Credential slots known to hold a key (`None` until `scan_slots` ran).
static USED: Mutex<Cell<Option<u8>>> = Mutex::new(Cell::new(None));
static PUBKEYS: Mutex<RefCell<[Option<[u8; 64]>; 16]>> = Mutex::new(RefCell::new([None; 16]));

/// Registers the chip driver. Call once at start-up.
pub fn install(chip: Chip) {
    critical_section::with(|cs| *CHIP.borrow(cs).borrow_mut() = Some(chip));
}

/// Registers the place where the site directory is kept (the Pico's flash). Without it no site is
/// recorded and no existing key is taken over (see the module documentation).
pub fn install_dir(dir: Dir) {
    critical_section::with(|cs| *DIR.borrow(cs).borrow_mut() = Some(dir));
}

/// Removes the drivers again (host tests).
pub fn uninstall() {
    critical_section::with(|cs| {
        *CHIP.borrow(cs).borrow_mut() = None;
        *DIR.borrow(cs).borrow_mut() = None;
        *PUBKEYS.borrow(cs).borrow_mut() = [None; 16];
        USED.borrow(cs).set(None);
    });
}

pub fn installed() -> bool {
    critical_section::with(|cs| CHIP.borrow(cs).borrow().is_some())
}

/// Runs `f` with exclusive use of the chip. The driver is taken out of the global while `f` runs
/// (chip commands take up to ~100 ms: never hold a critical section across them); a nested or
/// concurrent call therefore fails instead of corrupting the command sequence.
pub fn with_chip<R>(f: impl FnOnce(&mut dyn ChipOps) -> Result<R, Error>) -> Result<R, Error> {
    let chip = critical_section::with(|cs| CHIP.borrow(cs).borrow_mut().take());
    let Some(chip) = chip else {
        return Err(Error::Bus);
    };
    let r = f(&mut *chip);
    critical_section::with(|cs| *CHIP.borrow(cs).borrow_mut() = Some(chip));
    r
}

/// Serial number, revision, I2C address and lock state of the chip (`None`: chip not reachable).
pub fn chip_info() -> Option<ChipInfo> {
    with_chip(|c| c.info()).ok()
}

/// Is a private key present in `slot`? `Ok(false)` only for the chip's "no key here" answer;
/// any other failure is an error, so a bus problem can never make a used slot look free.
fn slot_has_key(slot: u8) -> Result<bool, Error> {
    match with_chip(|c| c.public_key(slot)) {
        Ok(_) => Ok(true),
        Err(Error::Status(STATUS_EMPTY_SLOT)) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Counts the credential slots that hold a key (reads every slot once: ~0.5 s, call at start-up)
/// and remembers the result for `used_slots()`. `None`: the chip did not answer cleanly.
pub fn scan_slots() -> Option<u8> {
    let mut used = 0u8;
    for slot in FIRST_CRED_SLOT..FIRST_CRED_SLOT + SLOTS {
        if slot_has_key(slot).ok()? {
            used += 1;
        }
    }
    critical_section::with(|cs| USED.borrow(cs).set(Some(used)));
    Some(used)
}

/// Credential slots in use as of the last `scan_slots()` plus the keys created since (no chip
/// access, cheap). `None` before the first scan.
pub fn used_slots() -> Option<u8> {
    critical_section::with(|cs| USED.borrow(cs).get())
}

/// 32 random bytes from the chip (seed of the RNG, `env/rng.rs`).
pub fn chip_random() -> Result<[u8; 32], Error> {
    with_chip(|c| c.random())
}

/// The 32-byte handle for the key `pk` in `slot`: [version][slot][fingerprint][zeros].
pub fn handle(version: u8, slot: u8, pk: &[u8; 64]) -> Vec<u8> {
    let mut h = alloc::vec![0u8; HANDLE_LEN];
    h[0] = version;
    h[1] = slot;
    h[2..2 + FP_LEN].copy_from_slice(&fingerprint(pk));
    h
}

fn fingerprint(pk: &[u8; 64]) -> [u8; FP_LEN] {
    let d = Sha256::digest(pk);
    let mut f = [0u8; FP_LEN];
    f.copy_from_slice(&d[..FP_LEN]);
    f
}

fn cached_pubkey(slot: u8) -> Result<[u8; 64], Error> {
    if let Some(pk) = critical_section::with(|cs| PUBKEYS.borrow(cs).borrow()[slot as usize]) {
        return Ok(pk);
    }
    let pk = with_chip(|c| c.public_key(slot))?;
    critical_section::with(|cs| PUBKEYS.borrow(cs).borrow_mut()[slot as usize] = Some(pk));
    Ok(pk)
}

/// Runs `f` with the directory store (`None`: no store installed). Like `with_chip`, the store is
/// taken out of the global while `f` runs: a flash erase must not happen inside a critical section.
fn with_dir<R>(f: impl FnOnce(&mut dyn DirStore) -> R) -> Option<R> {
    let dir = critical_section::with(|cs| DIR.borrow(cs).borrow_mut().take())?;
    let r = f(&mut *dir);
    critical_section::with(|cs| *DIR.borrow(cs).borrow_mut() = Some(dir));
    Some(r)
}

/// The directory entry of an RP (never all zero, that means "empty").
fn dir_tag(rp: &[u8; 32]) -> [u8; DIR_ENTRY] {
    let mut t = [0u8; DIR_ENTRY];
    t.copy_from_slice(&rp[..DIR_ENTRY]);
    if t == [0u8; DIR_ENTRY] {
        t[DIR_ENTRY - 1] = 1;
    }
    t
}

fn dir_entry(dir: &[u8; DIR_LEN], i: usize) -> &[u8] {
    &dir[i * DIR_ENTRY..(i + 1) * DIR_ENTRY]
}

fn dir_owned(dir: &[u8; DIR_LEN], i: usize) -> bool {
    dir_entry(dir, i).iter().any(|&b| b != 0)
}

/// The credential slot that already holds the key of this RP, with its public key. An entry whose
/// slot holds no key (an interrupted registration) is ignored; a chip that does not answer is not
/// (it must never look like "no key here").
fn dir_find(dir: &[u8; DIR_LEN], rp: &[u8; 32]) -> Option<(u8, [u8; 64])> {
    let tag = dir_tag(rp);
    for i in 0..SLOTS as usize {
        if dir_entry(dir, i) == &tag[..] {
            let slot = FIRST_CRED_SLOT + i as u8;
            match cached_pubkey(slot) {
                Ok(pk) => return Some((slot, pk)),
                Err(Error::Status(STATUS_EMPTY_SLOT)) => {}
                Err(_) => panic!("se: cannot read key slot"),
            }
        }
    }
    None
}

/// Records in the directory (in the Pico's flash) that `slot` belongs to `rp`. It is done BEFORE
/// the key is handed out: if it cannot be stored, the registration fails (panic, like every
/// other failure here) instead of a key being shared with the next site without a trace.
fn dir_record(dir: &mut [u8; DIR_LEN], slot: u8, rp: &[u8; 32]) {
    let off = (slot - FIRST_CRED_SLOT) as usize * DIR_ENTRY;
    dir[off..off + DIR_ENTRY].copy_from_slice(&dir_tag(rp));
    if let Some(Err(())) = with_dir(|d| d.save(dir)) {
        panic!("se: cannot record the site in the flash directory");
    }
}

pub struct SeEcdsa;

impl Ecdsa for SeEcdsa {
    type SecretKey = SeSecretKey;
    type PublicKey = SePublicKey;
    type Signature = SeSignature;
}

pub struct SeSecretKey {
    slot: u8,
    pubkey: [u8; 64],
}

pub struct SePublicKey {
    x: [u8; EC_FIELD_SIZE],
    y: [u8; EC_FIELD_SIZE],
}

pub struct SeSignature {
    r: [u8; 32],
    s: [u8; 32],
}

impl EcSecretKey for SeSecretKey {
    type PublicKey = SePublicKey;
    type Signature = SeSignature;

    fn random(rng: &mut impl Rng) -> Self {
        let rp = rng.take_rp_id_hash();
        // The directory comes from the Pico's flash. Without a hint or without a store nothing can
        // be recorded, so no key is shared or taken over then.
        let mut dir = if rp.is_some() { with_dir(|d| d.load()) } else { None };
        // 1. This RP already has a key: use it again, no slot is consumed.
        if let (Some(rp), Some(dir)) = (&rp, &dir) {
            if let Some((slot, pubkey)) = dir_find(dir, rp) {
                return SeSecretKey { slot, pubkey };
            }
        }
        // 2. A slot of nobody that already holds a private key: this RP takes it over as it is.
        //    The slots without a key are collected for step 3 (also those with a stale entry).
        let mut empty = [0u8; SLOTS as usize];
        let mut n_empty = 0;
        for i in 0..SLOTS as usize {
            let slot = FIRST_CRED_SLOT + i as u8;
            let has_key = match slot_has_key(slot) {
                Ok(b) => b,
                Err(_) => panic!("se: cannot read key slot"),
            };
            if !has_key {
                empty[n_empty] = slot;
                n_empty += 1;
                continue;
            }
            if let (Some(rp), Some(dir)) = (&rp, dir.as_mut()) {
                if !dir_owned(dir, i) {
                    let pubkey = match cached_pubkey(slot) {
                        Ok(pk) => pk,
                        Err(_) => panic!("se: cannot read key slot"),
                    };
                    dir_record(dir, slot, rp);
                    return SeSecretKey { slot, pubkey };
                }
            }
        }
        // 3. First empty slot, in order: GenKey. If the chip refuses GenKey in a slot (e.g. one that
        //    cannot hold a P-256 private key) the next one is tried, so such a slot is never used.
        for &slot in &empty[..n_empty] {
            match with_chip(|c| c.gen_key(slot)) {
                Ok(pubkey) => {
                    critical_section::with(|cs| {
                        PUBKEYS.borrow(cs).borrow_mut()[slot as usize] = Some(pubkey);
                        let u = USED.borrow(cs);
                        u.set(u.get().map(|n| (n + 1).min(SLOTS)));
                    });
                    if let (Some(rp), Some(dir)) = (&rp, dir.as_mut()) {
                        dir_record(dir, slot, rp);
                    }
                    return SeSecretKey { slot, pubkey };
                }
                Err(Error::Status(_)) => continue,
                Err(_) => panic!("se: GenKey failed"),
            }
        }
        panic!("se: no free key slot for a new site, refusing to overwrite an existing key")
    }

    fn public_key(&self) -> SePublicKey {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&self.pubkey[..32]);
        y.copy_from_slice(&self.pubkey[32..]);
        SePublicKey { x, y }
    }

    fn sign(&self, message: &[u8]) -> SeSignature {
        let digest: [u8; 32] = Sha256::digest(message).into();
        match with_chip(|c| c.sign(self.slot, &digest)) {
            Ok(sig) => {
                let mut r = [0u8; 32];
                let mut s = [0u8; 32];
                r.copy_from_slice(&sig[..32]);
                s.copy_from_slice(&sig[32..]);
                SeSignature { r, s }
            }
            // The trait cannot report errors. A refused signature (chip gone) becomes an
            // all-zero signature that no verifier accepts.
            Err(_) => SeSignature { r: [0; 32], s: [0; 32] },
        }
    }

    fn export(&self) -> Vec<u8> {
        let version = if self.slot == ATTEST_SLOT { HANDLE_ATTEST } else { HANDLE_CRED };
        handle(version, self.slot, &self.pubkey)
    }

    fn import(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != HANDLE_LEN {
            return None;
        }
        let slot = bytes[1];
        let slot_ok = match bytes[0] {
            HANDLE_CRED => (FIRST_CRED_SLOT..FIRST_CRED_SLOT + SLOTS).contains(&slot),
            HANDLE_ATTEST => slot == ATTEST_SLOT,
            _ => false,
        };
        if !slot_ok || bytes[2 + FP_LEN..].iter().any(|&b| b != 0) {
            return None;
        }
        let pubkey = cached_pubkey(slot).ok()?;
        // The slot may hold a different key than the one the handle was made for (or the attestation key was replaced).
        if fingerprint(&pubkey)[..] != bytes[2..2 + FP_LEN] {
            return None;
        }
        Some(SeSecretKey { slot, pubkey })
    }
}

impl EcPublicKey for SePublicKey {
    type Signature = SeSignature;

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        *x = self.x;
        *y = self.y;
    }
}

fn der_int(out: &mut Vec<u8>, v: &[u8; 32]) {
    let mut i = 0;
    while i < 31 && v[i] == 0 {
        i += 1;
    }
    let body = &v[i..];
    let pad = body[0] & 0x80 != 0;
    out.push(0x02);
    out.push((body.len() + pad as usize) as u8);
    if pad {
        out.push(0);
    }
    out.extend_from_slice(body);
}

impl EcSignature for SeSignature {
    fn to_der(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(72);
        der_int(&mut body, &self.r);
        der_int(&mut body, &self.s);
        let mut out = Vec::with_capacity(body.len() + 2);
        out.push(0x30);
        out.push(body.len() as u8);
        out.extend_from_slice(&body);
        out
    }
}
