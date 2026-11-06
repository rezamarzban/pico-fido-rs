//! OpenSK `Ecdsa` whose private keys never leave the ATECC608A.
//!
//! * `random()` allocates the next credential slot (round-robin on Counter 1, which survives
//!   power cycles) and runs GenKey there. The key that was in that slot is overwritten: with N
//!   slots the N+1-th registration evicts the oldest credential (its handle then fails `import`).
//! * `export()` is a 32-byte *handle*: [version][slot][6-byte public-key fingerprint][zeros].
//!   OpenSK stores it inside the encrypted credential ID, exactly like a wrapped software key.
//! * `import()` checks that the slot still holds the key the handle was made for (fingerprint).
//! * The attestation key lives in slot `ATTEST_SLOT` and is created once at provisioning
//!   (atecc608a/tools/make_attest_cert.py). OpenSK's attestation store holds its handle
//!   (version 2) where a software firmware would hold the 32-byte private key.
//! * `sign()` hashes the message (SHA-256) and lets the chip sign the digest. The chip config has
//!   no LimitedUse bit, so the signature budget is counted here: before every credential
//!   signature the chip's monotonic Counter 0 is incremented, and the chip refuses to increment
//!   past `COUNTER_MAX` (the config preloads it with `COUNTER_MAX - budget`). The attestation
//!   key does not spend the budget.

use alloc::vec::Vec;
use core::cell::RefCell;
use critical_section::Mutex;
use opensk::api::crypto::ec_signing::{EcPublicKey, EcSecretKey, EcSignature, Ecdsa};
use opensk::api::crypto::EC_FIELD_SIZE;
use opensk::api::rng::Rng;
use sha2::{Digest, Sha256};

use super::chip::ChipOps;
use super::proto::Error;

/// Slot map of the provisioned chip (atecc608a/out/atecc608a_general_config.bin): slots 0-9 are
/// ECC P-256 private-key slots with GenKey enabled. Slot 0 holds the attestation key (made once,
/// never overwritten by the firmware); slots 1..=9 are credential slots. Slots 10-15 are not used.
pub const ATTEST_SLOT: u8 = 0;
pub const FIRST_CRED_SLOT: u8 = 1;
/// Number of credential slots (the 10th registration evicts the oldest credential).
pub const SLOTS: u8 = 9;

/// Handle of a credential key (slot < SLOTS) / of the attestation key (slot == ATTEST_SLOT).
pub const HANDLE_CRED: u8 = 1;
pub const HANDLE_ATTEST: u8 = 2;
const HANDLE_LEN: usize = 32;
const FP_LEN: usize = 6;
/// Counter 0 value at which the chip refuses to count further (datasheet maximum).
pub const COUNTER_MAX: u32 = 2_097_151;

type Chip = &'static mut (dyn ChipOps + Send);

static CHIP: Mutex<RefCell<Option<Chip>>> = Mutex::new(RefCell::new(None));
static PUBKEYS: Mutex<RefCell<[Option<[u8; 64]>; 16]>> = Mutex::new(RefCell::new([None; 16]));

/// Registers the chip driver. Call once at start-up.
pub fn install(chip: Chip) {
    critical_section::with(|cs| *CHIP.borrow(cs).borrow_mut() = Some(chip));
}

/// Removes the driver again (host tests).
pub fn uninstall() {
    critical_section::with(|cs| {
        *CHIP.borrow(cs).borrow_mut() = None;
        *PUBKEYS.borrow(cs).borrow_mut() = [None; 16];
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

/// Remaining signatures before the chip refuses to sign (`None`: chip not reachable).
pub fn budget_left() -> Option<u32> {
    with_chip(|c| c.counter(0)).ok().map(|v| COUNTER_MAX.saturating_sub(v))
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

    fn random(_rng: &mut impl Rng) -> Self {
        // Round-robin slot from Counter 1 (first registration: counter 1 -> slot FIRST_CRED_SLOT).
        // If the chip refuses GenKey in a slot (e.g. a slot that cannot hold a P-256 private key)
        // the next slot is tried, so such a slot is simply never used.
        for attempt in 0..SLOTS {
            let n = with_chip(|c| c.counter_inc(1)).unwrap_or_else(|_| panic!("se: counter 1"));
            let slot = FIRST_CRED_SLOT + (n.wrapping_sub(1) % SLOTS as u32) as u8;
            match with_chip(|c| c.gen_key(slot)) {
                Ok(pubkey) => {
                    critical_section::with(|cs| PUBKEYS.borrow(cs).borrow_mut()[slot as usize] = Some(pubkey));
                    return SeSecretKey { slot, pubkey };
                }
                Err(Error::Status(_)) if attempt + 1 < SLOTS => continue,
                Err(_) => break,
            }
        }
        panic!("se: GenKey failed")
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
        // Spend one unit of the budget first (like a LimitedUse key would). At the limit the chip
        // refuses to increment, and nothing is signed.
        if self.slot != ATTEST_SLOT && with_chip(|c| c.counter_inc(0)).is_err() {
            return SeSignature { r: [0; 32], s: [0; 32] };
        }
        match with_chip(|c| c.sign(self.slot, &digest)) {
            Ok(sig) => {
                let mut r = [0u8; 32];
                let mut s = [0u8; 32];
                r.copy_from_slice(&sig[..32]);
                s.copy_from_slice(&sig[32..]);
                SeSignature { r, s }
            }
            // The trait cannot report errors. A refused signature (budget used up, chip gone)
            // becomes an all-zero signature that no verifier accepts; `PicoUserPresence` already
            // refuses new operations once `budget_left()` is 0.
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
        // The slot may have been recycled for a newer credential (or the attestation key replaced).
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
