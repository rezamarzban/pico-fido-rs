//! OpenSK `Ecdsa` whose private keys never leave the ATECC608A.
//!
//! * `random()` allocates the next chip slot (round-robin on Counter 1, which survives power
//!   cycles) and runs GenKey there. The key that was in that slot is overwritten: with N slots
//!   the N+1-th registration evicts the oldest credential (its handle then fails `import`).
//! * `export()` is a 32-byte *handle*: [version][slot][6-byte public-key fingerprint][zeros].
//!   OpenSK stores it inside the encrypted credential ID, exactly like a wrapped software key.
//! * `import()` checks that the slot still holds the key the handle was made for (fingerprint).
//! * `sign()` hashes the message (SHA-256) and lets the chip sign the digest. The chip's
//!   LimitedUse/Counter 0 limit is what stops signing after the configured budget.

use alloc::vec::Vec;
use core::cell::RefCell;
use critical_section::Mutex;
use opensk::api::crypto::ec_signing::{EcPublicKey, EcSecretKey, EcSignature, Ecdsa};
use opensk::api::crypto::EC_FIELD_SIZE;
use opensk::api::rng::Rng;
use sha2::{Digest, Sha256};

use super::chip::ChipOps;
use super::proto::Error;

/// Number of chip slots used for credential keys (feature `se_slots_16`: all sixteen).
#[cfg(feature = "se_slots_16")]
pub const SLOTS: u8 = 16;
#[cfg(not(feature = "se_slots_16"))]
pub const SLOTS: u8 = 8;

const HANDLE_VERSION: u8 = 1;
const HANDLE_LEN: usize = 32;
const FP_LEN: usize = 6;
/// Counter 0 value at which a LimitedUse key stops working (chip datasheet).
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

/// XORs chip randomness into `buf` (32 bytes per chip call). Silent no-op without a chip.
pub fn mix_random(buf: &mut [u8]) {
    for chunk in buf.chunks_mut(32) {
        if let Ok(r) = with_chip(|c| c.random()) {
            for (b, x) in chunk.iter_mut().zip(r.iter()) {
                *b ^= x;
            }
        }
    }
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
        // Round-robin slot from Counter 1 (first registration: counter 1 -> slot 0).
        let n = with_chip(|c| c.counter_inc(1)).unwrap_or_else(|_| panic!("se: counter 1"));
        let slot = (n.wrapping_sub(1) % SLOTS as u32) as u8;
        let pubkey = with_chip(|c| c.gen_key(slot)).unwrap_or_else(|_| panic!("se: GenKey failed"));
        critical_section::with(|cs| PUBKEYS.borrow(cs).borrow_mut()[slot as usize] = Some(pubkey));
        SeSecretKey { slot, pubkey }
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
            // The trait cannot report errors. A refused signature (budget used up, chip gone)
            // becomes an all-zero signature that no verifier accepts; `PicoUserPresence` already
            // refuses new operations once `budget_left()` is 0.
            Err(_) => SeSignature { r: [0; 32], s: [0; 32] },
        }
    }

    fn export(&self) -> Vec<u8> {
        let mut h = alloc::vec![0u8; HANDLE_LEN];
        h[0] = HANDLE_VERSION;
        h[1] = self.slot;
        h[2..2 + FP_LEN].copy_from_slice(&fingerprint(&self.pubkey));
        h
    }

    fn import(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != HANDLE_LEN || bytes[0] != HANDLE_VERSION || bytes[1] >= SLOTS {
            return None;
        }
        if bytes[2 + FP_LEN..].iter().any(|&b| b != 0) {
            return None;
        }
        let slot = bytes[1];
        let pubkey = cached_pubkey(slot).ok()?;
        // The slot may have been recycled for a newer credential.
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
