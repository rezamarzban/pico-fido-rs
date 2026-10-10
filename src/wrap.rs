//! Wrapping of the master key under a key derived from the PIN.
//!
//! KEK material = Argon2id(password = LEFT(SHA-256(PIN), 16), salt = random 16 bytes, m, t, p = 1),
//! 64 bytes: the first 32 are the encryption key, the last 32 the MAC key.
//! Encrypt-then-MAC with HMAC-SHA-256 only:
//!   keystream = HMAC(enc_key, "fido-wrap-ks" || salt)      (one block = 32 bytes = the key size)
//!   body      = master XOR keystream
//!   tag       = HMAC(mac_key, "fido-wrap-tag" || m_kib || t || salt || body)
//! A fresh random salt is used for every wrap, so a keystream is never reused. A wrong PIN is
//! detected by the tag; there is no separate PIN verifier stored that could be attacked offline.
//!
//! The cost parameters are stored in the record, so they can be raised later without breaking
//! existing devices. They are bounded by the heap (main.rs HEAP_SIZE): see MAX_M_KIB.
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::store::Record;

/// Argon2 memory in KiB / passes for new wraps. The RP2040 has 264 KiB RAM in total, so memory
/// hardness is limited and the passes carry the cost. NOT measured on hardware: check the logged
/// "pin op took N ms" and tune (target about 0.5 - 1 s per guess).
#[cfg(not(test))]
pub const M_KIB: u32 = 96;
#[cfg(not(test))]
pub const T_COST: u8 = 24;
#[cfg(test)]
pub const M_KIB: u32 = 8;
#[cfg(test)]
pub const T_COST: u8 = 1;
/// Largest memory cost a stored record may ask for (protects the 160 KiB heap).
pub const MAX_M_KIB: u32 = 128;

fn kdf(pin_hash: &[u8; 16], salt: &[u8; 16], m_kib: u32, t: u8) -> Option<[u8; 64]> {
    if !(8..=MAX_M_KIB).contains(&m_kib) || t == 0 {
        return None;
    }
    let params = Params::new(m_kib, t as u32, 1, Some(64)).ok()?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 64];
    a.hash_password_into(pin_hash, salt, &mut out).ok()?;
    Some(out)
}

fn hmac_of(key: &[u8], parts: &[&[u8]]) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m
}

fn tag_of(mac_key: &[u8], m_kib: u32, t: u8, salt: &[u8; 16], body: &[u8; 32]) -> Hmac<Sha256> {
    hmac_of(
        mac_key,
        &[b"fido-wrap-tag", &m_kib.to_le_bytes(), &[t], salt, body],
    )
}

/// Wraps `master` under the PIN. `None` only if the key derivation itself fails.
pub fn wrap(master: &[u8; 32], pin_hash: &[u8; 16], salt: [u8; 16]) -> Option<Record> {
    let mut k = kdf(pin_hash, &salt, M_KIB, T_COST)?;
    let mut ks: [u8; 32] = hmac_of(&k[..32], &[b"fido-wrap-ks", &salt])
        .finalize()
        .into_bytes()
        .into();
    let mut body = [0u8; 32];
    for ((b, m), s) in body.iter_mut().zip(master).zip(&ks) {
        *b = m ^ s;
    }
    ks.zeroize();
    let tag: [u8; 32] = tag_of(&k[32..], M_KIB, T_COST, &salt, &body)
        .finalize()
        .into_bytes()
        .into();
    k.zeroize();
    Some(Record {
        wrapped: true,
        m_kib: M_KIB,
        t_cost: T_COST,
        salt,
        body,
        tag,
    })
}

/// Recovers the master key. `None` = wrong PIN (or damaged / unsupported record).
pub fn unwrap(rec: &Record, pin_hash: &[u8; 16]) -> Option<[u8; 32]> {
    if !rec.wrapped {
        return None;
    }
    let mut k = kdf(pin_hash, &rec.salt, rec.m_kib, rec.t_cost)?;
    let ok = tag_of(&k[32..], rec.m_kib, rec.t_cost, &rec.salt, &rec.body)
        .verify_slice(&rec.tag)
        .is_ok();
    let mut master = None;
    if ok {
        let mut ks: [u8; 32] = hmac_of(&k[..32], &[b"fido-wrap-ks", &rec.salt])
            .finalize()
            .into_bytes()
            .into();
        let mut m = [0u8; 32];
        for ((o, b), s) in m.iter_mut().zip(&rec.body).zip(&ks) {
            *o = b ^ s;
        }
        ks.zeroize();
        master = Some(m);
    }
    k.zeroize();
    master
}
