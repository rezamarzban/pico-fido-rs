//! Wrapping of the 32-byte master seed under a key derived from the PIN.
//!
//! KEK material = Argon2id(password = LEFT(SHA-256(PIN), 16), salt = random 16 bytes, m, t, p = 1),
//! 64 bytes: the first 32 are the encryption key, the last 32 the MAC key.
//! Encrypt-then-MAC with HMAC-SHA-256 only:
//!   keystream = HMAC(enc_key, "fido-wrap-ks" || salt)      (one block = 32 bytes = the seed size)
//!   body      = seed XOR keystream
//!   tag       = HMAC(mac_key, "fido-wrap-tag" || m_kib || t || salt || body)
//! A wrong PIN is detected by the tag; no PIN verifier is stored.
//!
//! Argon2 works in a static 64 KiB buffer, so it never touches the OpenSK heap. It is only called
//! from the main thread, one call at a time.
use argon2::{Algorithm, Argon2, Block, Params, Version};
use core::mem::MaybeUninit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::store::Record;

/// Argon2 memory in KiB / passes for new wraps. NOT measured on hardware: check the logged
/// time of a PIN check and tune `T_COST` (target about 0.5 - 1 s per guess).
pub const M_KIB: u32 = 64;
pub const T_COST: u8 = 24;
/// Largest memory cost a stored record may ask for: the size of the static buffer.
pub const MAX_M_KIB: u32 = 64;
/// Upper bound for a stored time cost. The value comes from flash, so a damaged or forged record
/// must not be able to make a PIN check run for minutes.
pub const MAX_T_COST: u8 = 64;

const BLOCKS: usize = MAX_M_KIB as usize;
const _: () = core::assert!(core::mem::size_of::<Block>() == 1024);

static mut ARGON_MEM: [MaybeUninit<Block>; BLOCKS] = {
    const U: MaybeUninit<Block> = MaybeUninit::uninit();
    [U; BLOCKS]
};

/// The Argon2 password: the 16-byte PIN hash, or - for PUF-bound records - an HMAC of it under
/// the SRAM-PUF key (so a flash dump alone cannot be used to test PIN guesses).
fn password(pin_hash: &[u8; 16], puf: Option<&[u8; 32]>) -> (Zeroizing<[u8; 32]>, usize) {
    let mut pw = Zeroizing::new([0u8; 32]);
    match puf {
        Some(k) => {
            let h = hmac_of(k, &[b"puf-pin", pin_hash]).finalize().into_bytes();
            pw.copy_from_slice(&h);
            (pw, 32)
        }
        None => {
            pw[..16].copy_from_slice(pin_hash);
            (pw, 16)
        }
    }
}

fn kdf(password: &[u8], salt: &[u8; 16], m_kib: u32, t: u8) -> Option<[u8; 64]> {
    if !(8..=MAX_M_KIB).contains(&m_kib) || !m_kib.is_multiple_of(4) || !(1..=MAX_T_COST).contains(&t) {
        return None;
    }
    let params = Params::new(m_kib, t as u32, 1, Some(64)).ok()?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 64];
    // SAFETY: single core, called from the main thread only and never re-entrantly, so nothing
    // else touches ARGON_MEM. All-zero bytes are a valid `Block` (an array of u64).
    let ok = unsafe {
        let base = core::ptr::addr_of_mut!(ARGON_MEM) as *mut u8;
        core::ptr::write_bytes(base, 0, BLOCKS * 1024);
        let mem = core::slice::from_raw_parts_mut(base as *mut Block, m_kib as usize);
        let ok = a
            .hash_password_into_with_memory(password, salt, &mut out, mem)
            .is_ok();
        // Wipe the working set (volatile: must not be optimised away).
        for i in 0..BLOCKS * 1024 {
            core::ptr::write_volatile(base.add(i), 0);
        }
        ok
    };
    if ok {
        Some(out)
    } else {
        out.zeroize();
        None
    }
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

/// Wraps `seed` under the PIN (and the PUF key if given). `None` only if the key derivation fails.
pub fn wrap(
    seed: &[u8; 32],
    pin_hash: &[u8; 16],
    salt: [u8; 16],
    puf: Option<&[u8; 32]>,
) -> Option<Record> {
    let (pw, n) = password(pin_hash, puf);
    let mut k = kdf(&pw[..n], &salt, M_KIB, T_COST)?;
    let mut ks: [u8; 32] = hmac_of(&k[..32], &[b"fido-wrap-ks", &salt])
        .finalize()
        .into_bytes()
        .into();
    let mut body = [0u8; 32];
    for ((b, m), s) in body.iter_mut().zip(seed).zip(&ks) {
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
        puf: puf.is_some(),
        m_kib: M_KIB,
        t_cost: T_COST,
        salt,
        body,
        tag,
    })
}

/// Recovers the seed. `None` = wrong PIN (or damaged / unsupported record). The tag comparison is
/// constant-time (`subtle`), the result is wiped on drop.
///
/// `puf` must be `Some` exactly when `rec.puf` is set.
pub fn unwrap(
    rec: &Record,
    pin_hash: &[u8; 16],
    puf: Option<&[u8; 32]>,
) -> Option<Zeroizing<[u8; 32]>> {
    if !rec.wrapped || rec.puf != puf.is_some() {
        return None;
    }
    let (pw, n) = password(pin_hash, puf);
    let mut k = Zeroizing::new(kdf(&pw[..n], &rec.salt, rec.m_kib, rec.t_cost)?);
    let expect = tag_of(&k[32..], rec.m_kib, rec.t_cost, &rec.salt, &rec.body)
        .finalize()
        .into_bytes();
    if !bool::from(expect.as_slice().ct_eq(&rec.tag)) {
        k.zeroize();
        return None;
    }
    let mut ks: [u8; 32] = hmac_of(&k[..32], &[b"fido-wrap-ks", &rec.salt])
        .finalize()
        .into_bytes()
        .into();
    let mut m = Zeroizing::new([0u8; 32]);
    for ((o, b), s) in m.iter_mut().zip(&rec.body).zip(&ks) {
        *o = b ^ s;
    }
    ks.zeroize();
    Some(m)
}

/// Expands the 32-byte seed to the 128 bytes OpenSK's key store expects: encryption key,
/// authentication key and the two cred-random keys (see `get_master_keys` in OpenSK).
/// Writes into a caller-owned buffer so no plaintext copy is left behind by a by-value return.
pub fn expand_into(seed: &[u8; 32], out: &mut [u8; 128]) {
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let mut block: [u8; 32] = hmac_of(seed, &[b"harden-master-v1", &[i as u8]])
            .finalize()
            .into_bytes()
            .into();
        chunk.copy_from_slice(&block);
        block.zeroize();
    }
}

/// A no-PIN record whose seed is masked with the PUF key: a flash dump alone does not hold the seed.
pub fn plain_puf(seed: &[u8; 32], puf: &[u8; 32]) -> Record {
    let mut rec = Record::plain(*seed);
    let mask = hmac_of(puf, &[b"puf-plain-mask"]).finalize().into_bytes();
    for (b, m) in rec.body.iter_mut().zip(mask.iter()) {
        *b ^= m;
    }
    rec.puf = true;
    // Authenticate the masked seed: with a wrong PUF key (for example after the helper data was
    // replaced) `plain_seed` must fail instead of returning a wrong seed.
    rec.tag = plain_tag(puf, &rec.body);
    rec
}

fn plain_tag(puf: &[u8; 32], body: &[u8; 32]) -> [u8; 32] {
    hmac_of(puf, &[b"puf-plain-tag", body]).finalize().into_bytes().into()
}

/// A PUF-masked no-PIN record written before the tag existed (all-zero tag). It is still
/// accepted, then re-sealed with a tag at the next boot that has the PUF key.
pub fn legacy_plain_puf(rec: &Record) -> bool {
    rec.puf && !rec.wrapped && rec.tag == [0u8; 32]
}

/// The seed of a no-PIN record (`puf` must be `Some` exactly when `rec.puf` is set).
pub fn plain_seed(rec: &Record, puf: Option<&[u8; 32]>) -> Option<Zeroizing<[u8; 32]>> {
    if rec.wrapped || rec.puf != puf.is_some() {
        return None;
    }
    if let Some(k) = puf {
        if !legacy_plain_puf(rec) && !bool::from(plain_tag(k, &rec.body).as_slice().ct_eq(&rec.tag)) {
            return None; // wrong PUF key or damaged record
        }
    }
    let mut seed = Zeroizing::new(rec.body);
    if let Some(k) = puf {
        let mask = hmac_of(k, &[b"puf-plain-mask"]).finalize().into_bytes();
        for (b, m) in seed.iter_mut().zip(mask.iter()) {
            *b ^= m;
        }
    }
    Some(seed)
}
