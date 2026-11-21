//! Wrapping of the 32-byte master seed under a key derived from the PIN, with AES-256-GCM.
//!
//! key   = HMAC-SHA-256(salt, "fido-wrap-key" || password)         (32 bytes, the AES-256 key)
//! nonce = salt[..12]                                               (salt is fresh random per wrap)
//! body || tag = AES-256-GCM(key, nonce, aad = "fido-wrap-v3" || puf flag, seed)
//! The 16-byte GCM tag is stored in `Record::tag[..16]` (the rest is zero). A wrong PIN is detected
//! by the tag; no PIN verifier is stored.
//!
//! There is NO memory-hard KDF any more: the only cost of a PIN guess is one HMAC + one AES-GCM
//! decryption. Offline guessing against a flash dump is therefore only limited by the PUF input
//! (`password` below) and by the PIN's own entropy.
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::store::Record;

/// `Record::m_kib` / `t_cost` of an AES-GCM wrap. Old Argon2id records (m_kib >= 8) are no longer
/// readable and are refused: do a CTAP reset (or re-set the PIN on a device that has none).
const FMT_AES: u32 = 0;

/// The key input: the 16-byte PIN hash, or - for PUF-bound records - an HMAC of it under
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

fn hmac_of(key: &[u8], parts: &[&[u8]]) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m
}

fn aes_key(password: &[u8], salt: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let k: [u8; 32] = hmac_of(salt, &[b"fido-wrap-key", password])
        .finalize()
        .into_bytes()
        .into();
    Zeroizing::new(k)
}

fn aad(puf: bool) -> [u8; 13] {
    let mut a = *b"fido-wrap-v3\0";
    a[12] = puf as u8;
    a
}

/// Wraps `seed` under the PIN (and the PUF key if given). `None` only on an internal AES error.
pub fn wrap(
    seed: &[u8; 32],
    pin_hash: &[u8; 16],
    salt: [u8; 16],
    puf: Option<&[u8; 32]>,
) -> Option<Record> {
    let (pw, n) = password(pin_hash, puf);
    let key = aes_key(&pw[..n], &salt);
    let cipher = Aes256Gcm::new_from_slice(&key[..]).ok()?;
    let mut body = *seed;
    let t = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(&salt[..12]),
            &aad(puf.is_some()),
            &mut body,
        )
        .ok()?;
    let mut tag = [0u8; 32];
    tag[..16].copy_from_slice(&t);
    Some(Record {
        wrapped: true,
        puf: puf.is_some(),
        puf_slot: 0, // the caller sets the real slot (`bind_slot` in env/harden.rs)
        m_kib: FMT_AES,
        t_cost: 0,
        salt,
        body,
        tag,
    })
}

/// Recovers the seed. `None` = wrong PIN (or damaged / unsupported record). The GCM tag check is
/// constant-time, the result is wiped on drop.
///
/// `puf` must be `Some` exactly when `rec.puf` is set.
pub fn unwrap(
    rec: &Record,
    pin_hash: &[u8; 16],
    puf: Option<&[u8; 32]>,
) -> Option<Zeroizing<[u8; 32]>> {
    if !rec.wrapped || rec.puf != puf.is_some() || rec.m_kib != FMT_AES || rec.t_cost != 0 {
        return None;
    }
    if rec.tag[16..] != [0u8; 16] {
        return None;
    }
    let (pw, n) = password(pin_hash, puf);
    let key = aes_key(&pw[..n], &rec.salt);
    let cipher = Aes256Gcm::new_from_slice(&key[..]).ok()?;
    let mut m = Zeroizing::new(rec.body);
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&rec.salt[..12]),
            &aad(rec.puf),
            &mut m[..],
            Tag::from_slice(&rec.tag[..16]),
        )
        .ok()?;
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
    hmac_of(puf, &[b"puf-plain-tag", body])
        .finalize()
        .into_bytes()
        .into()
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
        if !legacy_plain_puf(rec) && !bool::from(plain_tag(k, &rec.body).as_slice().ct_eq(&rec.tag))
        {
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
