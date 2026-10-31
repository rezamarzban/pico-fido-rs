//! Wrapping of the 32-byte master seed ("the private key") under the PINs and the SRAM PUF.
//!
//! ```text
//! host PIN + IR PIN + SRAM-PUF secret --> Argon2id --> 256-bit key --> AES-256-GCM --> encrypted seed
//! ```
//!
//! Two stages, because the host dialog and the IR remote are separate PINs that are asked at different
//! moments (the host PIN in the host's PIN dialog, the IR PIN while the device waits for the physical
//! button):
//!
//! * **Stage 1, host PIN.** `pw1 = HMAC(K_puf, "puf-pin" || host_hash)` (or the bare 16-byte hash without a PUF)
//!   goes through Argon2id (salt = the record's random salt) and gives 64 bytes: `k1[..32]` and `k1[32..]`.
//!   `k1[32..]` makes the **host verifier** (16 bytes, stored in the record) that tells a right host PIN
//!   from a wrong one without the IR PIN. A record that has no IR PIN yet (`rec.ir == false`) is
//!   encrypted directly with `k1[..32]`.
//! * **Stage 2, IR PIN.** `pw2 = HMAC(K_puf, "puf-pin-ir" || host_hash || ir_digest)` (SHA-256 of the same
//!   input without a PUF) goes through Argon2id again; the first 32 bytes of the output are the
//!   AES-256-GCM key of an `rec.ir` record. A wrong IR PIN is detected by the GCM tag.
//!
//! Record: `body` = ciphertext (32 bytes), `tag[..16]` = GCM tag, `tag[16..]` = host verifier. The
//! GCM nonce is the first 12 bytes of the record's random salt: the key is derived from that salt, so every
//! key is used for exactly one encryption. The associated data binds the flags, the Argon2 parameters
//! and the salt. No PIN or IR hash is stored anywhere.
//!
//! Argon2 works in a static 64 KiB buffer, so it never touches the OpenSK heap. It is only called
//! from the main thread, one call at a time.
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use core::mem::MaybeUninit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::store::Record;

/// Argon2 memory in KiB / passes for new wraps. NOT measured on hardware: check the logged
/// time of a PIN check and tune `T_COST` (target about 0.5 - 1 s per Argon2 run; a PIN check with
/// an IR PIN runs Argon2 twice).
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

/// The Argon2 password of stage 1: the 16-byte host PIN hash, or - for PUF-bound records - an HMAC
/// of it under the SRAM-PUF key (so a flash dump alone cannot be used to test PIN guesses).
fn password_host(host: &[u8; 16], puf: Option<&[u8; 32]>) -> (Zeroizing<[u8; 32]>, usize) {
    let mut pw = Zeroizing::new([0u8; 32]);
    match puf {
        Some(k) => {
            let h = hmac_of(k, &[b"puf-pin", host]).finalize().into_bytes();
            pw.copy_from_slice(&h);
            (pw, 32)
        }
        None => {
            pw[..16].copy_from_slice(host);
            (pw, 16)
        }
    }
}

/// The Argon2 password of stage 2: host PIN hash + IR PIN digest (+ the PUF key).
fn password_full(host: &[u8; 16], ir: &[u8; 32], puf: Option<&[u8; 32]>) -> Zeroizing<[u8; 32]> {
    let mut pw = Zeroizing::new([0u8; 32]);
    match puf {
        Some(k) => {
            let h = hmac_of(k, &[b"puf-pin-ir", host, ir]).finalize().into_bytes();
            pw.copy_from_slice(&h);
        }
        None => {
            let mut h = Sha256::new();
            h.update(b"pin-ir-v2");
            h.update(host);
            h.update(ir);
            let d = h.finalize();
            pw.copy_from_slice(&d);
        }
    }
    pw
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

// ---- AES-256-GCM record ------------------------------------------------------------------------

const AAD_LEN: usize = 35;

/// Associated data: binds the flags, the Argon2 parameters and the salt to the ciphertext.
fn aad(puf: bool, ir: bool, m_kib: u32, t: u8, salt: &[u8; 16]) -> [u8; AAD_LEN] {
    let mut a = [0u8; AAD_LEN];
    a[..12].copy_from_slice(b"fido-wrap-v2");
    a[12] = puf as u8;
    a[13] = ir as u8;
    a[14..18].copy_from_slice(&m_kib.to_le_bytes());
    a[18] = t;
    a[19..].copy_from_slice(salt);
    a
}

/// The key is derived from the salt, so it is used once: the nonce can be taken from the salt.
fn nonce_of(salt: &[u8; 16]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n.copy_from_slice(&salt[..12]);
    n
}

/// 16-byte verifier of the host PIN from the MAC half of the stage-1 output.
fn verifier(k_mac: &[u8], a: &[u8; AAD_LEN]) -> [u8; 16] {
    let h = hmac_of(k_mac, &[b"fido-host-verify", a]).finalize().into_bytes();
    let mut v = [0u8; 16];
    v.copy_from_slice(&h[..16]);
    v
}

fn seal_record(
    seed: &[u8; 32],
    aes_key: &[u8],
    host_verifier: [u8; 16],
    salt: [u8; 16],
    puf: bool,
    ir: bool,
) -> Option<Record> {
    let cipher = Aes256Gcm::new_from_slice(aes_key).ok()?;
    let a = aad(puf, ir, M_KIB, T_COST, &salt);
    let nonce = nonce_of(&salt);
    let mut body = *seed;
    let gcm_tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &a, &mut body)
        .ok()?;
    let mut tag = [0u8; 32];
    tag[..16].copy_from_slice(&gcm_tag);
    tag[16..].copy_from_slice(&host_verifier);
    Some(Record {
        wrapped: true,
        puf,
        puf_slot: 0, // the caller sets the real slot (`bind_slot` in env/harden.rs)
        ir,
        m_kib: M_KIB,
        t_cost: T_COST,
        salt,
        body,
        tag,
    })
}

fn open_with(aes_key: &[u8], rec: &Record, a: &[u8; AAD_LEN]) -> Option<Zeroizing<[u8; 32]>> {
    let cipher = Aes256Gcm::new_from_slice(aes_key).ok()?;
    let nonce = nonce_of(&rec.salt);
    let mut buf = Zeroizing::new(rec.body);
    let gcm_tag = Tag::from_slice(&rec.tag[..16]);
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(&nonce), a, &mut buf[..], gcm_tag)
        .ok()?;
    Some(buf)
}

/// Wraps `seed` under the host PIN (and the PUF key if given) only: stage 1 decrypts it. Used when a
/// PIN is set and the IR PIN is not enrolled yet. `None` only if the key derivation fails.
pub fn wrap_host(
    seed: &[u8; 32],
    host: &[u8; 16],
    salt: [u8; 16],
    puf: Option<&[u8; 32]>,
) -> Option<Record> {
    let (pw, n) = password_host(host, puf);
    let k1 = Zeroizing::new(kdf(&pw[..n], &salt, M_KIB, T_COST)?);
    let a = aad(puf.is_some(), false, M_KIB, T_COST, &salt);
    seal_record(seed, &k1[..32], verifier(&k1[32..], &a), salt, puf.is_some(), false)
}

/// Wraps `seed` under host PIN + IR PIN digest (+ the PUF key if given): two Argon2id runs, the
/// first only for the host verifier, the second for the AES-256-GCM key.
pub fn wrap_full(
    seed: &[u8; 32],
    host: &[u8; 16],
    ir: &[u8; 32],
    salt: [u8; 16],
    puf: Option<&[u8; 32]>,
) -> Option<Record> {
    let (pw1, n1) = password_host(host, puf);
    let k1 = Zeroizing::new(kdf(&pw1[..n1], &salt, M_KIB, T_COST)?);
    let a = aad(puf.is_some(), true, M_KIB, T_COST, &salt);
    let pw2 = password_full(host, ir, puf);
    let k2 = Zeroizing::new(kdf(&pw2[..], &salt, M_KIB, T_COST)?);
    seal_record(seed, &k2[..32], verifier(&k1[32..], &a), salt, puf.is_some(), true)
}

/// Result of stage 1.
pub enum Host {
    /// Wrong host PIN (or damaged / unsupported record).
    Wrong,
    /// Right host PIN; the record needs the IR PIN too (`rec.ir`): nothing is decrypted yet.
    Verified,
    /// Right host PIN and the record has no IR PIN: the seed is open.
    Seed(Zeroizing<[u8; 32]>),
}

/// Stage 1: checks the host PIN against the record's verifier (constant time). `puf` must be `Some`
/// exactly when `rec.puf` is set.
pub fn host_stage(rec: &Record, host: &[u8; 16], puf: Option<&[u8; 32]>) -> Host {
    if !rec.wrapped || rec.puf != puf.is_some() {
        return Host::Wrong;
    }
    let (pw, n) = password_host(host, puf);
    let Some(k1) = kdf(&pw[..n], &rec.salt, rec.m_kib, rec.t_cost) else {
        return Host::Wrong;
    };
    let k1 = Zeroizing::new(k1);
    let a = aad(rec.puf, rec.ir, rec.m_kib, rec.t_cost, &rec.salt);
    let v = verifier(&k1[32..], &a);
    if !bool::from(v[..].ct_eq(&rec.tag[16..])) {
        return Host::Wrong;
    }
    if rec.ir {
        return Host::Verified;
    }
    match open_with(&k1[..32], rec, &a) {
        Some(seed) => Host::Seed(seed),
        None => Host::Wrong,
    }
}

/// Stage 2: opens the seed of an IR record with host PIN + IR PIN digest (+ PUF key). `None` = wrong
/// IR PIN (the GCM tag does not match) or a damaged / unsupported record.
pub fn open_ir(
    rec: &Record,
    host: &[u8; 16],
    ir: &[u8; 32],
    puf: Option<&[u8; 32]>,
) -> Option<Zeroizing<[u8; 32]>> {
    if !rec.wrapped || !rec.ir || rec.puf != puf.is_some() {
        return None;
    }
    let pw2 = password_full(host, ir, puf);
    let k2 = Zeroizing::new(kdf(&pw2[..], &rec.salt, rec.m_kib, rec.t_cost)?);
    let a = aad(rec.puf, rec.ir, rec.m_kib, rec.t_cost, &rec.salt);
    open_with(&k2[..32], rec, &a)
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
