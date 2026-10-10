//! CTAP2 PIN/UV auth protocols 1 and 2: shared secret, AES-256-CBC, HMAC-SHA-256 (crypto only;
//! the command logic is in ctap.rs).
//!
//! Protocol 1: secret = SHA-256(Z); zero IV, no IV on the wire; MAC = first 16 bytes of HMAC.
//! Protocol 2: HKDF-SHA-256 (zero salt) with info "CTAP2 HMAC key" / "CTAP2 AES key";
//!             random IV prepended to the ciphertext; MAC = full 32 bytes of HMAC.
// The RustCrypto `cipher` 0.4 API used here names `GenericArray`, which newer generic-array
// releases mark deprecated. Remove this allow when moving to the cipher 0.5 / generic-array 1.x API.
#![allow(deprecated)]

use aes::cipher::{generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::cbor::{R, W};
use crate::ctap::err;

type Enc = cbc::Encryptor<Aes256>;
type Dec = cbc::Decryptor<Aes256>;

pub struct Shared {
    v: u8,
    mac_key: [u8; 32],
    aes_key: [u8; 32],
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.mac_key.zeroize();
        self.aes_key.zeroize();
    }
}

fn hmac_of(key: &[u8], parts: &[&[u8]]) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m
}

/// HKDF-SHA-256 with a 32-byte zero salt, one output block (32 bytes).
fn hkdf(z: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac_of(&[0u8; 32], &[z]).finalize().into_bytes();
    hmac_of(&prk, &[info, &[1]]).finalize().into_bytes().into()
}

/// Constant-time comparison of the first `n` bytes of `full` with `tag` (which must be `n` long).
fn tag_matches(full: &[u8], tag: &[u8], n: usize) -> bool {
    if tag.len() != n {
        return false;
    }
    let mut d = 0u8;
    for (a, b) in full[..n].iter().zip(tag) {
        d |= a ^ b;
    }
    d == 0
}

fn mac_len(v: u8) -> usize {
    if v == 1 {
        16
    } else {
        32
    }
}

/// Checks a pinUvAuthParam made with the pinUvAuthToken (`token` is the HMAC key).
pub fn verify_token(v: u8, token: &[u8; 32], parts: &[&[u8]], tag: &[u8]) -> bool {
    tag_matches(
        &hmac_of(token, parts).finalize().into_bytes(),
        tag,
        mac_len(v),
    )
}

impl Shared {
    /// From the raw ECDH x-coordinate.
    pub fn from_z(v: u8, z: &[u8]) -> Shared {
        if v == 1 {
            let h: [u8; 32] = Sha256::digest(z).into();
            Shared {
                v,
                mac_key: h,
                aes_key: h,
            }
        } else {
            Shared {
                v,
                mac_key: hkdf(z, b"CTAP2 HMAC key"),
                aes_key: hkdf(z, b"CTAP2 AES key"),
            }
        }
    }

    pub fn derive(v: u8, sk: &SecretKey, peer: &PublicKey) -> Shared {
        let z = diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
        Shared::from_z(v, z.raw_secret_bytes())
    }

    /// `pt` must be a multiple of 16 bytes.
    pub fn encrypt_iv(&self, pt: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        let mut buf = pt.to_vec();
        let mut e = Enc::new(
            GenericArray::from_slice(&self.aes_key),
            GenericArray::from_slice(iv),
        );
        for b in buf.chunks_exact_mut(16) {
            e.encrypt_block_mut(GenericArray::from_mut_slice(b));
        }
        if self.v == 2 {
            let mut out = Vec::with_capacity(16 + buf.len());
            out.extend_from_slice(iv);
            out.extend_from_slice(&buf);
            out
        } else {
            buf
        }
    }

    pub fn encrypt(&self, pt: &[u8], rng: &mut dyn FnMut(&mut [u8])) -> Vec<u8> {
        let mut iv = [0u8; 16];
        if self.v == 2 {
            rng(&mut iv);
        }
        self.encrypt_iv(pt, &iv)
    }

    /// Returns `None` if the length is not valid for this protocol.
    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        let (iv, ct): (&[u8], &[u8]) = if self.v == 2 {
            if data.len() < 32 {
                return None;
            }
            data.split_at(16)
        } else {
            (&[0u8; 16][..], data)
        };
        if ct.is_empty() || ct.len() % 16 != 0 {
            return None;
        }
        let mut buf = ct.to_vec();
        let mut d = Dec::new(
            GenericArray::from_slice(&self.aes_key),
            GenericArray::from_slice(iv),
        );
        for b in buf.chunks_exact_mut(16) {
            d.decrypt_block_mut(GenericArray::from_mut_slice(b));
        }
        Some(buf)
    }

    /// `authenticate(shared secret, parts)` check for a received pinUvAuthParam.
    pub fn verify(&self, parts: &[&[u8]], tag: &[u8]) -> bool {
        tag_matches(
            &hmac_of(&self.mac_key, parts).finalize().into_bytes(),
            tag,
            mac_len(self.v),
        )
    }

    #[cfg(test)]
    pub fn authenticate(&self, parts: &[&[u8]]) -> Vec<u8> {
        hmac_of(&self.mac_key, parts).finalize().into_bytes()[..mac_len(self.v)].to_vec()
    }
}

/// Fresh P-256 key for the key agreement.
pub fn new_secret(rng: &mut dyn FnMut(&mut [u8])) -> SecretKey {
    loop {
        let mut b = [0u8; 32];
        rng(&mut b);
        let k = SecretKey::from_slice(&b);
        b.zeroize();
        if let Ok(k) = k {
            return k;
        }
    }
}

/// Parses a COSE_Key (ECDH-ES+HKDF-256, P-256) from the platform. The coordinates are always read
/// as P-256, so the key must also say so: kty = 2 (EC2) and crv = 1 (P-256) are required, and alg
/// must be -25 (ECDH-ES+HKDF-256) when present (some clients omit it). Contradictions are rejected.
pub fn parse_cose(r: &mut R) -> Result<PublicKey, u8> {
    let (mut kty, mut alg, mut crv) = (None, None, None);
    let (mut x, mut y) = (None, None);
    for _ in 0..r.map()? {
        match r.int()? {
            1 => kty = Some(r.int()?),
            3 => alg = Some(r.int()?),
            -1 => crv = Some(r.int()?),
            -2 => x = Some(r.bytes()?),
            -3 => y = Some(r.bytes()?),
            _ => r.skip()?,
        }
    }
    let (Some(x), Some(y)) = (x, y) else {
        return Err(err::MISSING_PARAMETER);
    };
    if x.len() != 32 || y.len() != 32 {
        return Err(err::INVALID_PARAMETER);
    }
    let mut sec = [0u8; 65];
    sec[0] = 4;
    sec[1..33].copy_from_slice(x);
    sec[33..].copy_from_slice(y);
    let pk = PublicKey::from_sec1_bytes(&sec).map_err(|_| err::INVALID_PARAMETER)?;
    if kty.is_none() || crv.is_none() {
        return Err(err::MISSING_PARAMETER);
    }
    if kty != Some(2) || crv != Some(1) || !matches!(alg, None | Some(-25)) {
        return Err(err::INVALID_PARAMETER);
    }
    Ok(pk)
}

/// COSE_Key of the authenticator's key agreement key.
pub fn cose_key(pk: &PublicKey) -> Vec<u8> {
    let pt = pk.to_encoded_point(false);
    let mut c = W::new();
    c.map(5);
    c.uint(1);
    c.uint(2); // kty: EC2
    c.uint(3);
    c.int(-25); // alg: ECDH-ES+HKDF-256
    c.int(-1);
    c.uint(1); // crv: P-256
    c.int(-2);
    c.bytes(pt.x().unwrap());
    c.int(-3);
    c.bytes(pt.y().unwrap());
    c.0
}
