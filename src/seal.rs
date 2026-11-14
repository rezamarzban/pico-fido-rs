//! AES-256-GCM sealing of everything sensitive that is written to the Pico's flash.
//!
//! * **Key hierarchy.** The root key is the 32-byte SRAM-PUF key (`puf.rs`, never stored). Per
//!   *domain* (key-value store, site directory, signature counter) two independent keys are derived
//!   with HMAC-SHA-256 from it:
//!   `enc = HMAC(root, "pfrs-flash-v1/<domain>/enc")` (the AES-256 key) and
//!   `siv = HMAC(root, "pfrs-flash-v1/<domain>/siv")` (only used to make nonces).
//! * **Nonce.** 96 bits, *synthetic*: `HMAC(siv, len(aad) as u32 LE || aad || plaintext)[..12]`. No
//!   counter has to survive a power cut and no RNG is needed (the chip's RNG cannot be called from
//!   inside the flash drivers). Two different (aad, plaintext) pairs get different nonces except
//!   with probability 2^-96 per pair; the same pair gets the same nonce AND the same ciphertext, so
//!   a nonce is never used for two different messages. The only thing this leaks is "this record is
//!   identical to that one".
//! * **Sealed layout** (all binary, little endian): `nonce (12) || ciphertext (= plaintext length) ||
//!   GCM tag (16)`. `OVERHEAD` = 28 bytes. The associated data (`aad`) is never stored: the caller
//!   rebuilds it from where the data lives (store key id, record position), so a sealed value moved to
//!   another key or position fails authentication.
//!
//! `host-test/seal_ref.py` is a Python reference of exactly this construction; the host tests check
//! known-answer vectors from it.

use aes_gcm::aead::{AeadInPlace, KeyInit as _}; // aes-gcm 0.10 (crypto-common 0.1); hmac 0.13 has its own `KeyInit`
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use alloc::vec::Vec;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// Bytes added to every sealed message.
pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// What a key protects. Keys of different domains are unrelated.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// OpenSK's key-value store (`env/persist.rs`).
    Store,
    /// Site directory (`env/dir_flash.rs`).
    Dir,
    /// Signature counter (`env/tally_flash.rs`).
    Tally,
}

impl Domain {
    fn label(self) -> &'static [u8] {
        match self {
            Domain::Store => b"store",
            Domain::Dir => b"dir",
            Domain::Tally => b"tally",
        }
    }
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// The keys of one domain, ready to use. Derived from the root key; wiped when dropped.
pub struct Sealer {
    cipher: Aes256Gcm,
    siv: Zeroizing<[u8; 32]>,
}

impl Sealer {
    pub fn new(root: &[u8; 32], domain: Domain) -> Sealer {
        let enc = Zeroizing::new(hmac(root, &[b"pfrs-flash-v1/", domain.label(), b"/enc"]));
        let siv = Zeroizing::new(hmac(root, &[b"pfrs-flash-v1/", domain.label(), b"/siv"]));
        Sealer {
            cipher: Aes256Gcm::new_from_slice(&enc[..]).expect("AES-256 key is 32 bytes"),
            siv,
        }
    }

    fn nonce(&self, aad: &[u8], plain: &[u8]) -> [u8; NONCE_LEN] {
        let h = hmac(&self.siv[..], &[&(aad.len() as u32).to_le_bytes(), aad, plain]);
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(&h[..NONCE_LEN]);
        n
    }

    /// Seals `plain` into `out` (`out.len()` must be `plain.len() + OVERHEAD`).
    pub fn seal_into(&self, aad: &[u8], plain: &[u8], out: &mut [u8]) {
        assert_eq!(out.len(), plain.len() + OVERHEAD);
        let nonce = self.nonce(aad, plain);
        let (n_out, rest) = out.split_at_mut(NONCE_LEN);
        let (ct, tag_out) = rest.split_at_mut(plain.len());
        n_out.copy_from_slice(&nonce);
        ct.copy_from_slice(plain);
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, ct)
            .expect("GCM: message length is within the limits");
        tag_out.copy_from_slice(&tag);
    }

    pub fn seal(&self, aad: &[u8], plain: &[u8]) -> Vec<u8> {
        let mut out = alloc::vec![0u8; plain.len() + OVERHEAD];
        self.seal_into(aad, plain, &mut out);
        out
    }

    /// The plaintext, or `None` if `sealed` is too short, was changed, belongs to another `aad`
    /// or was sealed under another key. Nothing of a rejected message is returned.
    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < OVERHEAD {
            return None;
        }
        let (nonce, rest) = sealed.split_at(NONCE_LEN);
        let (ct, tag) = rest.split_at(rest.len() - TAG_LEN);
        let mut buf = ct.to_vec();
        match self.cipher.decrypt_in_place_detached(
            Nonce::from_slice(nonce),
            aad,
            &mut buf,
            Tag::from_slice(tag),
        ) {
            Ok(()) => Some(buf),
            Err(_) => {
                // The buffer holds unauthenticated garbage (CTR output): drop it without using it.
                buf.fill(0);
                None
            }
        }
    }
}
