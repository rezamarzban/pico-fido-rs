//! RNG for OpenSK. The only entropy source is the ATECC608A: an HMAC-DRBG (NIST SP 800-90A,
//! HMAC-SHA-256) is seeded with the chip's Random command and re-seeded from the chip every
//! `RESEED_BYTES` of output.
//!
//! If the chip does not answer there is no fallback to a weaker source: the firmware halts
//! (a defmt panic), like at start-up without the chip.

use core::convert::Infallible;
use hmac::{Hmac, KeyInit, Mac};
use opensk::api::rng::rand_core::{utils, TryCryptoRng, TryRng};
use opensk::api::rng::Rng;
use sha2::Sha256;

use crate::se::ecdsa::chip_random;

/// Output between two re-seeds. One chip Random call takes ~20 ms.
const RESEED_BYTES: u32 = 1024;

fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// HMAC_DRBG with SHA-256 (SP 800-90A 10.1.2), no additional input, no prediction resistance
/// (the re-seed from the chip replaces it).
struct HmacDrbg {
    k: [u8; 32],
    v: [u8; 32],
}

impl HmacDrbg {
    fn new(seed: &[u8; 32]) -> Self {
        let mut d = HmacDrbg {
            k: [0u8; 32],
            v: [1u8; 32],
        };
        d.update(Some(seed));
        d
    }

    fn update(&mut self, data: Option<&[u8; 32]>) {
        let empty: &[u8] = &[];
        let d: &[u8] = match data {
            Some(x) => x,
            None => empty,
        };
        self.k = hmac(&self.k, &[&self.v, &[0x00], d]);
        self.v = hmac(&self.k, &[&self.v]);
        if data.is_some() {
            self.k = hmac(&self.k, &[&self.v, &[0x01], d]);
            self.v = hmac(&self.k, &[&self.v]);
        }
    }

    fn reseed(&mut self, seed: &[u8; 32]) {
        self.update(Some(seed));
    }

    fn fill(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(32) {
            self.v = hmac(&self.k, &[&self.v]);
            chunk.copy_from_slice(&self.v[..chunk.len()]);
        }
        self.update(None);
    }
}

pub struct PicoRng {
    drbg: HmacDrbg,
    since_seed: u32,
    /// Relying party of the key about to be created (set by OpenSK, see third_party/opensk-rp-hint.patch).
    rp_hint: Option<[u8; 32]>,
}

fn seed() -> [u8; 32] {
    for _ in 0..3 {
        if let Ok(s) = chip_random() {
            return s;
        }
    }
    defmt::panic!("RNG: the secure element does not answer");
}

impl PicoRng {
    /// Needs the chip driver to be installed (`se::i2c::init`).
    pub fn new() -> Self {
        Self {
            drbg: HmacDrbg::new(&seed()),
            since_seed: 0,
            rp_hint: None,
        }
    }
}

impl TryRng for PicoRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        if self.since_seed >= RESEED_BYTES {
            self.drbg.reseed(&seed());
            self.since_seed = 0;
        }
        self.drbg.fill(dest);
        self.since_seed = self.since_seed.saturating_add(dest.len() as u32);
        Ok(())
    }
}

impl TryCryptoRng for PicoRng {}

impl Rng for PicoRng {
    fn set_rp_id_hash(&mut self, rp_id_hash: &[u8; 32]) {
        self.rp_hint = Some(*rp_id_hash);
    }

    fn take_rp_id_hash(&mut self) -> Option<[u8; 32]> {
        self.rp_hint.take()
    }
}
