//! RNG for OpenSK. The only entropy source is the ATECC608A: a ChaCha20 DRBG is seeded with the
//! chip's Random command and re-seeded from the chip every `RESEED_BYTES` of output.
//!
//! If the chip does not answer there is no fallback to a weaker source: the firmware halts
//! (a defmt panic), like at start-up without the chip.

use core::convert::Infallible;
use opensk::api::rng::rand_core::{TryCryptoRng, TryRng};
use opensk::api::rng::Rng;
use rand_chacha::ChaCha20Rng;
// The DRBG is rand_chacha 0.3 (rand_core 0.6); OpenSK's `Rng` is built on rand_core 0.10.
use rand_core::{RngCore, SeedableRng};

use crate::se::ecdsa::chip_random;

/// Output between two re-seeds. One chip Random call takes ~20 ms.
const RESEED_BYTES: u32 = 1024;

pub struct PicoRng {
    drbg: ChaCha20Rng,
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
            drbg: ChaCha20Rng::from_seed(seed()),
            since_seed: 0,
            rp_hint: None,
        }
    }
}

impl PicoRng {
    fn fill(&mut self, dest: &mut [u8]) {
        if self.since_seed >= RESEED_BYTES {
            self.drbg = ChaCha20Rng::from_seed(seed());
            self.since_seed = 0;
        }
        self.drbg.fill_bytes(dest);
        self.since_seed = self.since_seed.saturating_add(dest.len() as u32);
    }
}

impl TryRng for PicoRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        self.fill(dest);
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
