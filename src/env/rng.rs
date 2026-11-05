//! RNG for OpenSK. The only entropy source is the ATECC608A: a ChaCha20 DRBG is seeded with the
//! chip's Random command and re-seeded from the chip every `RESEED_BYTES` of output.
//!
//! If the chip does not answer there is no fallback to a weaker source: the firmware halts
//! (a defmt panic), like at start-up without the chip.

use opensk::api::rng::Rng;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

use crate::se::ecdsa::chip_random;

/// Output between two re-seeds. One chip Random call takes ~20 ms.
const RESEED_BYTES: u32 = 1024;

pub struct PicoRng {
    drbg: ChaCha20Rng,
    since_seed: u32,
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
        }
    }
}

impl RngCore for PicoRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.since_seed >= RESEED_BYTES {
            self.drbg = ChaCha20Rng::from_seed(seed());
            self.since_seed = 0;
        }
        self.drbg.fill_bytes(dest);
        self.since_seed = self.since_seed.saturating_add(dest.len() as u32);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for PicoRng {}

impl Rng for PicoRng {}
