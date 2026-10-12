//! RNG adapter for OpenSK: reuses the existing ROSC + SHA-256 conditioning.

use opensk::api::rng::Rng;
use rand_core::{CryptoRng, RngCore};

/// Thin wrapper that satisfies OpenSK's `Rng` trait.
pub struct PicoRng;

impl PicoRng {
    pub fn new() -> Self {
        Self
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
        // Reuse the existing conditioned ROSC RNG from keys.rs.
        crate::keys::fill_random(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for PicoRng {}

impl Rng for PicoRng {}
