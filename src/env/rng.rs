//! RNG adapter for OpenSK: reuses the existing ROSC + SHA-256 conditioning.
//!
//! OpenSK's `Rng` trait is built on rand_core 0.10, where an infallible generator implements
//! `TryRng<Error = Infallible>` (and the `TryCryptoRng` marker); `Rng` / `CryptoRng` follow from
//! that. The crate is used through OpenSK's re-export so there is a single rand_core 0.10 in the
//! build (the firmware's own `rand_core` 0.6 dependency only serves `rand_chacha` in
//! `src/ram_guard.rs`).

use core::convert::Infallible;

use opensk::api::rng::rand_core::{utils, TryCryptoRng, TryRng};
use opensk::api::rng::Rng;

/// Thin wrapper that satisfies OpenSK's `Rng` trait.
pub struct PicoRng;

impl PicoRng {
    pub fn new() -> Self {
        Self
    }
}

impl TryRng for PicoRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        // Reuse the existing conditioned ROSC RNG from keys.rs.
        crate::keys::fill_random(dest);
        Ok(())
    }
}

impl TryCryptoRng for PicoRng {}

impl Rng for PicoRng {}
