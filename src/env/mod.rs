//! OpenSK environment for the Raspberry Pi Pico (RP2040 + Embassy).
//!
//! Implements `opensk::env::Env` and its component traits so that the OpenSK CTAP core can run on
//! this board. Everything blocking (user presence, flash, packet I/O) lives here; the USB stack
//! runs on a separate, higher-priority executor and talks to OpenSK through `hid`.

mod clock;
mod dir_flash;
mod flash_store;
pub mod hid;
mod persist;
mod rng;
mod user_presence;

use clock::PicoClock;
pub use dir_flash::FlashDir;
use hid::PicoHidConnection;
pub use persist::PicoPersist;
use rng::PicoRng;
pub use user_presence::PicoUserPresence;

use core::fmt;
use opensk::api::customization::{CustomizationImpl, DEFAULT_CUSTOMIZATION};
use opensk::api::key_store;
use opensk::env::Env;

/// OpenSK defaults. `use_batch_attestation` stays false (packed self-attestation, signed with the
/// credential key): U2F registration always uses the attestation key in the chip, but turning
/// batch attestation on would also make every FIDO2 registration carry that per-device
/// certificate, which every site can then use to recognise the device. Set it to true only if
/// that is wanted (and the attestation material is provisioned, see atecc608a/CONFIG.md).
pub const CUSTOMIZATION: CustomizationImpl = DEFAULT_CUSTOMIZATION;

/// One step of a polling wait on the main thread: give the status display a turn, then wait.
pub fn poll_wait(d: embassy_time::Duration) {
    #[cfg(feature = "oled")]
    crate::oled::poll();
    embassy_time::block_for(d);
}

/// Top-level environment that ties all OpenSK platform pieces together.
pub struct PicoEnv {
    rng: PicoRng,
    user_presence: PicoUserPresence,
    persist: PicoPersist,
    clock: PicoClock,
    hid: PicoHidConnection,
}

impl PicoEnv {
    pub fn new(persist: PicoPersist, user_presence: PicoUserPresence) -> Self {
        Self {
            rng: PicoRng::new(),
            user_presence,
            persist,
            clock: PicoClock::new(),
            hid: PicoHidConnection,
        }
    }
}

/// Debug sink that forwards to defmt (only used with OpenSK's `debug_ctap` feature).
pub struct DefmtWrite;

impl fmt::Write for DefmtWrite {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        defmt::info!("{}", s);
        Ok(())
    }
}

impl Env for PicoEnv {
    type Rng = PicoRng;
    type UserPresence = PicoUserPresence;
    type Persist = PicoPersist;
    type KeyStore = Self;
    type Write = DefmtWrite;
    type Customization = CustomizationImpl;
    type HidConnection = PicoHidConnection;
    type Clock = PicoClock;
    // ECDSA (credential and attestation keys) runs inside the ATECC608A, the rest in software.
    type Crypto = crate::se::crypto::PicoCrypto;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }

    fn user_presence(&mut self) -> &mut Self::UserPresence {
        &mut self.user_presence
    }

    fn persist(&mut self) -> &mut Self::Persist {
        &mut self.persist
    }

    fn key_store(&mut self) -> &mut Self::KeyStore {
        self
    }

    fn clock(&mut self) -> &mut Self::Clock {
        &mut self.clock
    }

    fn write(&mut self) -> Self::Write {
        DefmtWrite
    }

    fn customization(&self) -> &Self::Customization {
        &CUSTOMIZATION
    }

    fn hid_connection(&mut self) -> &mut Self::HidConnection {
        &mut self.hid
    }

    fn boots_after_soft_reset(&self) -> bool {
        // Same as OpenSK's Wasefire environment: no way to tell a soft reset from a cold boot.
        false
    }
}

// OpenSK's blanket `KeyStore` implementation: the master keys live in the key-value store and
// encrypt the credential IDs (which carry the chip-slot handles).
impl key_store::Helper for PicoEnv {}
