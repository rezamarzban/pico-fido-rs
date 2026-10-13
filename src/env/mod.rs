//! OpenSK environment for the Raspberry Pi Pico (RP2040 + Embassy).
//!
//! Implements `opensk::env::Env` and its component traits so that the OpenSK CTAP core can run on
//! this board. Everything blocking (user presence, flash, packet I/O) lives here; the USB stack
//! runs on a separate, higher-priority executor and talks to OpenSK through `hid`.

mod clock;
mod flash_store;
mod harden;
pub mod hid;
mod persist;
mod rng;
mod user_presence;

use clock::PicoClock;
use hid::PicoHidConnection;
pub use harden::{HardenPersist, LOCK_REQUEST};
pub use persist::PicoPersist;
use rng::PicoRng;
pub use user_presence::PicoUserPresence;

use core::fmt;
use opensk::api::crypto::software_crypto::SoftwareCrypto;
use opensk::api::customization::{CustomizationImpl, DEFAULT_CUSTOMIZATION};
use opensk::api::key_store;
use opensk::env::Env;

/// OpenSK defaults, except:
/// * PINs must have at least 10 code points. The master key is wrapped with Argon2id under the
///   PIN, but the RP2040 cannot make offline guessing expensive enough for short PINs: a long
///   passphrase is the real protection of a stolen device.
/// * `use_batch_attestation` stays false (packed self-attestation): switching it on without a
///   provisioned attestation key would make every makeCredential fail. U2F registration needs the
///   key anyway (provision it with OpenSK's tools/configure.py).
pub const CUSTOMIZATION: CustomizationImpl = CustomizationImpl {
    default_min_pin_length: 10,
    ..DEFAULT_CUSTOMIZATION
};

/// Top-level environment that ties all OpenSK platform pieces together.
pub struct PicoEnv {
    rng: PicoRng,
    user_presence: PicoUserPresence,
    persist: HardenPersist,
    clock: PicoClock,
    hid: PicoHidConnection,
}

impl PicoEnv {
    pub fn new(persist: HardenPersist, user_presence: PicoUserPresence) -> Self {
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
    type Persist = HardenPersist;
    type KeyStore = Self;
    type Write = DefmtWrite;
    type Customization = CustomizationImpl;
    type HidConnection = PicoHidConnection;
    type Clock = PicoClock;
    type Crypto = SoftwareCrypto;

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

// OpenSK's blanket `KeyStore` implementation. Its master keys come from `HardenPersist::
// key_store_bytes` (RAM, unlocked by the PIN), so credential IDs are encrypted with them.
impl key_store::Helper for PicoEnv {}
