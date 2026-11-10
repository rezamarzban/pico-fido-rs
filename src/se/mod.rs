//! ATECC608A secure element. It does exactly this and nothing else:
//!
//! * GenKey (new private key in a slot) and public-key extraction
//! * ECDSA P-256 signing (Nonce pass-through + Sign)
//! * Random (seed of the RNG, `env/rng.rs`)
//! * No counters at all: signatures are not counted and key slots are filled in order, never overwritten
//! * Info + config-zone reads (serial number, revision, lock state: shown on the OLED)
//!
//! Modules:
//! * `proto`  - wire protocol (pure, host-tested)
//! * `chip`   - command layer over an abstract `Bus` (host-tested with a fake chip)
//! * `ecdsa`  - OpenSK `Ecdsa` whose private keys live in chip slots (host-tested)
//! * `crypto` - OpenSK `Crypto` using that ECDSA and the software primitives for the rest
//! * `i2c`    - the RP2040 bus (I2C1, GP14 SDA / GP15 SCL), firmware only
//!
//! Chip configuration: atecc608a/CONFIG.md.

pub mod chip;
pub mod crypto;
pub mod ecdsa;
pub mod i2c;
pub mod proto;
