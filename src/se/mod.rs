//! ATECC608A secure element: key custody, signing, signature budget and entropy.
//!
//! * `proto`  - wire protocol (pure, host-tested)
//! * `chip`   - command layer over an abstract `Bus` (host-tested with a fake chip)
//! * `ecdsa`  - OpenSK `Ecdsa` whose private keys live in chip slots (host-tested)
//! * `crypto` - OpenSK `Crypto` using that ECDSA and the software primitives for the rest
//! * `i2c`    - the RP2040 bus (I2C1, GP14 SDA / GP15 SCL), firmware only
//!
//! Chip configuration and the signature budget: atecc608a/CONFIG.md.

pub mod chip;
pub mod crypto;
pub mod ecdsa;
pub mod i2c;
pub mod proto;
