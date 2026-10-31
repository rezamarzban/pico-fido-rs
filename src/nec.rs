//! NEC infrared helpers (pure logic, no hardware: unit-tested on the host).
//!
//! A NEC frame is: leader mark (~9 ms low), leader space (~4.5 ms high; a repeat frame has ~2.25 ms),
//! 32 bits (each a ~560 us mark followed by a ~560 us space = 0 or a ~1690 us space = 1) and a stop
//! mark. The 32 bits are read MSB first exactly as in the MicroPython reference, e.g. `0x00FF45BA` =
//! address 0x00, inverted address 0xFF, command 0x45, inverted command 0xBA.
//!
//! Entropy: of those 32 bits only the command byte (and the address, which is constant for one
//! remote) carries information, so one key press is about log2(number of keys) bits, roughly 4.4
//! bits on a 21-key remote, not 32.
//!
//! The IR PIN is separate from the PIN typed in the host dialog: the digest below is one of the inputs of
//! the Argon2id key derivation (src/wrap.rs), together with the host PIN hash and the SRAM-PUF secret.
use sha2::{Digest, Sha256};

/// Keys needed for a PIN (about 35 bits on a 21-key remote) and the most that are kept.
pub const MIN_PRESSES: usize = 8;
pub const MAX_PRESSES: usize = 32;

pub fn leader_mark_ok(us: u32) -> bool {
    (7_000..11_000).contains(&us)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Space {
    /// ~4.5 ms: a frame follows.
    Frame,
    /// ~2.25 ms: the key is held, ignored.
    Repeat,
    Bad,
}

pub fn classify_space(us: u32) -> Space {
    if (3_500..5_500).contains(&us) {
        Space::Frame
    } else if (2_000..3_000).contains(&us) {
        Space::Repeat
    } else {
        Space::Bad
    }
}

/// A space of ~560 us is a 0, one of ~1690 us a 1 (the threshold is between them).
pub fn bit(space_us: u32) -> bool {
    space_us > 1_100
}

/// The check bytes of the frame: address == !inverted address, command == !inverted command.
pub fn valid(bits: u32) -> bool {
    let addr = (bits >> 24) as u8;
    let inv_addr = (bits >> 16) as u8;
    let cmd = (bits >> 8) as u8;
    let inv_cmd = bits as u8;
    addr == !inv_addr && cmd == !inv_cmd
}

/// Digest of a key sequence (order matters, every full 32-bit code is used). The IR PIN input of
/// the key derivation.
pub fn digest(codes: &[u32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pico-fido-ir-pin-v2");
    h.update([codes.len() as u8]);
    for c in codes {
        h.update(c.to_be_bytes());
    }
    h.finalize().into()
}
