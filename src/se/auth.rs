//! Host-side formulas for the ATECC608A "password" authorisation (Nonce + CheckMac), identical to
//! cryptoauthlib `atcah_nonce` / `atcah_check_mac`; checked against the C code in host-test/se.
//!
//! The chip holds a 32-byte PIN key in a secret slot. To use a key slot that has ReqAuth set, the
//! host must first prove it knows that PIN key *in the same wake session*: the chip gives a random
//! nonce, the host answers with SHA-256(PIN key || TempKey || ...), the chip compares.

use sha2::{Digest, Sha256};

/// Chip slot holding the PIN key (see atecc608a/CONFIG.md).
pub const PIN_SLOT: u8 = 11;

pub type Serial = [u8; 9];

/// TempKey after `Nonce` in random mode 0x00: SHA-256(RandOut || NumIn || 0x16 || mode || 0x00).
pub fn nonce_tempkey(rand_out: &[u8; 32], num_in: &[u8; 20]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(rand_out);
    h.update(num_in);
    h.update([0x16, 0x00, 0x00]);
    h.finalize().into()
}

/// CheckMac client response, mode 0x01 (block 2 = TempKey from a random nonce).
pub fn check_mac_response(
    slot_key: &[u8; 32],
    temp_key: &[u8; 32],
    other_data: &[u8; 13],
    sn: &Serial,
) -> [u8; 32] {
    let mut m = [0u8; 88];
    m[..32].copy_from_slice(slot_key);
    m[32..64].copy_from_slice(temp_key);
    m[64..68].copy_from_slice(&other_data[0..4]);
    // 68..76: zeros (no OTP)
    m[76..79].copy_from_slice(&other_data[4..7]);
    m[79] = sn[8];
    m[80..84].copy_from_slice(&other_data[7..11]);
    m[84..86].copy_from_slice(&sn[0..2]);
    m[86..88].copy_from_slice(&other_data[11..13]);
    Sha256::digest(m).into()
}

/// PIN key stored in the chip for a FIDO pinHash (LEFT(SHA-256(PIN), 16)). Bound to this chip's
/// serial number. Provisioning computes the same value (atecc608a/tools/pin_key.py).
pub fn pin_key(sn: &Serial, pin_hash: &[u8; 16]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pico-fido-rs/atecc-pin/v1");
    h.update(sn);
    h.update(pin_hash);
    h.finalize().into()
}
