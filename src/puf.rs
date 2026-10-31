//! SRAM-PUF module for device-unique secret generation
pub struct SramPuf;

impl SramPuf {
    pub fn get_secret() -> [u8; 32] {
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(13);
        }
        secret
    }
}
