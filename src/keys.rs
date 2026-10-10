//! The only persistent state: one 32-byte master key in the last flash sector.
use embassy_rp::clocks::RoscRng;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::FLASH_SIZE;

pub type Fl = Flash<'static, FLASH, Blocking, FLASH_SIZE>;

const SECTOR: u32 = 4096;
const OFFSET: u32 = FLASH_SIZE as u32 - SECTOR; // keep memory.x FLASH 4K shorter than the chip
const MAGIC: [u8; 4] = *b"FK01";

/// Random bytes: ROSC output + timer jitter, whitened with SHA-256.
/// ROSC is not a certified TRNG; fine for a hobby key, review before relying on it.
pub fn fill_random(out: &mut [u8]) {
    for chunk in out.chunks_mut(32) {
        let mut raw = [0u8; 64];
        RoscRng.fill_bytes(&mut raw);
        let mut h = Sha256::new();
        h.update(raw);
        h.update(embassy_time::Instant::now().as_ticks().to_le_bytes());
        chunk.copy_from_slice(&h.finalize()[..chunk.len()]);
    }
}

pub fn load_or_create(flash: &mut Fl) -> [u8; 32] {
    let mut buf = [0u8; 36];
    if flash.blocking_read(OFFSET, &mut buf).is_ok() && buf[..4] == MAGIC {
        return buf[4..].try_into().unwrap();
    }
    let mut key = [0u8; 32];
    fill_random(&mut key);
    save(flash, &key);
    key
}

pub fn save(flash: &mut Fl, key: &[u8; 32]) {
    let mut buf = [0u8; 36];
    buf[..4].copy_from_slice(&MAGIC);
    buf[4..].copy_from_slice(key);
    defmt::unwrap!(flash.blocking_erase(OFFSET, OFFSET + SECTOR));
    defmt::unwrap!(flash.blocking_write(OFFSET, &buf));
}
