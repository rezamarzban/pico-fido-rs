//! RNG (ROSC + SHA-256 conditioning), the flash type, and the optional USB serial number.
//! Credential storage is handled by OpenSK's Persist + KeyStore (src/env/).

use core::cell::{Cell, RefCell};
use defmt::warn;
use embassy_rp::clocks::RoscRng;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use rand::RngCore;
use sha2::{Digest, Sha256};
use static_cell::StaticCell;

use crate::health::Health;
use crate::FLASH_SIZE;

pub type Fl = Flash<'static, FLASH, Blocking, FLASH_SIZE>;

static POOL: Mutex<CriticalSectionRawMutex, Cell<[u8; 32]>> = Mutex::new(Cell::new([0; 32]));
static HEALTH: Mutex<CriticalSectionRawMutex, RefCell<Health>> =
    Mutex::new(RefCell::new(Health::new()));

/// Raw ROSC bytes consumed per 32 output bytes.
const RAW_PER_BLOCK: usize = 512;

/// Random bytes: ROSC output + timer jitter + running pool, conditioned with SHA-256.
/// Continuous health tests (health.rs) detect a stuck source. See SECURITY.md.
pub fn fill_random(out: &mut [u8]) {
    for chunk in out.chunks_mut(32) {
        let mut h = Sha256::new();
        h.update(POOL.lock(|p| p.get()));
        for _ in 0..RAW_PER_BLOCK / 64 {
            let mut raw = [0u8; 64];
            RoscRng.fill_bytes(&mut raw);
            if !HEALTH.lock(|h| h.borrow_mut().feed(&raw)) {
                defmt::panic!("RNG health test failed");
            }
            h.update(raw);
            h.update(embassy_time::Instant::now().as_ticks().to_le_bytes());
        }
        let d: [u8; 32] = h.finalize().into();
        POOL.lock(|p| {
            p.set(
                Sha256::new()
                    .chain_update(b"pool")
                    .chain_update(d)
                    .finalize()
                    .into(),
            )
        });
        chunk.copy_from_slice(&d[..chunk.len()]);
    }
}

/// USB serial number from the flash chip's unique ID (16 hex chars).
/// Returns `None` if the ID cannot be read or is a constant (all 0x00 / 0xFF), so that several
/// devices never present the same "unique" serial number.
pub fn serial(flash: &mut Fl) -> Option<&'static str> {
    let mut uid = [0u8; 8];
    if flash.blocking_unique_id(&mut uid).is_err() {
        warn!("flash: unique ID unreadable, USB serial number omitted");
        return None;
    }
    if uid.iter().all(|&b| b == 0) || uid.iter().all(|&b| b == 0xFF) {
        warn!("flash: unique ID is constant, USB serial number omitted");
        return None;
    }
    let mut s = [0u8; 16];
    for (i, b) in uid.iter().enumerate() {
        s[2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
        s[2 * i + 1] = b"0123456789abcdef"[(b & 15) as usize];
    }
    static SERIAL: StaticCell<[u8; 16]> = StaticCell::new();
    Some(core::str::from_utf8(&*SERIAL.init(s)).unwrap())
}
