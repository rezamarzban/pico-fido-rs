//! Flash glue for the master key (record logic is in store.rs) and the random generator.
use core::cell::Cell;
use defmt::{error, warn};
use embassy_rp::clocks::RoscRng;
use embassy_rp::flash::{Blocking, Error, Flash};
use embassy_rp::peripherals::FLASH;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use rand::RngCore;
use sha2::{Digest, Sha256};
use static_cell::StaticCell;

use crate::store::{self, Loaded, Pos, Sectors, REC_LEN};
use crate::FLASH_SIZE;

pub type Fl = Flash<'static, FLASH, Blocking, FLASH_SIZE>;

const SECTOR: u32 = 4096;
/// Two sectors at the very end of flash; keep memory.x FLASH 8K shorter than the chip.
fn offset(slot: usize) -> u32 {
    FLASH_SIZE as u32 - 2 * SECTOR + slot as u32 * SECTOR
}

struct Dev<'a>(&'a mut Fl);

impl Sectors for Dev<'_> {
    type Error = Error;
    fn read(&mut self, slot: usize, buf: &mut [u8; REC_LEN]) -> Result<(), Error> {
        self.0.blocking_read(offset(slot), buf)
    }
    fn erase(&mut self, slot: usize) -> Result<(), Error> {
        self.0.blocking_erase(offset(slot), offset(slot) + SECTOR)
    }
    fn write(&mut self, slot: usize, rec: &[u8; REC_LEN]) -> Result<(), Error> {
        self.0.blocking_write(offset(slot), rec)
    }
}

static POOL: Mutex<CriticalSectionRawMutex, Cell<[u8; 32]>> = Mutex::new(Cell::new([0; 32]));
/// Raw ROSC bytes consumed per 32 output bytes.
const RAW_PER_BLOCK: usize = 512;

/// Random bytes: lots of ROSC output + timer jitter + a running pool, conditioned with SHA-256.
/// Hashing cannot add entropy: security still rests on the ROSC being unpredictable. A stuck
/// source is detected and stops the firmware. The RP2040 has no certified TRNG; read SECURITY.md.
pub fn fill_random(out: &mut [u8]) {
    for chunk in out.chunks_mut(32) {
        let mut h = Sha256::new();
        h.update(POOL.lock(|p| p.get()));
        for _ in 0..RAW_PER_BLOCK / 64 {
            let mut raw = [0u8; 64];
            RoscRng.fill_bytes(&mut raw);
            if raw.iter().all(|&b| b == raw[0]) {
                defmt::panic!("RNG source stuck");
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

/// Loads the master key. First boot (blank flash) creates one. A read error or a damaged,
/// non-blank record returns `None`: the device then refuses to work until an explicit reset,
/// instead of silently replacing the key.
pub fn load(flash: &mut Fl) -> (Option<[u8; 32]>, Option<Pos>) {
    match store::load(&mut Dev(flash)) {
        Ok(Loaded::Key(k, p)) => (Some(k), Some(p)),
        Ok(Loaded::Blank) => {
            let mut k = [0u8; 32];
            fill_random(&mut k);
            match store::save(&mut Dev(flash), &k, None) {
                Ok(p) => (Some(k), Some(p)),
                Err(_) => {
                    error!("flash: could not initialise key storage");
                    (None, None)
                }
            }
        }
        Ok(Loaded::Corrupt) => {
            error!("flash: key record damaged - refusing to re-key, hold BOOTSEL on a CTAP reset to start over");
            (None, None)
        }
        Err(_) => {
            error!("flash: read error");
            (None, None)
        }
    }
}

/// Persist a replacement key. On error the previous record is still intact.
pub fn replace(flash: &mut Fl, key: &[u8; 32], pos: Option<Pos>) -> Result<Pos, ()> {
    store::save(&mut Dev(flash), key, pos).map_err(|_| warn!("flash: saving key failed"))
}

/// USB serial number from the flash chip's unique ID (16 hex chars).
pub fn serial(flash: &mut Fl) -> &'static str {
    let mut uid = [0u8; 8];
    let _ = flash.blocking_unique_id(&mut uid);
    let mut s = [0u8; 16];
    for (i, b) in uid.iter().enumerate() {
        s[2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
        s[2 * i + 1] = b"0123456789abcdef"[(b & 15) as usize];
    }
    static SERIAL: StaticCell<[u8; 16]> = StaticCell::new();
    core::str::from_utf8(&*SERIAL.init(s)).unwrap()
}
