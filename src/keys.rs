//! Flash glue for the master key (record logic is in store.rs) and the random generator.
use core::cell::{Cell, RefCell};
use defmt::{error, info, warn};
use embassy_rp::clocks::RoscRng;
use embassy_rp::flash::{Blocking, Error, Flash};
use embassy_rp::peripherals::FLASH;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use rand::RngCore;
use sha2::{Digest, Sha256};
use static_cell::StaticCell;

use crate::health::Health;
use crate::store::{self, Loaded, Replaced, Sectors, REC_LEN};
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
static HEALTH: Mutex<CriticalSectionRawMutex, RefCell<Health>> =
    Mutex::new(RefCell::new(Health::new()));
/// Raw ROSC bytes consumed per 32 output bytes.
const RAW_PER_BLOCK: usize = 512;

/// Random bytes: lots of ROSC output + timer jitter + a running pool, conditioned with SHA-256.
/// Hashing cannot add entropy: security still rests on the ROSC being unpredictable. Continuous
/// health tests (health.rs) detect a stuck or badly degraded source and stop the firmware. The RP2040 has no certified TRNG; read SECURITY.md.
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

/// Result of a key replacement: what the CTAP layer must answer and which key it must now use.
pub struct Outcome {
    /// The new key is durable (the next boot will load it).
    pub ok: bool,
    /// The key the running firmware must use from now on. It always matches what the next boot
    /// loads, or is `None` (refuse to operate) when that cannot be determined.
    pub active: Option<[u8; 32]>,
}

/// Loads the master key. First boot (blank flash) creates one. A read error or a damaged,
/// non-blank record returns `None`: the device then refuses to work until an explicit reset,
/// instead of silently replacing the key.
pub fn load(flash: &mut Fl) -> Option<[u8; 32]> {
    match store::load(&mut Dev(flash)) {
        Ok(Loaded::Key(k, _)) => Some(k),
        Ok(Loaded::Blank) => {
            let mut k = [0u8; 32];
            fill_random(&mut k);
            let o = replace(flash, &k);
            if !o.ok {
                error!("flash: could not initialise key storage");
            }
            o.active
        }
        Ok(Loaded::Corrupt) => {
            error!("flash: key record damaged - refusing to re-key, do a CTAP reset (touch, within 10 s of plug-in) to start over");
            None
        }
        Err(_) => {
            error!("flash: read error");
            None
        }
    }
}

/// Persist a replacement key. The flash is always re-read after a failure, so the returned
/// `active` key is exactly what the next boot will load (or `None` if that is unknowable).
pub fn replace(flash: &mut Fl, key: &[u8; 32]) -> Outcome {
    match store::replace(&mut Dev(flash), key) {
        Replaced::New(saved) => {
            if !saved.old_wiped {
                warn!("flash: old key slot could not be wiped (new key still takes precedence)");
            }
            info!("flash: new key committed, seq {}", saved.pos.seq);
            Outcome {
                ok: true,
                active: Some(*key),
            }
        }
        Replaced::Kept(k) => {
            warn!("flash: saving key failed, previous key kept");
            Outcome {
                ok: false,
                active: Some(k),
            }
        }
        Replaced::NoKey => {
            error!("flash: saving key failed and flash holds no valid key");
            Outcome {
                ok: false,
                active: None,
            }
        }
        Replaced::Unknown => {
            error!("flash: saving key failed and flash state is unreadable");
            Outcome {
                ok: false,
                active: None,
            }
        }
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
