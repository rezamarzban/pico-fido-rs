//! Flash glue for the master-key record and PIN retry counter (logic is in store.rs) and the
//! random generator.
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
use crate::store::{self, Loaded, Record, Replaced, Sectors, Vault, REC_LEN, TRIES_PAGES};
use crate::FLASH_SIZE;

pub type Fl = Flash<'static, FLASH, Blocking, FLASH_SIZE>;

const SECTOR: u32 = 4096;
/// The last three sectors of flash: [retry counter][key slot 0][key slot 1]. build.rs keeps the
/// linker FLASH region 12K shorter than the chip.
fn offset(slot: usize) -> u32 {
    FLASH_SIZE as u32 - 2 * SECTOR + slot as u32 * SECTOR
}
const TRIES_OFFSET: u32 = FLASH_SIZE as u32 - 3 * SECTOR;
/// One flag byte per 256-byte page (a page is programmed at most once between erases).
const PAGE: u32 = 256;

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
    fn tries_read(&mut self, out: &mut [u8; TRIES_PAGES]) -> Result<(), Error> {
        for (i, b) in out.iter_mut().enumerate() {
            self.0
                .blocking_read(TRIES_OFFSET + i as u32 * PAGE, core::slice::from_mut(b))?;
        }
        Ok(())
    }
    fn tries_mark(&mut self, page: usize, val: u8) -> Result<(), Error> {
        self.0
            .blocking_write(TRIES_OFFSET + page as u32 * PAGE, &[val])
    }
    fn tries_clear(&mut self) -> Result<(), Error> {
        self.0.blocking_erase(TRIES_OFFSET, TRIES_OFFSET + SECTOR)
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

/// Loads the stored record. First boot (blank flash) creates a plain random key. A read error or
/// a damaged, non-blank record returns `None`: the device then refuses to work until an explicit
/// reset, instead of silently replacing the key. A record with a PIN comes back still wrapped:
/// the key is only unwrapped by a successful getPinToken.
pub fn load(flash: &mut Fl) -> Option<Record> {
    match store::load(&mut Dev(flash)) {
        Ok(Loaded::Rec(r, p)) => {
            info!(
                "flash: key record seq {}, PIN {}",
                p.seq,
                if r.wrapped { "set" } else { "not set" }
            );
            // An earlier update may have left an older record behind (failed wipe): retry now.
            match store::purge_stale(&mut Dev(flash)) {
                Ok(true) => {}
                Ok(false) => {
                    warn!("flash: an older key record is still readable and could not be wiped")
                }
                Err(_) => warn!("flash: could not check for older key records"),
            }
            Some(r)
        }
        Ok(Loaded::Blank) => {
            let mut k = [0u8; 32];
            fill_random(&mut k);
            let rec = Record::plain(k);
            match log_replace(store::replace_record(&mut Dev(flash), &rec)) {
                Replaced::New(_) => Some(rec),
                Replaced::Kept(r) => Some(r),
                _ => {
                    error!("flash: could not initialise key storage");
                    None
                }
            }
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

fn log_replace(r: Replaced) -> Replaced {
    match &r {
        Replaced::New(saved) => {
            if !saved.old_wiped {
                warn!("flash: old key slot could not be wiped (new record still takes precedence)");
            }
            info!("flash: record committed, seq {}", saved.pos.seq);
        }
        Replaced::Kept(_) => warn!("flash: saving failed, previous record kept"),
        Replaced::NoKey => error!("flash: saving failed and flash holds no valid record"),
        Replaced::Unknown => error!("flash: saving failed and flash state is unreadable"),
    }
    r
}

/// The persistent state used by the CTAP layer. After any failed `replace` the flash is re-read
/// (store.rs), so the returned `Replaced` always matches what the next boot will load.
pub struct FlashVault(pub Fl);

impl Vault for FlashVault {
    fn replace(&mut self, rec: &Record) -> Replaced {
        log_replace(store::replace_record(&mut Dev(&mut self.0), rec))
    }
    fn tries_used(&mut self) -> Result<u8, ()> {
        store::count_tries(&mut Dev(&mut self.0))
            .map_err(|_| error!("flash: retry counter unreadable"))
    }
    fn begin_try(&mut self) -> Result<usize, ()> {
        store::begin_try(&mut Dev(&mut self.0))
            .map_err(|_| error!("flash: retry counter not writable"))
    }
    fn finish_try(&mut self, page: usize) -> Result<(), ()> {
        store::finish_try(&mut Dev(&mut self.0), page)
            .map_err(|_| warn!("flash: could not refund PIN attempt"))
    }
    fn clear_tries(&mut self) -> Result<(), ()> {
        store::reset_tries(&mut Dev(&mut self.0))
            .map_err(|_| warn!("flash: could not clear retry counter"))
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
