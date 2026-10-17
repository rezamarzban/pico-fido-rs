//! Flash glue for the master-seed record and the PIN retry counter (logic: store.rs).
//!
//! Layout: the last three 4 KiB sectors of flash: [retry counter][slot 0][slot 1]. build.rs keeps
//! them (and the key-value store below them) out of the linker's FLASH region.
use core::cell::RefCell;
use defmt::{error, info, warn};
use embassy_rp::flash::Error;
use zeroize::Zeroizing;

use crate::keys::{fill_random, Fl};
use crate::store::{self, Loaded, Record, Replaced, Sectors, Vault, REC_LEN, TRIES_PAGES};
use crate::{FLASH_SIZE, VAULT_BYTES};

const SECTOR: u32 = 4096;
const _: () = core::assert!(VAULT_BYTES == 3 * SECTOR as usize);

fn offset(slot: usize) -> u32 {
    FLASH_SIZE as u32 - 2 * SECTOR + slot as u32 * SECTOR
}
const TRIES_OFFSET: u32 = FLASH_SIZE as u32 - 3 * SECTOR;
/// One flag byte per 256-byte page (a page is programmed at most once between erases).
const PAGE: u32 = 256;

struct Dev<'a>(&'a RefCell<Fl>);

impl Sectors for Dev<'_> {
    type Error = Error;
    fn read(&mut self, slot: usize, buf: &mut [u8; REC_LEN]) -> Result<(), Error> {
        self.0.borrow_mut().blocking_read(offset(slot), buf)
    }
    fn erase(&mut self, slot: usize) -> Result<(), Error> {
        self.0
            .borrow_mut()
            .blocking_erase(offset(slot), offset(slot) + SECTOR)
    }
    fn write(&mut self, slot: usize, rec: &[u8; REC_LEN]) -> Result<(), Error> {
        self.0.borrow_mut().blocking_write(offset(slot), rec)
    }
    fn tries_read(&mut self, out: &mut [u8; TRIES_PAGES]) -> Result<(), Error> {
        let mut f = self.0.borrow_mut();
        for (i, b) in out.iter_mut().enumerate() {
            f.blocking_read(TRIES_OFFSET + i as u32 * PAGE, core::slice::from_mut(b))?;
        }
        Ok(())
    }
    fn tries_mark(&mut self, page: usize, val: u8) -> Result<(), Error> {
        self.0
            .borrow_mut()
            .blocking_write(TRIES_OFFSET + page as u32 * PAGE, &[val])
    }
    fn tries_clear(&mut self) -> Result<(), Error> {
        self.0
            .borrow_mut()
            .blocking_erase(TRIES_OFFSET, TRIES_OFFSET + SECTOR)
    }
}

fn log_replace(r: Replaced) -> Replaced {
    match &r {
        Replaced::New(saved) => {
            if !saved.old_wiped {
                warn!("vault: old record could not be wiped (new record still takes precedence)");
            }
            info!("vault: record committed, seq {}", saved.pos.seq);
        }
        Replaced::Kept(_) => warn!("vault: saving failed, previous record kept"),
        Replaced::NoKey => error!("vault: saving failed and flash holds no valid record"),
        Replaced::Unknown => error!("vault: saving failed and flash state is unreadable"),
    }
    r
}

pub struct FlashVault(pub &'static RefCell<Fl>);

impl Vault for FlashVault {
    fn replace(&mut self, rec: &Record) -> Replaced {
        log_replace(store::replace_record(&mut Dev(self.0), rec))
    }
    fn purge_stale(&mut self) -> Result<bool, ()> {
        store::purge_stale(&mut Dev(self.0)).map_err(|_| error!("vault: stale-record wipe failed"))
    }
    fn tries_used(&mut self) -> Result<u8, ()> {
        store::count_tries(&mut Dev(self.0)).map_err(|_| error!("vault: retry counter unreadable"))
    }
    fn begin_try(&mut self) -> Result<usize, ()> {
        store::begin_try(&mut Dev(self.0))
            .map_err(|_| error!("vault: retry counter full or not writable"))
    }
    fn finish_try(&mut self, page: usize) -> Result<(), ()> {
        store::finish_try(&mut Dev(self.0), page)
            .map_err(|_| warn!("vault: could not refund PIN attempt"))
    }
    fn clear_tries(&mut self) -> Result<(), ()> {
        store::reset_tries(&mut Dev(self.0))
            .map_err(|_| warn!("vault: could not clear retry counter"))
    }
}

/// Opens the vault. Blank flash (first boot) creates a plain random seed (or, with the SRAM PUF required, is left blank for the caller). A read error or a
/// damaged, non-blank record yields `None`: the device then refuses to use any key until a CTAP
/// reset, instead of silently replacing the seed. With `create_plain == false` a blank vault is
/// left blank and reported (third value) so the caller can create a PUF-bound record.
pub fn open(flash: &'static RefCell<Fl>, create_plain: bool) -> (FlashVault, Option<Record>, bool) {
    let mut v = FlashVault(flash);
    let mut blank = false;
    let rec = match store::load(&mut Dev(flash)) {
        Ok(Loaded::Rec(r, p)) => {
            info!(
                "vault: record seq {}, PIN {}",
                p.seq,
                if r.wrapped { "set" } else { "not set" }
            );
            let wiped = match store::purge_stale(&mut Dev(flash)) {
                Ok(true) => true,
                Ok(false) => {
                    warn!("vault: an older record is still readable and could not be wiped");
                    false
                }
                Err(_) => {
                    warn!("vault: could not check for older records");
                    false
                }
            };
            if !wiped && !create_plain {
                // SRAM PUF required: an older record may be unmasked or lack the PUF input. Do not
                // use the vault until it is wiped (every boot retries); a CTAP reset also recovers.
                error!("vault: older record not wiped with the PUF required - locked");
                None
            } else {
                Some(r)
            }
        }
        Ok(Loaded::Blank) if !create_plain => {
            // First boot with the SRAM PUF required: the caller creates a PUF-bound record. A
            // plain seed must never reach flash, not even for a moment.
            blank = true;
            None
        }
        Ok(Loaded::Blank) => {
            let mut k = Zeroizing::new([0u8; 32]);
            fill_random(&mut k[..]);
            let rec = Record::plain(*k);
            match v.replace(&rec) {
                Replaced::New(_) => Some(rec),
                Replaced::Kept(r) => Some(r),
                _ => {
                    error!("vault: could not initialise");
                    None
                }
            }
        }
        Ok(Loaded::Corrupt) => {
            error!("vault: record damaged - refusing to re-key; do a CTAP reset to start over");
            None
        }
        Err(_) => {
            error!("vault: read error");
            None
        }
    };
    (v, rec, blank)
}
