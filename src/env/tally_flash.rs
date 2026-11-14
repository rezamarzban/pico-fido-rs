//! Lifetime signature counters in the Pico's flash, one per chip (the chips count nothing; each is
//! told apart by its unique serial number). Three 4 KiB sectors below the directory sectors
//! (src/layout.rs; build.rs keeps them out of the linker's FLASH region).
//! The format (an append-only log, one record per signature) is in `se/tallylog.rs`, host-tested,
//! and works on a plaintext 4 KiB page image. **Every record is sealed with AES-256-GCM** under a
//! key derived from the SRAM PUF (`seal.rs`, `sealed_log.rs`): a copy of the flash shows neither
//! the chip serial numbers nor the counts.
//!
//! The decrypted page is kept in RAM (`cache`) so that counting a signature does not have to
//! decrypt the whole log again; it is rebuilt from flash whenever a chip is selected or a write
//! failed. The total and the count since power-up are published to the display through
//! `crate::status`.

use alloc::vec::Vec;
use core::cell::RefCell;
use portable_atomic::Ordering;

use super::flash_io;
use crate::keys::Fl;
use crate::layout::{TALLY_PHYS, TALLY_START};
use crate::puf;
use crate::se::dirlog::{Plan, PAGE};
use crate::se::ecdsa::{ChipSerial, SigTally};
use crate::se::tallylog;
use crate::seal::{Domain, Sealer};
use crate::sealed_log::{self, TALLY};
use crate::status;

const _: () = assert!(TALLY.logical_len == PAGE);
const _: () = assert!(TALLY.rec == tallylog::REC);
const _: () = assert!(TALLY.header_len == tallylog::HEADER.len());
const _: () = assert!(TALLY.max_recs == tallylog::MAX_RECS);
const _: () = assert!(TALLY.phys_len == TALLY_PHYS);

/// The sealed bytes of the counter region.
fn phys() -> &'static [u8] {
    flash_io::xip(TALLY_START, TALLY_PHYS)
}

/// The counter page decrypted into the layout `se/tallylog.rs` reads (also used by the status
/// display). Blank if the key cannot be rebuilt.
pub fn page() -> Vec<u8> {
    match puf::try_sealer(Domain::Tally) {
        Some(s) => sealed_log::open_page(&TALLY, &s, phys()),
        None => alloc::vec![0xFFu8; PAGE],
    }
}

pub struct FlashTally {
    flash: &'static RefCell<Fl>,
    /// The connected chip (`None` until `select`: nothing is counted then) and ITS signature total.
    chip: Option<ChipSerial>,
    total: u32,
    /// The decrypted page as it is in flash.
    cache: Vec<u8>,
}

// SAFETY: single core; only used from OpenSK's thread-mode code (signing), never from the USB executor.
unsafe impl Send for FlashTally {}

impl FlashTally {
    pub fn new(flash: &'static RefCell<Fl>) -> Self {
        FlashTally {
            flash,
            chip: None,
            total: 0,
            cache: Vec::new(),
        }
    }

    /// Programs the operations of `plan` into flash and brings `cache` in line with them.
    fn write(&mut self, sealer: &Sealer, plan: Plan) -> Result<(), ()> {
        let mut flash = self.flash.borrow_mut();
        match plan {
            Plan::Nothing => Ok(()),
            Plan::Append { offset, data } => {
                for w in sealed_log::seal_program(&TALLY, sealer, offset, &data).ok_or(())? {
                    flash_io::program(&mut flash, TALLY_START + w.offset, &w.data)?;
                }
                self.cache[offset..offset + data.len()].copy_from_slice(&data);
                Ok(())
            }
            Plan::Rewrite { data } => {
                flash_io::erase(&mut flash, TALLY_START, TALLY_PHYS)?;
                for w in sealed_log::seal_program(&TALLY, sealer, 0, &data).ok_or(())? {
                    flash_io::program(&mut flash, TALLY_START + w.offset, &w.data)?;
                }
                self.cache.fill(0xFF);
                self.cache[..data.len()].copy_from_slice(&data);
                Ok(())
            }
        }
    }
}

impl SigTally for FlashTally {
    /// Switches to the count of this chip (0 for a chip never seen) and publishes it.
    fn select(&mut self, chip: &ChipSerial) {
        self.chip = Some(*chip);
        self.cache = page();
        self.total = tallylog::scan(&self.cache, chip).0;
        status::SIGS_TOTAL.store(self.total, Ordering::Relaxed);
    }

    fn bump(&mut self) {
        let Some(chip) = self.chip else { return };
        self.total = self.total.saturating_add(1);
        status::SIGS_TOTAL.store(self.total, Ordering::Relaxed);
        status::SIGS_BOOT.fetch_add(1, Ordering::Relaxed);
        // A failed write only means the stored total lags behind; signing goes on. Without the key
        // nothing is written (never plaintext).
        let Some(sealer) = puf::try_sealer(Domain::Tally) else {
            return;
        };
        let plan = tallylog::plan(&self.cache, &chip, self.total);
        if self.write(&sealer, plan).is_err() {
            // Flash and cache may differ now: start over from what is really in flash.
            self.cache = page();
        }
    }
}
