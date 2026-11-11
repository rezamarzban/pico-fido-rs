//! Lifetime signature counters in the Pico's flash, one per chip (the chips count nothing; each is told apart by its unique serial number). One more 4 KiB page,
//! directly below the site directory page (build.rs keeps it out of the linker's FLASH region).
//! The format (an append-only log, one record per signature) is in `se/tallylog.rs`, host-tested.
//! The total and the count since power-up are published to the display through `crate::status`.

use core::cell::RefCell;
use portable_atomic::Ordering;

use super::dir_flash::DIR_START;
use super::flash_store::{PAGE_SIZE, XIP_BASE};
use crate::keys::Fl;
use crate::se::dirlog::{Plan, PAGE};
use crate::se::ecdsa::{ChipSerial, SigTally};
use crate::se::tallylog;
use crate::status;

const _: () = assert!(PAGE_SIZE == PAGE);

/// The counter page: the 4 KiB right below the directory page.
pub const TALLY_START: usize = DIR_START - PAGE_SIZE;

pub struct FlashTally {
    flash: &'static RefCell<Fl>,
    /// The connected chip (`None` until `select`: nothing is counted then) and ITS signature total.
    chip: Option<ChipSerial>,
    total: u32,
}

// SAFETY: single core; only used from OpenSK's thread-mode code (signing), never from the USB executor.
unsafe impl Send for FlashTally {}

pub fn page() -> &'static [u8] {
    // SAFETY: TALLY_START..+PAGE_SIZE lies inside the memory-mapped flash, outside the firmware
    // image (build.rs) and the other flash areas; nothing writes it concurrently.
    unsafe { core::slice::from_raw_parts((XIP_BASE + TALLY_START) as *const u8, PAGE_SIZE) }
}

impl FlashTally {
    pub fn new(flash: &'static RefCell<Fl>) -> Self {
        FlashTally { flash, chip: None, total: 0 }
    }
}

impl SigTally for FlashTally {
    /// Switches to the count of this chip (0 for a chip never seen) and publishes it.
    fn select(&mut self, chip: &ChipSerial) {
        self.chip = Some(*chip);
        self.total = tallylog::scan(page(), chip).0;
        status::SIGS_TOTAL.store(self.total, Ordering::Relaxed);
    }

    fn bump(&mut self) {
        let Some(chip) = self.chip else { return };
        self.total = self.total.saturating_add(1);
        status::SIGS_TOTAL.store(self.total, Ordering::Relaxed);
        status::SIGS_BOOT.fetch_add(1, Ordering::Relaxed);
        let mut flash = self.flash.borrow_mut();
        // A failed write only means the stored total lags behind; signing goes on.
        let _ = match tallylog::plan(page(), &chip, self.total) {
            Plan::Nothing | Plan::Full => Ok(()),
            Plan::Append { offset, data } => flash.blocking_write((TALLY_START + offset) as u32, &data),
            Plan::Rewrite { data } => flash
                .blocking_erase(TALLY_START as u32, (TALLY_START + PAGE_SIZE) as u32)
                .and_then(|_| flash.blocking_write(TALLY_START as u32, &data)),
        };
    }
}
