//! The site directories (which relying party owns which ATECC608A key slot) in the Pico's flash,
//! one per chip: each chip is identified by its unique serial number, so the key can be used with
//! several chips and always works with the directory of the chip that is connected.
//!
//! It used to live in data slot 13 of the chip; now NOTHING but keys is stored in the chip. The
//! directory has its own two 4 KiB flash sectors (A directly below the OpenSK key-value store, B
//! below the signature-counter page; build.rs keeps them out of the linker's FLASH region, like the
//! store). They are separate from the store on purpose: OpenSK's own reset and the store's "format"
//! never touch them. The format (an append-only record log, no erase to add a site, copy-on-write
//! between the two sectors to compact it, so a power failure never loses the directory) is in
//! `se/dirlog.rs`, which is host-tested. If the flash is erased from outside the directory is gone
//! and `se::ecdsa` takes over slots that hold a key but belong to nobody (see SECURITY.md).

use core::cell::RefCell;

use super::flash_store::{PAGE_SIZE, STORE_START, XIP_BASE};
use crate::keys::Fl;
use crate::se::dirlog::{self, DirPlan, Step};
use crate::se::ecdsa::{ChipSerial, DirStore, DIR_LEN};

const _: () = assert!(PAGE_SIZE == dirlog::PAGE);

/// Directory sector A: the 4 KiB right below the key-value store.
pub const DIR_START: usize = STORE_START - PAGE_SIZE;
/// Directory sector B: below the signature-counter page (which keeps the place it always had, right
/// below sector A, so a build that already had the counter there keeps its count).
pub const DIR_B_START: usize = DIR_START - 2 * PAGE_SIZE;

fn sector_start(sector: usize) -> usize {
    if sector == 0 {
        DIR_START
    } else {
        DIR_B_START
    }
}

fn sector_slice(start: usize) -> &'static [u8] {
    // SAFETY: `start..start+PAGE_SIZE` lies inside the memory-mapped flash, outside the firmware
    // image (build.rs) and outside the store; it is only written by `FlashDir::save`, never while
    // it is being read.
    unsafe { core::slice::from_raw_parts((XIP_BASE + start) as *const u8, PAGE_SIZE) }
}

/// Both directory sectors, read straight through the XIP window (also used by the status display).
pub fn pages() -> [&'static [u8]; 2] {
    [sector_slice(DIR_START), sector_slice(DIR_B_START)]
}

pub struct FlashDir {
    flash: &'static RefCell<Fl>,
    /// The connected chip (`None` until `select`): without it the directory reads as empty and
    /// nothing is saved.
    chip: Option<ChipSerial>,
}

// SAFETY: there is a single core. The directory is only used from OpenSK's thread-mode code (key
// creation); the USB / interrupt executor never touches it. The `RefCell` is shared with the
// key-value store, whose operations never overlap with a key creation.
unsafe impl Send for FlashDir {}

impl FlashDir {
    pub fn new(flash: &'static RefCell<Fl>) -> Self {
        FlashDir { flash, chip: None }
    }
}

impl DirStore for FlashDir {
    fn select(&mut self, chip: &ChipSerial) {
        self.chip = Some(*chip);
    }

    fn load(&mut self) -> [u8; DIR_LEN] {
        match &self.chip {
            Some(chip) => dirlog::scan(pages(), chip).0,
            None => [0u8; DIR_LEN],
        }
    }

    fn save(&mut self, dir: &[u8; DIR_LEN]) -> Result<(), ()> {
        let chip = self.chip.ok_or(())?;
        let plan = dirlog::plan(pages(), &chip, dir);
        if plan == DirPlan::Full {
            return Err(());
        }
        let mut flash = self.flash.borrow_mut();
        // Copy-on-write (see se/dirlog.rs): a rewrite only ever touches the inactive sector and ends
        // with the header, which is the commit. Every program step is read back before the next one
        // runs, so a header is never written after a records write that did not take.
        for step in plan.steps() {
            match step {
                Step::Erase { sector } => {
                    let start = sector_start(sector);
                    flash
                        .blocking_erase(start as u32, (start + PAGE_SIZE) as u32)
                        .map_err(|_| ())?;
                }
                Step::Program {
                    sector,
                    offset,
                    data,
                } => {
                    flash
                        .blocking_write((sector_start(sector) + offset) as u32, &data)
                        .map_err(|_| ())?;
                    if pages()[sector][offset..offset + data.len()] != data[..] {
                        return Err(());
                    }
                }
            }
        }
        Ok(())
    }
}
