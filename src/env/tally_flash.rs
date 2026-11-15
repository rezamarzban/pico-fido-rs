//! Lifetime signature counters in the Pico's flash, one per chip (the chips count nothing; each is
//! told apart by its unique serial number). Two regions of three 4 KiB sectors each (A below the
//! PUF helper sector, B below the PUF-secret backup; src/layout.rs, build.rs keeps them out of the
//! linker's FLASH region).
//! The format (an append-only record log, copy-on-write between the two regions to compact it, so a
//! power failure never loses the counters) is in `se/tallylog.rs`, host-tested, and works on
//! plaintext 4 KiB page images. **Every record is sealed with AES-256-GCM** under a key derived from
//! the SRAM PUF (`seal.rs`, `sealed_log.rs`): a copy of the flash shows neither the chip serial
//! numbers nor the counts.
//!
//! The decrypted pages are kept in RAM (`cache`) so that counting a signature does not have to
//! decrypt the whole log again; they are rebuilt from flash whenever a chip is selected or a write
//! failed. Two numbers are kept apart: `total` is every signature counted for the chip, `stored` is
//! what flash is known to hold. Only `stored` is published to the display through `crate::status`,
//! so the display never claims more than what survives a power cut. After a failed write `total`
//! keeps counting and the next successful write brings flash up to date.

use alloc::vec::Vec;
use core::cell::RefCell;
use portable_atomic::Ordering;

use super::flash_io;
use crate::keys::Fl;
use crate::layout::{TALLY_A_START, TALLY_B_START, TALLY_PHYS};
use crate::puf;
use crate::se::dirlog::{Sectors, Step, PAGE};
use crate::se::ecdsa::{ChipSerial, SigTally};
use crate::se::tallylog::{self, TallyPlan};
use crate::seal::{Domain, Sealer};
use crate::sealed_log::{self, TALLY};
use crate::status;

const _: () = assert!(TALLY.logical_len == PAGE);
const _: () = assert!(TALLY.rec == tallylog::REC);
const _: () = assert!(TALLY.header_len == tallylog::HEADER_LEN);
const _: () = assert!(TALLY.max_recs == tallylog::MAX_RECS);
const _: () = assert!(TALLY.phys_len == TALLY_PHYS);

fn sector_start(sector: usize) -> usize {
    if sector == 0 {
        TALLY_A_START
    } else {
        TALLY_B_START
    }
}

/// The sealed bytes of one counter region.
fn phys(sector: usize) -> &'static [u8] {
    flash_io::xip(sector_start(sector), TALLY_PHYS)
}

/// Both counter regions decrypted into the page layout `se/tallylog.rs` reads; `None` if the key
/// cannot be rebuilt.
fn try_pages() -> Option<[Vec<u8>; 2]> {
    let s = puf::try_sealer(Domain::Tally)?;
    Some([
        sealed_log::open_page(&TALLY, &s, phys(0)),
        sealed_log::open_page(&TALLY, &s, phys(1)),
    ])
}

/// Both counter regions decrypted (also used by the status display). Blank if the key cannot be
/// rebuilt.
pub fn pages() -> [Vec<u8>; 2] {
    try_pages().unwrap_or_else(|| [alloc::vec![0xFFu8; PAGE], alloc::vec![0xFFu8; PAGE]])
}

/// The two pages as the slices `tallylog` works on.
pub fn sectors(p: &[Vec<u8>; 2]) -> Sectors<'_> {
    [&p[0][..], &p[1][..]]
}

pub struct FlashTally {
    flash: &'static RefCell<Fl>,
    /// The connected chip (`None` until `select`: nothing is counted then).
    chip: Option<ChipSerial>,
    /// Every signature counted for this chip (may be ahead of flash after a failed write).
    total: u32,
    /// The total that flash is known to hold for this chip (what the display shows).
    stored: u32,
    /// The decrypted regions as they are in flash; `None` while the key was not available to read them
    /// (nothing is written then: a blank view would make a compaction forget the other chips).
    cache: Option<[Vec<u8>; 2]>,
}

// SAFETY: single core; only used from OpenSK's thread-mode code (signing), never from the USB executor.
unsafe impl Send for FlashTally {}

impl FlashTally {
    pub fn new(flash: &'static RefCell<Fl>) -> Self {
        FlashTally {
            flash,
            chip: None,
            total: 0,
            stored: 0,
            cache: None,
        }
    }

    fn publish(&self) {
        status::SIGS_TOTAL.store(self.stored, Ordering::Relaxed);
    }

    /// Rebuilds `cache` from what is really in flash and takes `stored` from it.
    fn reload(&mut self) {
        self.cache = try_pages();
        if let (Some(c), Some(chip)) = (&self.cache, &self.chip) {
            self.stored = tallylog::scan(sectors(c), chip).0;
        }
        self.publish();
    }

    /// Runs the flash operations of `plan` in order and keeps `cache` in line with them. Every
    /// program step is read back before the next one runs, so a header (the commit of a compaction)
    /// is never written after a records write that did not take.
    fn write(&mut self, sealer: &Sealer, plan: &TallyPlan) -> Result<(), ()> {
        let flash_cell = self.flash;
        let mut flash = flash_cell.borrow_mut();
        let cache = self.cache.as_mut().ok_or(())?;
        for step in plan.steps() {
            match step {
                Step::Erase { sector } => {
                    flash_io::erase(&mut flash, sector_start(sector), TALLY_PHYS)?;
                    cache[sector].fill(0xFF);
                }
                Step::Program {
                    sector,
                    offset,
                    data,
                } => {
                    let writes = sealed_log::seal_program(&TALLY, sealer, offset, &data).ok_or(())?;
                    for w in writes {
                        flash_io::program(&mut flash, sector_start(sector) + w.offset, &w.data)?;
                        if phys(sector)[w.offset..w.offset + w.data.len()] != w.data[..] {
                            return Err(());
                        }
                    }
                    cache[sector][offset..offset + data.len()].copy_from_slice(&data);
                }
            }
        }
        Ok(())
    }
}

impl SigTally for FlashTally {
    /// Switches to the count of this chip (0 for a chip never seen) and publishes it.
    fn select(&mut self, chip: &ChipSerial) {
        self.chip = Some(*chip);
        self.stored = 0;
        self.reload();
        self.total = self.stored;
    }

    fn bump(&mut self) {
        let Some(chip) = self.chip else { return };
        self.total = self.total.saturating_add(1);
        status::SIGS_BOOT.fetch_add(1, Ordering::Relaxed);
        // A failed write only means the stored total lags behind (the display shows `stored`, so it
        // says so); signing goes on. Without the key nothing is written (never plaintext).
        let Some(sealer) = puf::try_sealer(Domain::Tally) else {
            return;
        };
        if self.cache.is_none() {
            self.reload();
        }
        let plan = match self.cache.as_ref() {
            Some(c) => tallylog::plan(sectors(c), &chip, self.total),
            None => return,
        };
        match self.write(&sealer, &plan) {
            Ok(()) => {
                self.stored = self.total;
                self.publish();
            }
            // Flash and cache may differ now: start over from what is really in flash.
            Err(()) => self.reload(),
        }
    }
}
