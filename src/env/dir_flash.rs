//! The site directories (which relying party owns which ATECC608A key slot) in the Pico's flash,
//! one per chip: each chip is identified by its unique serial number, so the key can be used with
//! several chips and always works with the directory of the chip that is connected.
//!
//! It used to live in data slot 13 of the chip; now NOTHING but keys is stored in the chip. The
//! directory has its own two 8 KiB flash sectors (A directly below the OpenSK key-value store, B
//! below it; src/layout.rs, build.rs keeps them out of the linker's FLASH region, like the store).
//! They are separate from the store on purpose: OpenSK's own reset and the store's "format" never
//! touch them. The format (an append-only record log, no erase to add a site, copy-on-write between
//! the two sectors to compact it, so a power failure never loses the directory) is in
//! `se/dirlog.rs`, which is host-tested and works on a plaintext page image.
//!
//! **Every record is sealed with AES-256-GCM** under a key derived from the SRAM PUF (`seal.rs`,
//! `sealed_log.rs`): a copy of the flash shows neither the chip serial numbers nor the site hashes.
//! The 16-byte sector header (magic, generation) is not secret. `pages()` returns the decrypted page
//! images; the planner's flash operations are translated to sealed ones one record at a time.
//! If the flash is erased from outside the directory is gone and `se::ecdsa` takes over slots that
//! hold a key but belong to nobody (see SECURITY.md).

use alloc::vec::Vec;
use core::cell::RefCell;

use super::flash_io;
use crate::keys::Fl;
use crate::layout::{DIR_A_START, DIR_B_START, DIR_PHYS};
use crate::puf;
use crate::se::dirlog::{self, DirPlan, Step};
use crate::se::ecdsa::{ChipSerial, DirStore, DIR_LEN};
use crate::seal::Domain;
use crate::sealed_log::{self, DIR};

const _: () = assert!(DIR.logical_len == dirlog::PAGE);
const _: () = assert!(DIR.rec == dirlog::REC);
const _: () = assert!(DIR.header_len == dirlog::HEADER_LEN);
const _: () = assert!(DIR.max_recs == dirlog::MAX_RECS);
const _: () = assert!(DIR.phys_len == DIR_PHYS);

fn sector_start(sector: usize) -> usize {
    if sector == 0 {
        DIR_A_START
    } else {
        DIR_B_START
    }
}

/// The sealed bytes of one directory sector.
fn phys(sector: usize) -> &'static [u8] {
    flash_io::xip(sector_start(sector), DIR_PHYS)
}

fn blank_pages() -> [Vec<u8>; 2] {
    [
        alloc::vec![0xFFu8; dirlog::PAGE],
        alloc::vec![0xFFu8; dirlog::PAGE],
    ]
}

/// Both directory sectors decrypted into the page layout `se/dirlog.rs` reads (also used by the
/// status display). Blank if the key cannot be rebuilt.
pub fn pages() -> [Vec<u8>; 2] {
    match puf::try_sealer(Domain::Dir) {
        Some(s) => [
            sealed_log::open_page(&DIR, &s, phys(0)),
            sealed_log::open_page(&DIR, &s, phys(1)),
        ],
        None => blank_pages(),
    }
}

/// The two pages as the slices `dirlog` works on.
pub fn sectors(p: &[Vec<u8>; 2]) -> dirlog::Sectors<'_> {
    [&p[0][..], &p[1][..]]
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
            Some(chip) => {
                let p = pages();
                dirlog::scan(sectors(&p), chip).0
            }
            None => [0u8; DIR_LEN],
        }
    }

    fn save(&mut self, dir: &[u8; DIR_LEN]) -> Result<(), ()> {
        let chip = self.chip.ok_or(())?;
        // No key, no directory: refuse (the registration then fails) instead of writing plaintext.
        let sealer = puf::try_sealer(Domain::Dir).ok_or(())?;
        let logical = pages();
        let plan = dirlog::plan(sectors(&logical), &chip, dir);
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
                    flash_io::erase(&mut flash, sector_start(sector), DIR_PHYS)?;
                }
                Step::Program {
                    sector,
                    offset,
                    data,
                } => {
                    let writes = sealed_log::seal_program(&DIR, &sealer, offset, &data).ok_or(())?;
                    for w in writes {
                        flash_io::program(&mut flash, sector_start(sector) + w.offset, &w.data)?;
                        if phys(sector)[w.offset..w.offset + w.data.len()] != w.data[..] {
                            return Err(());
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
