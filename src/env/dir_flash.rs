//! The site directory (which relying party owns which ATECC608A key slot) in the Pico's flash.
//!
//! It used to live in data slot 13 of the chip; now NOTHING but keys is stored in the chip. The
//! directory has its own 4 KiB flash page directly below the OpenSK key-value store (build.rs keeps
//! that page out of the linker's FLASH region, like the store). It is separate from the store on
//! purpose: OpenSK's own reset and the store's "format" never touch it. The page format (an
//! append-only record log, no erase to add a site) is in `se/dirlog.rs`, which is host-tested.
//! A directory that is lost is not fatal: the keys stay in the chip, and `se::ecdsa` takes over
//! slots that hold a key but belong to nobody.

use core::cell::RefCell;

use super::flash_store::{PAGE_SIZE, STORE_START, XIP_BASE};
use crate::keys::Fl;
use crate::se::dirlog::{self, Plan};
use crate::se::ecdsa::{DirStore, DIR_LEN};

const _: () = assert!(PAGE_SIZE == dirlog::PAGE);

/// The directory page: the 4 KiB right below the key-value store.
pub const DIR_START: usize = STORE_START - PAGE_SIZE;

pub struct FlashDir {
    flash: &'static RefCell<Fl>,
}

// SAFETY: there is a single core. The directory is only used from OpenSK's thread-mode code (key
// creation); the USB / interrupt executor never touches it. The `RefCell` is shared with the
// key-value store, whose operations never overlap with a key creation.
unsafe impl Send for FlashDir {}

impl FlashDir {
    pub fn new(flash: &'static RefCell<Fl>) -> Self {
        FlashDir { flash }
    }

    /// The page, read straight through the XIP window.
    fn page(&self) -> &'static [u8] {
        // SAFETY: DIR_START..DIR_START+PAGE_SIZE lies inside the memory-mapped flash, outside the
        // firmware image (build.rs) and outside the store; nothing writes it concurrently.
        unsafe { core::slice::from_raw_parts((XIP_BASE + DIR_START) as *const u8, PAGE_SIZE) }
    }
}

impl DirStore for FlashDir {
    fn load(&mut self) -> [u8; DIR_LEN] {
        dirlog::scan(self.page()).0
    }

    fn save(&mut self, dir: &[u8; DIR_LEN]) -> Result<(), ()> {
        match dirlog::plan(self.page(), dir) {
            Plan::Nothing => Ok(()),
            Plan::Append { offset, data } => self
                .flash
                .borrow_mut()
                .blocking_write((DIR_START + offset) as u32, &data)
                .map_err(|_| ()),
            Plan::Rewrite { data } => {
                let mut flash = self.flash.borrow_mut();
                flash
                    .blocking_erase(DIR_START as u32, (DIR_START + PAGE_SIZE) as u32)
                    .map_err(|_| ())?;
                flash.blocking_write(DIR_START as u32, &data).map_err(|_| ())
            }
        }
    }
}
