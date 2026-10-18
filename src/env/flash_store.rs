//! `wasefire_store::Storage` on the last `STORE_PAGES` sectors of the RP2040 flash.
//!
//! Geometry follows OpenSK's own "Nordic configuration" (4-byte words, 4 KiB pages, a word may be
//! written twice between erases, `STORE_PAGES` pages). build.rs keeps the same area out of the linker's FLASH
//! region, so firmware and store can never overlap.
//!
//! Reads go straight through the XIP window (no copy, no flash lock). Writes and erases use the
//! embassy flash driver, which runs them from RAM with interrupts masked: the USB interrupt is
//! delayed for the duration of a sector erase (tens of ms), which the host tolerates (NAKs).
use alloc::borrow::Cow;
use core::cell::RefCell;
use wasefire_store::{Storage, StorageError, StorageIndex, StorageResult};

use crate::keys::Fl;
use crate::{FLASH_SIZE, PUF_BYTES, STORE_PAGES, VAULT_BYTES};

pub const PAGE_SIZE: usize = 4096;
const STORE_BYTES: usize = STORE_PAGES * PAGE_SIZE;
/// The vault (src/vault.rs) occupies the very end of flash, then the two PUF helper
/// sectors (src/puf.rs), and the store sits right below them.
const STORE_START: usize = FLASH_SIZE - VAULT_BYTES - PUF_BYTES - STORE_BYTES;
/// Start of the memory-mapped flash (XIP window).
const XIP_BASE: usize = 0x1000_0000;

pub struct FlashStorage {
    flash: &'static RefCell<Fl>,
}

impl FlashStorage {
    pub fn new(flash: &'static RefCell<Fl>) -> Self {
        FlashStorage { flash }
    }

    /// Erases the whole store area (used when the area holds nothing the store understands).
    pub fn format(&mut self) -> Result<(), embassy_rp::flash::Error> {
        self.flash
            .borrow_mut()
            .blocking_erase(STORE_START as u32, (STORE_START + STORE_BYTES) as u32)
    }

    /// Flash offset of `index`, checked against the store area.
    fn offset(index: &StorageIndex, length: usize) -> StorageResult<usize> {
        let end = index
            .byte
            .checked_add(length)
            .ok_or(StorageError::OutOfBounds)?;
        if index.page >= STORE_PAGES || end > PAGE_SIZE {
            return Err(StorageError::OutOfBounds);
        }
        Ok(STORE_START + index.page * PAGE_SIZE + index.byte)
    }
}

impl Storage for FlashStorage {
    fn word_size(&self) -> usize {
        4
    }

    fn page_size(&self) -> usize {
        PAGE_SIZE
    }

    fn num_pages(&self) -> usize {
        STORE_PAGES
    }

    fn max_word_writes(&self) -> usize {
        2
    }

    fn max_page_erases(&self) -> usize {
        10000
    }

    fn read_slice(&self, index: StorageIndex, length: usize) -> StorageResult<Cow<'_, [u8]>> {
        let offset = Self::offset(&index, length)?;
        // SAFETY: the range was checked to lie inside the store area of the memory-mapped flash.
        let bytes = unsafe { core::slice::from_raw_parts((XIP_BASE + offset) as *const u8, length) };
        Ok(Cow::Borrowed(bytes))
    }

    fn write_slice(&mut self, index: StorageIndex, value: &[u8]) -> StorageResult<()> {
        let offset = Self::offset(&index, value.len())?;
        self.flash
            .borrow_mut()
            .blocking_write(offset as u32, value)
            .map_err(|_| StorageError::CustomError)
    }

    fn erase_page(&mut self, page: usize) -> StorageResult<()> {
        let index = StorageIndex { page, byte: 0 };
        let from = Self::offset(&index, PAGE_SIZE)?;
        self.flash
            .borrow_mut()
            .blocking_erase(from as u32, (from + PAGE_SIZE) as u32)
            .map_err(|_| StorageError::CustomError)
    }
}
