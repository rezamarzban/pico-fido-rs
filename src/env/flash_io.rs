//! Flash access shared by the sealed directory and counter (`dir_flash.rs`, `tally_flash.rs`).
//!
//! Sealed records are 44 / 60 bytes long, so they do not line up with the 256-byte programming
//! page of the flash chip the way the old 16 / 32-byte records did. `program` therefore never lets
//! one write cross a page boundary.

use crate::keys::Fl;
use crate::layout::{PAGE, XIP_BASE};

const PROG_PAGE: usize = 256;

/// Programs `data` at flash offset `addr` (bits can only go from 1 to 0: the target must be blank
/// or already hold exactly these bits). One write per 256-byte page.
pub fn program(flash: &mut Fl, addr: usize, data: &[u8]) -> Result<(), ()> {
    let mut addr = addr;
    let mut rest = data;
    while !rest.is_empty() {
        let n = (PROG_PAGE - addr % PROG_PAGE).min(rest.len());
        flash
            .blocking_write(addr as u32, &rest[..n])
            .map_err(|_| ())?;
        addr += n;
        rest = &rest[n..];
    }
    Ok(())
}

/// Erases `len` bytes (a multiple of the 4 KiB sector) at flash offset `start`.
pub fn erase(flash: &mut Fl, start: usize, len: usize) -> Result<(), ()> {
    debug_assert!(start.is_multiple_of(PAGE) && len.is_multiple_of(PAGE));
    flash
        .blocking_erase(start as u32, (start + len) as u32)
        .map_err(|_| ())
}

/// `len` bytes of flash at offset `start`, read through the XIP window.
pub fn xip(start: usize, len: usize) -> &'static [u8] {
    // SAFETY: callers pass an area of the memory-mapped flash outside the firmware image
    // (build.rs, src/layout.rs); it is only written through `program` / `erase`, never while a
    // returned slice is being read.
    unsafe { core::slice::from_raw_parts((XIP_BASE + start) as *const u8, len) }
}
