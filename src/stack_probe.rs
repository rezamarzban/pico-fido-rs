//! Peak stack measurement (feature `stack_probe`, for development builds only).
//!
//! At start-up the unused part of the stack is painted with a pattern; after every handled packet
//! the high-water mark is read back and logged when it grows. All code (thread mode, interrupts,
//! the interrupt executor) shares the one main stack on this chip, so the mark covers all of it.
//!
//! Assumes the `flip-link` layout (`.cargo/config.toml`): the stack is the lowest region of RAM,
//! from the bottom of the RAM region (after the SRAM-PUF bytes, if any) up to `_stack_start`, and
//! an overflow runs off the bottom instead of into statics. Do not use it with another linker.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicUsize, Ordering};

use defmt::info;

unsafe extern "C" {
    /// Initial stack pointer = top of the stack (provided by cortex-m-rt / flip-link).
    static _stack_start: u32;
}

/// Bottom of the stack region: start of the linker's RAM region (see build.rs).
const BOTTOM: usize = if cfg!(feature = "sram_puf") { 0x2000_0200 } else { 0x2000_0000 };
const PAINT: u32 = 0xC5C5_C5C5;
/// Words left unpainted below the stack pointer: the frames of `paint` itself and its callers.
const MARGIN: usize = 512;

static PEAK: AtomicUsize = AtomicUsize::new(0);

fn top() -> usize {
    (&raw const _stack_start) as usize
}

/// Paints everything below the current stack pointer. Call once, early in `main`.
pub fn paint() {
    let sp = cortex_m::register::msp::read() as usize;
    let end = sp.saturating_sub(MARGIN) & !3;
    let mut a = BOTTOM;
    while a < end {
        // SAFETY: [BOTTOM, sp) is the unused part of the stack, nothing else lives there.
        unsafe { write_volatile(a as *mut u32, PAINT) };
        a += 4;
    }
    info!("stack: {} of {} bytes painted", end - BOTTOM, top() - BOTTOM);
}

/// Logs the stack use when it exceeds the previous peak.
pub fn report() {
    let mut a = BOTTOM;
    let t = top();
    // SAFETY: only reads RAM that belongs to the stack region.
    while a < t && unsafe { read_volatile(a as *const u32) } == PAINT {
        a += 4;
    }
    let used = t - a;
    if used > PEAK.load(Ordering::Relaxed) {
        PEAK.store(used, Ordering::Relaxed);
        info!("stack: peak {} of {} bytes", used, t - BOTTOM);
    }
}
