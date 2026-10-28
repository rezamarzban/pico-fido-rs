//! Stack scrubbing.
//!
//! Zeroizing wipes a variable when it is dropped, but values that were moved or returned by value,
//! the internal state of the HMAC/SHA-256/P-256 code and compiler spill slots leave copies in dead
//! stack frames. Calling `stack()` from a shallow frame overwrites the region just below it, where
//! those dead frames are, with zeros. The array is written with volatile stores and passed to
//! `black_box`, so the compiler can neither drop nor shorten the writes.
//!
//! Limits: CPU registers are not touched (they are overwritten within a few instructions anyway),
//! and a live frame above the caller is of course not scrubbed.
use core::hint::black_box;
use core::ptr::write_volatile;

#[inline(never)]
fn wipe<const WORDS: usize>() {
    let mut a = [0u32; WORDS];
    for w in a.iter_mut() {
        // SAFETY: `w` is a valid, aligned reference into `a`.
        unsafe { write_volatile(w, 0) };
    }
    black_box(&mut a);
}

/// Scrubs 4 KiB below the caller. Cheap (about 1k word stores): call after every command.
pub fn stack() {
    wipe::<1024>();
}

/// Scrubs 32 KiB below the caller. At boot, because a warm reset (watchdog, panic) keeps RAM.
pub fn stack_boot() {
    wipe::<8192>();
}
