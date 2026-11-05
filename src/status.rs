//! Device status shared between the firmware parts and the OLED display (`src/oled.rs`). Plain
//! atomics: written where the state changes, read by the display. Nothing here is secret.
use portable_atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

/// HID packets handled.
pub static PKTS: AtomicU32 = AtomicU32::new(0);
/// A CTAP command is being processed.
pub static BUSY: AtomicBool = AtomicBool::new(false);

pub const USB_NONE: u8 = 0;
pub const USB_CONFIGURED: u8 = 1;
pub const USB_SUSPENDED: u8 = 2;
pub static USB: AtomicU8 = AtomicU8::new(USB_NONE);

/// Signatures the secure element still allows (`SE_UNKNOWN` = not read yet / chip did not answer).
pub const SE_UNKNOWN: u32 = u32::MAX;
pub static SE_LEFT: AtomicU32 = AtomicU32::new(SE_UNKNOWN);

/// Key-value store usage and erase-budget use, in store words (0 = not read yet).
pub static STORE_USED: AtomicU32 = AtomicU32::new(0);
pub static STORE_TOTAL: AtomicU32 = AtomicU32::new(0);
pub static LIFE_USED: AtomicU32 = AtomicU32::new(0);
pub static LIFE_TOTAL: AtomicU32 = AtomicU32::new(0);

pub fn set_store(used: u32, total: u32, life_used: u32, life_total: u32) {
    STORE_USED.store(used, Ordering::Relaxed);
    STORE_TOTAL.store(total, Ordering::Relaxed);
    LIFE_USED.store(life_used, Ordering::Relaxed);
    LIFE_TOTAL.store(life_total, Ordering::Relaxed);
}
