//! Device status shared between the firmware parts and the OLED display (`src/oled.rs`). Plain
//! atomics: written where the state changes, read by the display. Nothing here is secret.
#![allow(dead_code)] // some items are only used with the `oled` / `ir` features
use portable_atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

/// Time the main thread spent asleep in `wfi` (microseconds, wrapping). CPU load = 1 - idle.
pub static IDLE_US: AtomicU32 = AtomicU32::new(0);
/// HID packets handled.
pub static PKTS: AtomicU32 = AtomicU32::new(0);
/// A CTAP command is being processed.
pub static BUSY: AtomicBool = AtomicBool::new(false);

pub const USB_NONE: u8 = 0;
pub const USB_CONFIGURED: u8 = 1;
pub const USB_SUSPENDED: u8 = 2;
pub static USB: AtomicU8 = AtomicU8::new(USB_NONE);

pub const PUF_OFF: u8 = 0;
pub const PUF_BLANK: u8 = 1;
pub const PUF_DAMAGED: u8 = 2;
pub const PUF_NOISY: u8 = 3;
pub const PUF_READY: u8 = 4;
pub static PUF: AtomicU8 = AtomicU8::new(PUF_OFF);
pub static PUF_SLOT: AtomicU8 = AtomicU8::new(0);

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

/// IR PIN entry screen (src/ir_pin.rs -> src/oled.rs): kind 0 = normal status screen,
/// 1 = setting a PIN, 2 = entering it. Step 1/2 (set: enter, repeat), key count, message.
pub static ENTRY_KIND: AtomicU8 = AtomicU8::new(0);
pub static ENTRY_STEP: AtomicU8 = AtomicU8::new(1);
pub static ENTRY_COUNT: AtomicU8 = AtomicU8::new(0);
/// 0 none, 1 need more keys, 2 sequences differ.
pub static ENTRY_MSG: AtomicU8 = AtomicU8::new(0);
/// Draw the next frame now instead of waiting for the frame interval.
pub static REDRAW: AtomicBool = AtomicBool::new(false);
