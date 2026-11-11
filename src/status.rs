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

/// The secure element answered at start-up and its identity below is valid.
pub static SE_PRESENT: AtomicBool = AtomicBool::new(false);
/// Serial number (9 bytes: SN0-3, SN4-7, SN8), revision (4 bytes), I2C address, lock bits.
pub static SE_SN_A: AtomicU32 = AtomicU32::new(0);
pub static SE_SN_B: AtomicU32 = AtomicU32::new(0);
pub static SE_SN_C: AtomicU8 = AtomicU8::new(0);
pub static SE_REV: AtomicU32 = AtomicU32::new(0);
pub static SE_ADDR: AtomicU8 = AtomicU8::new(0);
pub const SE_CFG_LOCKED: u8 = 1;
pub const SE_DATA_LOCKED: u8 = 2;
pub static SE_LOCKS: AtomicU8 = AtomicU8::new(0);
/// Credential key slots in use (0..=9; `SE_UNKNOWN` = not scanned yet).
pub const SE_UNKNOWN: u32 = u32::MAX;
pub static SE_REGS: AtomicU32 = AtomicU32::new(SE_UNKNOWN);

/// Credential slots that belong to a site (0..=9; `SE_UNKNOWN` = not known yet).
pub static SE_SITES: AtomicU32 = AtomicU32::new(SE_UNKNOWN);
/// Bit n = chip slot n holds a private key (bit 0 = attestation slot) / belongs to a site.
pub static KEY_MASK: AtomicU32 = AtomicU32::new(0);
pub static OWN_MASK: AtomicU32 = AtomicU32::new(0);
/// Signatures made: lifetime total (kept in the Pico's flash) and since power-up.
pub static SIGS_TOTAL: AtomicU32 = AtomicU32::new(0);
pub static SIGS_BOOT: AtomicU32 = AtomicU32::new(0);

/// Stores the chip identity read at start-up.
pub fn set_se(i: &crate::se::proto::ChipInfo) {
    let s = &i.serial;
    SE_SN_A.store(u32::from_be_bytes([s[0], s[1], s[2], s[3]]), Ordering::Relaxed);
    SE_SN_B.store(u32::from_be_bytes([s[4], s[5], s[6], s[7]]), Ordering::Relaxed);
    SE_SN_C.store(s[8], Ordering::Relaxed);
    SE_REV.store(u32::from_be_bytes(i.revision), Ordering::Relaxed);
    SE_ADDR.store(i.i2c_addr, Ordering::Relaxed);
    let mut l = 0;
    if i.config_locked {
        l |= SE_CFG_LOCKED;
    }
    if i.data_locked {
        l |= SE_DATA_LOCKED;
    }
    SE_LOCKS.store(l, Ordering::Relaxed);
    SE_PRESENT.store(true, Ordering::Relaxed);
}

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
