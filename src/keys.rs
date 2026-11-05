//! The flash type and the optional USB serial number. Randomness comes from the secure element
//! (src/env/rng.rs); credentials are handled by OpenSK's Persist + KeyStore (src/env/).

use defmt::warn;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;
use static_cell::StaticCell;

use crate::FLASH_SIZE;

pub type Fl = Flash<'static, FLASH, Blocking, FLASH_SIZE>;

/// USB serial number from the flash chip's unique ID (16 hex chars).
/// Returns `None` if the ID cannot be read or is a constant (all 0x00 / 0xFF), so that several
/// devices never present the same "unique" serial number.
pub fn serial(flash: &mut Fl) -> Option<&'static str> {
    let mut uid = [0u8; 8];
    if flash.blocking_unique_id(&mut uid).is_err() {
        warn!("flash: unique ID unreadable, USB serial number omitted");
        return None;
    }
    if uid.iter().all(|&b| b == 0) || uid.iter().all(|&b| b == 0xFF) {
        warn!("flash: unique ID is constant, USB serial number omitted");
        return None;
    }
    let mut s = [0u8; 16];
    for (i, b) in uid.iter().enumerate() {
        s[2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
        s[2 * i + 1] = b"0123456789abcdef"[(b & 15) as usize];
    }
    static SERIAL: StaticCell<[u8; 16]> = StaticCell::new();
    Some(core::str::from_utf8(&*SERIAL.init(s)).unwrap())
}
