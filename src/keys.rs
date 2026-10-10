//! Credential table in the last 4K flash sector. Table index == ATECC key slot.
//! The private keys themselves live only inside the ATECC; this table maps credential IDs and
//! relying parties to slots and keeps user info for discoverable (resident) credentials.
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;

use super::FLASH_SIZE;

pub type Fl = Flash<'static, FLASH, Blocking, FLASH_SIZE>;

pub const MAX_CREDS: usize = 8;
pub const ID_LEN: usize = 16;
const MAX_UID: usize = 64;
const MAX_NAME: usize = 32;

const SECTOR: u32 = 4096;
const OFFSET: u32 = FLASH_SIZE as u32 - SECTOR; // keep memory.x FLASH 4K shorter than the chip
const MAGIC: [u8; 4] = *b"FK02";
const USED: u8 = 0xA5;
const ENTRY: usize = 184;
const TABLE_LEN: usize = 4 + MAX_CREDS * ENTRY;

#[derive(Clone)]
pub struct Cred {
    pub rk: bool,
    pub id: [u8; ID_LEN],
    pub rp: [u8; 32],
    pub uid: Vec<u8>,
    pub name: String,
    pub display: String,
}

pub fn trunc(s: &str, max: usize) -> String {
    let mut n = s.len().min(max);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    String::from(&s[..n])
}

fn encode(c: &Cred, b: &mut [u8]) {
    b[0] = USED;
    b[1] = c.rk as u8;
    b[2..18].copy_from_slice(&c.id);
    b[18..50].copy_from_slice(&c.rp);
    b[50] = c.uid.len() as u8;
    b[51..51 + c.uid.len()].copy_from_slice(&c.uid);
    b[115] = c.name.len() as u8;
    b[116..116 + c.name.len()].copy_from_slice(c.name.as_bytes());
    b[148] = c.display.len() as u8;
    b[149..149 + c.display.len()].copy_from_slice(c.display.as_bytes());
}

fn decode(b: &[u8]) -> Option<Cred> {
    if b[0] != USED {
        return None;
    }
    let (ul, nl, dl) = (b[50] as usize, b[115] as usize, b[148] as usize);
    if ul > MAX_UID || nl > MAX_NAME || dl > MAX_NAME {
        return None;
    }
    Some(Cred {
        rk: b[1] != 0,
        id: b[2..18].try_into().ok()?,
        rp: b[18..50].try_into().ok()?,
        uid: b[51..51 + ul].to_vec(),
        name: String::from_utf8(b[116..116 + nl].to_vec()).ok()?,
        display: String::from_utf8(b[149..149 + dl].to_vec()).ok()?,
    })
}

pub struct Store {
    pub slots: [Option<Cred>; MAX_CREDS],
    flash: Fl,
}

impl Store {
    pub fn load(mut flash: Fl) -> Self {
        let mut slots: [Option<Cred>; MAX_CREDS] = Default::default();
        let mut buf = vec![0u8; TABLE_LEN];
        if flash.blocking_read(OFFSET, &mut buf).is_ok() && buf[..4] == MAGIC {
            for (i, s) in slots.iter_mut().enumerate() {
                *s = decode(&buf[4 + i * ENTRY..4 + (i + 1) * ENTRY]);
            }
        }
        Store { slots, flash }
    }

    pub fn free_slot(&self) -> Option<usize> {
        self.slots.iter().position(|s| s.is_none())
    }

    /// Persist the whole table. Returns false if the flash operation failed.
    pub fn save(&mut self) -> bool {
        let mut buf = vec![0xFFu8; TABLE_LEN];
        buf[..4].copy_from_slice(&MAGIC);
        for (i, s) in self.slots.iter().enumerate() {
            if let Some(c) = s {
                let e = &mut buf[4 + i * ENTRY..4 + (i + 1) * ENTRY];
                e.fill(0);
                encode(c, e);
            }
        }
        self.flash.blocking_erase(OFFSET, OFFSET + SECTOR).is_ok()
            && self.flash.blocking_write(OFFSET, &buf).is_ok()
    }
}
