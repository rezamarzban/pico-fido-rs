//! Credential table, stored twice (A/B) in the last two 4K flash sectors. Table index == ATECC slot.
//! The private keys live only inside the ATECC; this table maps credential IDs / relying parties to
//! slots and keeps user info for discoverable credentials.
//!
//! Each copy carries a sequence number and a SHA-256 over its contents. `save()` always writes the
//! *inactive* copy, so a power cut during a write leaves the previous copy intact and `load()` picks
//! the newest valid one. The hash detects corruption/torn writes; it does NOT authenticate against
//! someone who can rewrite flash (they can recompute it).
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;
use sha2::{Digest, Sha256};

use super::FLASH_SIZE;

pub type Fl = Flash<'static, FLASH, Blocking, FLASH_SIZE>;

pub const MAX_CREDS: usize = 8;
pub const ID_LEN: usize = 16;
const MAX_UID: usize = 64;
const MAX_NAME: usize = 32;

const SECTOR: u32 = 4096;
/// Two sectors at the end of flash; keep memory.x FLASH 8K shorter than the chip.
const OFF: [u32; 2] = [FLASH_SIZE as u32 - 2 * SECTOR, FLASH_SIZE as u32 - SECTOR];
const MAGIC: [u8; 4] = *b"FK03";
const USED: u8 = 0xA5;
const ENTRY: usize = 188;
const TABLE_LEN: usize = 8 + MAX_CREDS * ENTRY + 32; // magic+seq, entries, sha256

#[derive(Clone)]
pub struct Cred {
    pub rk: bool,
    pub id: [u8; ID_LEN],
    pub rp: [u8; 32],
    pub uid: Vec<u8>,
    pub name: String,
    pub display: String,
    /// Creation order (higher = newer); used to list discoverable credentials newest first.
    pub ts: u32,
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
    b[181..185].copy_from_slice(&c.ts.to_le_bytes());
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
        ts: u32::from_le_bytes(b[181..185].try_into().ok()?),
    })
}

fn build(seq: u32, slots: &[Option<Cred>; MAX_CREDS]) -> Vec<u8> {
    let mut buf = vec![0xFFu8; TABLE_LEN];
    buf[..4].copy_from_slice(&MAGIC);
    buf[4..8].copy_from_slice(&seq.to_le_bytes());
    for (i, s) in slots.iter().enumerate() {
        if let Some(c) = s {
            let e = &mut buf[8 + i * ENTRY..8 + (i + 1) * ENTRY];
            e.fill(0);
            encode(c, e);
        }
    }
    let h = Sha256::digest(&buf[..TABLE_LEN - 32]);
    buf[TABLE_LEN - 32..].copy_from_slice(&h);
    buf
}

fn parse(buf: &[u8]) -> Option<(u32, [Option<Cred>; MAX_CREDS])> {
    if buf[..4] != MAGIC || buf[TABLE_LEN - 32..] != Sha256::digest(&buf[..TABLE_LEN - 32])[..] {
        return None;
    }
    let seq = u32::from_le_bytes(buf[4..8].try_into().ok()?);
    let mut slots: [Option<Cred>; MAX_CREDS] = Default::default();
    for (i, s) in slots.iter_mut().enumerate() {
        *s = decode(&buf[8 + i * ENTRY..8 + (i + 1) * ENTRY]);
    }
    Some((seq, slots))
}

pub struct Store {
    pub slots: [Option<Cred>; MAX_CREDS],
    flash: Fl,
    seq: u32,
    active: usize,
}

impl Store {
    pub fn load(mut flash: Fl) -> Self {
        let mut best: Option<(u32, usize, [Option<Cred>; MAX_CREDS])> = None;
        for (i, &off) in OFF.iter().enumerate() {
            let mut buf = vec![0u8; TABLE_LEN];
            if flash.blocking_read(off, &mut buf).is_ok() {
                if let Some((seq, s)) = parse(&buf) {
                    if best.as_ref().map_or(true, |b| seq > b.0) {
                        best = Some((seq, i, s));
                    }
                }
            }
        }
        let (seq, active, slots) = best.unwrap_or((0, 1, Default::default()));
        Store { slots, flash, seq, active }
    }

    pub fn free_slot(&self) -> Option<usize> {
        self.slots.iter().position(|s| s.is_none())
    }

    pub fn next_ts(&self) -> u32 {
        self.slots.iter().flatten().map(|c| c.ts).max().map_or(1, |m| m.wrapping_add(1))
    }

    /// Writes the inactive copy, then switches to it. A power cut leaves the old copy valid.
    pub fn save(&mut self) -> bool {
        let target = 1 - self.active;
        let seq = self.seq.wrapping_add(1);
        let buf = build(seq, &self.slots);
        let ok = self.flash.blocking_erase(OFF[target], OFF[target] + SECTOR).is_ok()
            && self.flash.blocking_write(OFF[target], &buf).is_ok();
        if ok {
            self.seq = seq;
            self.active = target;
        }
        ok
    }
}
