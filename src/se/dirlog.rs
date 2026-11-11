//! On-flash format of the site directory (pure logic, host-tested; the flash access itself is in
//! `env/dir_flash.rs`).
//!
//! A 4 KiB page: a 16-byte header, then an append-only log of 16-byte records
//! `[slot index][7-byte RP tag][8-byte check]`. Adding a record never needs an erase (flash bits can
//! only be cleared), so a power failure can at worst leave one half-written record, which fails its
//! check and is skipped. The latest valid record of a slot wins. A page without the header (blank,
//! foreign data, old firmware) reads as an empty directory and is formatted by the first save.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use super::ecdsa::{DIR_ENTRY, DIR_LEN, SLOTS};

pub const PAGE: usize = 4096;
pub const HEADER: [u8; 16] = *b"PFRS-SITEDIR\x01\0\0\0";
pub const REC: usize = 16;
pub const MAX_RECS: usize = (PAGE - HEADER.len()) / REC;

/// What to do with the page to store a new directory image.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// The page already holds exactly this directory.
    Nothing,
    /// Program `data` at byte `offset` of the page (no erase).
    Append { offset: usize, data: Vec<u8> },
    /// Erase the page, then program `data` at its start.
    Rewrite { data: Vec<u8> },
}

fn check(idx: u8, tag: &[u8]) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(b"pfrs-dir");
    h.update([idx]);
    h.update(tag);
    let d = h.finalize();
    let mut c = [0u8; 8];
    c.copy_from_slice(&d[..8]);
    c
}

fn tag_of(dir: &[u8; DIR_LEN], i: usize) -> &[u8] {
    &dir[i * DIR_ENTRY..(i + 1) * DIR_ENTRY]
}

fn record(i: usize, dir: &[u8; DIR_LEN]) -> [u8; REC] {
    let tag = tag_of(dir, i);
    let mut r = [0u8; REC];
    r[0] = i as u8;
    r[1..8].copy_from_slice(tag);
    r[8..].copy_from_slice(&check(i as u8, tag));
    r
}

/// (directory image, record positions in use, header valid) of a page.
pub fn scan(page: &[u8]) -> ([u8; DIR_LEN], usize, bool) {
    let mut dir = [0u8; DIR_LEN];
    if page.len() != PAGE || page[..HEADER.len()] != HEADER {
        return (dir, 0, false);
    }
    let mut used = 0;
    while used < MAX_RECS {
        let r = &page[HEADER.len() + used * REC..HEADER.len() + (used + 1) * REC];
        if r.iter().all(|&b| b == 0xFF) {
            break; // first blank position: the end of the log
        }
        used += 1;
        let idx = r[0] as usize;
        if idx < SLOTS as usize && r[8..] == check(r[0], &r[1..8]) {
            dir[idx * DIR_ENTRY..(idx + 1) * DIR_ENTRY].copy_from_slice(&r[1..8]);
        }
    }
    (dir, used, true)
}

/// How to bring the page to hold `dir`.
pub fn plan(page: &[u8], dir: &[u8; DIR_LEN]) -> Plan {
    let (cur, used, valid) = scan(page);
    let changed: Vec<usize> = (0..SLOTS as usize).filter(|&i| tag_of(&cur, i) != tag_of(dir, i)).collect();
    if valid && changed.is_empty() {
        return Plan::Nothing;
    }
    if valid && used + changed.len() <= MAX_RECS {
        let mut data = Vec::with_capacity(changed.len() * REC);
        for &i in &changed {
            data.extend_from_slice(&record(i, dir));
        }
        return Plan::Append { offset: HEADER.len() + used * REC, data };
    }
    // No valid header (first use / foreign data) or the log is full: format, header + one record
    // per entry that is set. A power failure between the erase and the write leaves an empty
    // directory; the keys themselves are in the chip and are taken over again (se/ecdsa.rs).
    let mut data = Vec::with_capacity(HEADER.len() + SLOTS as usize * REC);
    data.extend_from_slice(&HEADER);
    for i in 0..SLOTS as usize {
        if tag_of(dir, i).iter().any(|&b| b != 0) {
            data.extend_from_slice(&record(i, dir));
        }
    }
    Plan::Rewrite { data }
}
