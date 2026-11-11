//! On-flash format of the site directory for SEVERAL chips (pure logic, host-tested; the flash
//! access itself is in `env/dir_flash.rs`).
//!
//! Every ATECC608A has a unique 9-byte serial number. A 4 KiB page holds the directories of all
//! chips this key has seen: a 16-byte header, then an append-only log of 32-byte records
//! `[chip serial (9)][slot index (1)][7-byte RP tag][8-byte check][7 zero bytes]`. Which records
//! count for the connected chip is decided by its serial, so swapping the chip switches to that
//! chip's own directory and never mixes two chips up. Adding a record never needs an erase (flash
//! bits can only be cleared), so a power failure can at worst leave one half-written record, which
//! fails its check and is skipped. The latest valid record of a (chip, slot) wins. A page without
//! the header (blank, foreign data, an older format) reads as empty and is formatted by the first
//! save. When the log is full, the page is rewritten with one record per entry of ALL chips; if
//! even that does not fit (more than `MAX_RECS` entries in total: 14 completely used chips) the
//! save is refused (`Plan::Full`) instead of forgetting another chip.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use super::ecdsa::{ChipSerial, DIR_ENTRY, DIR_LEN, SLOTS};

pub const PAGE: usize = 4096;
pub const HEADER: [u8; 16] = *b"PFRS-SITEDIR\x02\0\0\0";
pub const REC: usize = 32;
pub const MAX_RECS: usize = (PAGE - HEADER.len()) / REC;

/// What to do with a page to store a new value.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// The page already holds exactly this.
    Nothing,
    /// Program `data` at byte `offset` of the page (no erase).
    Append { offset: usize, data: Vec<u8> },
    /// Erase the page, then program `data` at its start.
    Rewrite { data: Vec<u8> },
    /// Does not fit even after compaction: do nothing and report a failure.
    Full,
}

fn check(serial: &ChipSerial, idx: u8, tag: &[u8]) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(b"pfrs-dir2");
    h.update(serial);
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

fn record(serial: &ChipSerial, i: usize, tag: &[u8]) -> [u8; REC] {
    let mut r = [0u8; REC];
    r[..9].copy_from_slice(serial);
    r[9] = i as u8;
    r[10..17].copy_from_slice(tag);
    r[17..25].copy_from_slice(&check(serial, i as u8, tag));
    r
}

/// Calls `f(serial, slot index, tag)` for every valid record in log order; returns the number of
/// record positions in use (valid or not), or `None` if the page has no valid header.
fn walk(page: &[u8], mut f: impl FnMut(ChipSerial, usize, &[u8])) -> Option<usize> {
    if page.len() != PAGE || page[..HEADER.len()] != HEADER {
        return None;
    }
    let mut used = 0;
    while used < MAX_RECS {
        let r = &page[HEADER.len() + used * REC..HEADER.len() + (used + 1) * REC];
        if r.iter().all(|&b| b == 0xFF) {
            break; // first blank position: the end of the log
        }
        used += 1;
        let mut serial = [0u8; 9];
        serial.copy_from_slice(&r[..9]);
        let idx = r[9] as usize;
        if idx < SLOTS as usize && r[17..25] == check(&serial, r[9], &r[10..17]) {
            f(serial, idx, &r[10..17]);
        }
    }
    Some(used)
}

/// (directory of chip `serial`, record positions in use, header valid) of a page.
pub fn scan(page: &[u8], serial: &ChipSerial) -> ([u8; DIR_LEN], usize, bool) {
    let mut dir = [0u8; DIR_LEN];
    let used = walk(page, |s, idx, tag| {
        if &s == serial {
            dir[idx * DIR_ENTRY..(idx + 1) * DIR_ENTRY].copy_from_slice(tag);
        }
    });
    (dir, used.unwrap_or(0), used.is_some())
}

/// Every entry of every chip (latest record wins, cleared entries left out).
fn entries(page: &[u8]) -> Vec<(ChipSerial, usize, [u8; DIR_ENTRY])> {
    let mut v: Vec<(ChipSerial, usize, [u8; DIR_ENTRY])> = Vec::new();
    let _ = walk(page, |s, idx, tag| {
        let mut t = [0u8; DIR_ENTRY];
        t.copy_from_slice(tag);
        match v.iter_mut().find(|e| e.0 == s && e.1 == idx) {
            Some(e) => e.2 = t,
            None => v.push((s, idx, t)),
        }
    });
    v.retain(|e| e.2.iter().any(|&b| b != 0));
    v
}

/// The serial numbers of all chips that have at least one site recorded, in order of first use.
pub fn chips(page: &[u8]) -> Vec<ChipSerial> {
    let mut v: Vec<ChipSerial> = Vec::new();
    for e in entries(page) {
        if !v.contains(&e.0) {
            v.push(e.0);
        }
    }
    v
}

/// (chips that have at least one site recorded, bytes of the page in use: header + record
/// positions; 0 = no valid header). For the status display; no hashing for the size.
pub fn usage(page: &[u8]) -> (Vec<ChipSerial>, usize) {
    if page.len() != PAGE || page[..HEADER.len()] != HEADER {
        return (Vec::new(), 0);
    }
    let n = (0..MAX_RECS)
        .take_while(|&i| page[HEADER.len() + i * REC..][..REC].iter().any(|&b| b != 0xFF))
        .count();
    (chips(page), HEADER.len() + n * REC)
}

/// How to bring the page to hold `dir` for chip `serial` (the other chips stay as they are).
pub fn plan(page: &[u8], serial: &ChipSerial, dir: &[u8; DIR_LEN]) -> Plan {
    let (cur, used, valid) = scan(page, serial);
    let changed: Vec<usize> = (0..SLOTS as usize).filter(|&i| tag_of(&cur, i) != tag_of(dir, i)).collect();
    if valid && changed.is_empty() {
        return Plan::Nothing;
    }
    if valid && used + changed.len() <= MAX_RECS {
        let mut data = Vec::with_capacity(changed.len() * REC);
        for &i in &changed {
            data.extend_from_slice(&record(serial, i, tag_of(dir, i)));
        }
        return Plan::Append { offset: HEADER.len() + used * REC, data };
    }
    // No valid header (first use / foreign data / older format) or the log is full: format, header
    // + one record per entry that is set, the other chips' entries first. A power failure between
    // the erase and the write leaves an empty page; the keys themselves are in the chips and are
    // taken over again (se/ecdsa.rs).
    let mut data = Vec::with_capacity(HEADER.len() + REC);
    data.extend_from_slice(&HEADER);
    let mut n = 0;
    if valid {
        for (s, i, t) in entries(page).into_iter().filter(|e| &e.0 != serial) {
            data.extend_from_slice(&record(&s, i, &t));
            n += 1;
        }
    }
    for i in 0..SLOTS as usize {
        if tag_of(dir, i).iter().any(|&b| b != 0) {
            data.extend_from_slice(&record(serial, i, tag_of(dir, i)));
            n += 1;
        }
    }
    if n > MAX_RECS {
        return Plan::Full;
    }
    Plan::Rewrite { data }
}
