//! On-flash format of the lifetime signature counters, one per chip (pure logic, host-tested; the
//! flash access is in `env/tally_flash.rs`). The chips count nothing: the counts are kept on the Pico,
//! and each chip is told apart by its unique 9-byte serial number.
//!
//! A 4 KiB page: a 16-byte header, then an append-only log of 16-byte records
//! `[chip serial (9)][count, u32 little endian][3-byte check]`. One record is appended per
//! signature, each position is programmed once, so no erase is needed until the page is full (every
//! ~250 signatures); the page is then formatted and restarted with one record per chip (the
//! `MAX_CHIPS` chips with the highest totals are kept). A half-written record fails its check and
//! is skipped; the latest valid record of a chip is its total.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use super::dirlog::{Plan, PAGE};
use super::ecdsa::ChipSerial;

pub const HEADER: [u8; 16] = *b"PFRS-SIGTALLY\x02\0\0";
pub const REC: usize = 16;
pub const MAX_RECS: usize = (PAGE - HEADER.len()) / REC;
/// Chips whose count survives a compaction of the log (leaves room for new records).
pub const MAX_CHIPS: usize = 32;

fn check(serial: &ChipSerial, count: u32) -> [u8; 3] {
    let mut h = Sha256::new();
    h.update(b"pfrs-sig2");
    h.update(serial);
    h.update(count.to_le_bytes());
    let d = h.finalize();
    let mut c = [0u8; 3];
    c.copy_from_slice(&d[..3]);
    c
}

fn record(serial: &ChipSerial, count: u32) -> [u8; REC] {
    let mut r = [0u8; REC];
    r[..9].copy_from_slice(serial);
    r[9..13].copy_from_slice(&count.to_le_bytes());
    r[13..].copy_from_slice(&check(serial, count));
    r
}

/// Calls `f(serial, count)` for every valid record in log order; returns the record positions in
/// use, or `None` if the page has no valid header.
fn walk(page: &[u8], mut f: impl FnMut(ChipSerial, u32)) -> Option<usize> {
    if page.len() != PAGE || page[..HEADER.len()] != HEADER {
        return None;
    }
    let mut used = 0;
    while used < MAX_RECS {
        let r = &page[HEADER.len() + used * REC..HEADER.len() + (used + 1) * REC];
        if r.iter().all(|&b| b == 0xFF) {
            break;
        }
        used += 1;
        let mut serial = [0u8; 9];
        serial.copy_from_slice(&r[..9]);
        let count = u32::from_le_bytes([r[9], r[10], r[11], r[12]]);
        if r[13..] == check(&serial, count) {
            f(serial, count);
        }
    }
    Some(used)
}

/// (total signatures of chip `serial`, record positions in use, header valid). Unknown chip: 0.
pub fn scan(page: &[u8], serial: &ChipSerial) -> (u32, usize, bool) {
    let mut total = 0u32;
    let used = walk(page, |s, c| {
        if &s == serial {
            total = c;
        }
    });
    (total, used.unwrap_or(0), used.is_some())
}

/// The total of every chip that has one (latest record wins), in order of first use.
pub fn totals(page: &[u8]) -> Vec<(ChipSerial, u32)> {
    let mut v: Vec<(ChipSerial, u32)> = Vec::new();
    let _ = walk(page, |s, c| match v.iter_mut().find(|e| e.0 == s) {
        Some(e) => e.1 = c,
        None => v.push((s, c)),
    });
    v
}

/// (chips that have a count, bytes of the page in use: header + record positions; 0 = no valid
/// header). For the status display; no hashing for the size.
pub fn usage(page: &[u8]) -> (Vec<ChipSerial>, usize) {
    if page.len() != PAGE || page[..HEADER.len()] != HEADER {
        return (Vec::new(), 0);
    }
    let n = (0..MAX_RECS)
        .take_while(|&i| {
            page[HEADER.len() + i * REC..][..REC]
                .iter()
                .any(|&b| b != 0xFF)
        })
        .count();
    (
        totals(page).into_iter().map(|e| e.0).collect(),
        HEADER.len() + n * REC,
    )
}

/// How to bring the page to the new `total` of chip `serial` (the other chips keep theirs).
pub fn plan(page: &[u8], serial: &ChipSerial, total: u32) -> Plan {
    let (cur, used, valid) = scan(page, serial);
    if valid && cur == total {
        return Plan::Nothing;
    }
    if valid && used < MAX_RECS {
        return Plan::Append {
            offset: HEADER.len() + used * REC,
            data: record(serial, total).to_vec(),
        };
    }
    let mut others: Vec<(ChipSerial, u32)> = if valid { totals(page) } else { Vec::new() };
    others.retain(|e| &e.0 != serial);
    others.sort_by_key(|e| core::cmp::Reverse(e.1)); // highest totals first (stable: ties keep log order)
    others.truncate(MAX_CHIPS - 1);
    let mut data = Vec::with_capacity(HEADER.len() + (others.len() + 1) * REC);
    data.extend_from_slice(&HEADER);
    for (s, c) in &others {
        data.extend_from_slice(&record(s, *c));
    }
    data.extend_from_slice(&record(serial, total));
    Plan::Rewrite { data }
}
