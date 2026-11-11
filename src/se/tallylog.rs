//! On-flash format of the lifetime signature counter (pure logic, host-tested; the flash access is
//! in `env/tally_flash.rs`). The chip counts nothing: this count is kept on the Pico.
//!
//! A 4 KiB page: a 16-byte header, then an append-only log of 8-byte records
//! `[count, u32 little endian][4-byte check]`. One record is appended per signature, each position
//! is programmed once, so no erase is needed until the page is full (every 510 signatures; the
//! page is then formatted and restarted with the current total: about 200 000 erase cycles' worth
//! of margin is left even after tens of millions of signatures). A half-written record fails its
//! check and is skipped; the latest valid record is the total.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use super::dirlog::{Plan, PAGE};

pub const HEADER: [u8; 16] = *b"PFRS-SIGTALLY\x01\0\0";
pub const REC: usize = 8;
pub const MAX_RECS: usize = (PAGE - HEADER.len()) / REC;

fn check(count: u32) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(b"pfrs-sig");
    h.update(count.to_le_bytes());
    let d = h.finalize();
    let mut c = [0u8; 4];
    c.copy_from_slice(&d[..4]);
    c
}

fn record(count: u32) -> [u8; REC] {
    let mut r = [0u8; REC];
    r[..4].copy_from_slice(&count.to_le_bytes());
    r[4..].copy_from_slice(&check(count));
    r
}

/// (total signatures, record positions in use, header valid) of a page. An unformatted page is 0.
pub fn scan(page: &[u8]) -> (u32, usize, bool) {
    if page.len() != PAGE || page[..HEADER.len()] != HEADER {
        return (0, 0, false);
    }
    let (mut total, mut used) = (0u32, 0usize);
    while used < MAX_RECS {
        let r = &page[HEADER.len() + used * REC..HEADER.len() + (used + 1) * REC];
        if r.iter().all(|&b| b == 0xFF) {
            break;
        }
        used += 1;
        let count = u32::from_le_bytes([r[0], r[1], r[2], r[3]]);
        if r[4..] == check(count) {
            total = count;
        }
    }
    (total, used, true)
}

/// How to bring the page to the new `total`.
pub fn plan(page: &[u8], total: u32) -> Plan {
    let (cur, used, valid) = scan(page);
    if valid && cur == total {
        return Plan::Nothing;
    }
    if valid && used < MAX_RECS {
        return Plan::Append { offset: HEADER.len() + used * REC, data: record(total).to_vec() };
    }
    let mut data = Vec::with_capacity(HEADER.len() + REC);
    data.extend_from_slice(&HEADER);
    data.extend_from_slice(&record(total));
    Plan::Rewrite { data }
}
