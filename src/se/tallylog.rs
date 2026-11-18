//! On-flash format of the lifetime signature counters, one per chip (pure logic, host-tested; the
//! flash access is in `env/tally_flash.rs`). The chips count nothing: the counts are kept on the Pico,
//! and each chip is told apart by its unique 9-byte serial number.
//!
//! Like the site directory (`dirlog.rs`) the counters live in TWO regions (A and B), of which exactly
//! one is *active* at a time. A region is a 16-byte header
//! `[magic "PFRSTAL\x03" (8)][generation u32 LE][4-byte check]` followed by an append-only log of
//! 16-byte records `[chip serial (9)][count, u32 little endian][3-byte check]`.
//!
//! **Counting a signature** appends one record to the active region; each position is programmed
//! once, so no erase is needed until the region is full (every ~250 signatures). A half-written
//! record fails its check and is skipped; the latest valid record of a chip is its total.
//!
//! **Compaction** (the log is full, or the very first save) is copy-on-write and never touches the
//! active region: the INACTIVE region is erased, one record per chip is programmed into it (the
//! `MAX_CHIPS` chips with the highest totals are kept), and only then its header, carrying the next
//! generation number, is programmed. That last write is the commit. Until it has completed the region
//! has no valid header and the old, intact region stays active; afterwards the region with the highest
//! valid generation is the active one. A power failure at any moment therefore leaves either the
//! complete old counters or the complete new ones, never blank or truncated ones (`TallyPlan::steps`
//! lists the steps in order; the host tests cut the power after every one of them and in the middle
//! of every program and erase step). At worst the signature that was being counted is not counted.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use super::dirlog::{Sectors, Step, PAGE};
use super::ecdsa::ChipSerial;

pub const MAGIC: [u8; 8] = *b"PFRSTAL\x03";
pub const HEADER_LEN: usize = 16;
pub const REC: usize = 16;
pub const MAX_RECS: usize = (PAGE - HEADER_LEN) / REC;
/// Chips whose count survives a compaction of the log (leaves room for new records).
pub const MAX_CHIPS: usize = 32;

/// What to do to store a new total (see the module documentation).
#[derive(Debug, PartialEq, Eq)]
pub enum TallyPlan {
    /// The counters already hold exactly this.
    Nothing,
    /// Program `data` at byte `offset` of the ACTIVE region (no erase).
    Append {
        sector: usize,
        offset: usize,
        data: Vec<u8>,
    },
    /// Copy-on-write into the inactive `sector`: erase it, program `records` at `HEADER_LEN`, and
    /// only then program `header` at offset 0 (the commit).
    Rewrite {
        sector: usize,
        records: Vec<u8>,
        header: [u8; HEADER_LEN],
    },
}

impl TallyPlan {
    /// The flash operations, in the order they must run. A power failure after any prefix of them
    /// (or in the middle of one) must leave counters that `scan` reads as the old or the new ones.
    pub fn steps(&self) -> Vec<Step> {
        match self {
            TallyPlan::Nothing => Vec::new(),
            TallyPlan::Append {
                sector,
                offset,
                data,
            } => alloc::vec![Step::Program {
                sector: *sector,
                offset: *offset,
                data: data.clone(),
            }],
            TallyPlan::Rewrite {
                sector,
                records,
                header,
            } => {
                let mut v = alloc::vec![Step::Erase { sector: *sector }];
                if !records.is_empty() {
                    v.push(Step::Program {
                        sector: *sector,
                        offset: HEADER_LEN,
                        data: records.clone(),
                    });
                }
                v.push(Step::Program {
                    sector: *sector,
                    offset: 0,
                    data: header.to_vec(),
                });
                v
            }
        }
    }
}

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

fn header_check(generation: u32) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(b"pfrs-talhdr3");
    h.update(generation.to_le_bytes());
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

/// The header that commits a region as generation `generation`.
pub fn header(generation: u32) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(&MAGIC);
    h[8..12].copy_from_slice(&generation.to_le_bytes());
    h[12..].copy_from_slice(&header_check(generation));
    h
}

/// Generation of a region with a valid header (`None`: blank, torn, foreign or older format).
fn sector_generation(s: &[u8]) -> Option<u32> {
    if s.len() != PAGE || s[..8] != MAGIC {
        return None;
    }
    let g = u32::from_le_bytes([s[8], s[9], s[10], s[11]]);
    (s[12..HEADER_LEN] == header_check(g)).then_some(g)
}

/// The active region (index, generation): the valid one with the newer generation (wrapping
/// comparison; on a tie region A). `None` if neither region has a valid header.
pub fn active(sectors: Sectors) -> Option<(usize, u32)> {
    match (sector_generation(sectors[0]), sector_generation(sectors[1])) {
        (Some(a), Some(b)) => {
            if (b.wrapping_sub(a) as i32) > 0 {
                Some((1, b))
            } else {
                Some((0, a))
            }
        }
        (Some(a), None) => Some((0, a)),
        (None, Some(b)) => Some((1, b)),
        (None, None) => None,
    }
}

/// Calls `f(serial, count)` for every valid record of the active region in log order; returns the
/// record positions in use (valid or not), or `None` if there is no active region.
fn walk(sectors: Sectors, mut f: impl FnMut(ChipSerial, u32)) -> Option<usize> {
    let (a, _) = active(sectors)?;
    let page = sectors[a];
    let mut used = 0;
    while used < MAX_RECS {
        let r = &page[HEADER_LEN + used * REC..HEADER_LEN + (used + 1) * REC];
        if r.iter().all(|&b| b == 0xFF) {
            break; // first blank position: the end of the log
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

/// (total signatures of chip `serial`, record positions in use in the active region, counters
/// valid). Unknown chip: 0.
pub fn scan(sectors: Sectors, serial: &ChipSerial) -> (u32, usize, bool) {
    let mut total = 0u32;
    let used = walk(sectors, |s, c| {
        if &s == serial {
            total = c;
        }
    });
    (total, used.unwrap_or(0), used.is_some())
}

/// The total of every chip that has one (latest record wins), in order of first use.
pub fn totals(sectors: Sectors) -> Vec<(ChipSerial, u32)> {
    let mut v: Vec<(ChipSerial, u32)> = Vec::new();
    let _ = walk(sectors, |s, c| match v.iter_mut().find(|e| e.0 == s) {
        Some(e) => e.1 = c,
        None => v.push((s, c)),
    });
    v
}

/// (chips that have a count, bytes of the ACTIVE region in use: header + record positions; 0 = no
/// valid counters). For the status display; no hashing for the size.
pub fn usage(sectors: Sectors) -> (Vec<ChipSerial>, usize) {
    let Some((a, _)) = active(sectors) else {
        return (Vec::new(), 0);
    };
    let n = (0..MAX_RECS)
        .take_while(|&i| {
            sectors[a][HEADER_LEN + i * REC..][..REC]
                .iter()
                .any(|&b| b != 0xFF)
        })
        .count();
    (
        totals(sectors).into_iter().map(|e| 