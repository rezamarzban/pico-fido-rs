//! On-flash format of the site directory for SEVERAL chips (pure logic, host-tested; the flash
//! access itself is in `env/dir_flash.rs`).
//!
//! Every ATECC608A has a unique 9-byte serial number. The directories of all chips this key has
//! seen live in TWO 4 KiB sectors (A and B), of which exactly one is *active* at a time. A sector
//! is a 16-byte header `[magic "PFRSDIR\x03" (8)][generation u32 LE][4-byte check]` followed by an
//! append-only log of 32-byte records `[chip serial (9)][slot index (1)][16-byte RP tag][6-byte check]`.
//! The RP tag is the first 16 bytes of the SHA-256 of the RP ID (128 bits). Which records count for the
//! connected chip is decided by its serial, so swapping the chip switches to that chip's own
//! directory and never mixes two chips up. The latest valid record of a (chip, slot) wins.
//!
//! **Adding a site** appends one record to the active sector; no erase is needed (flash bits can
//! only be cleared). A power failure can at worst leave one half-written record, which fails its
//! check and is skipped (that registration never completed, so no key was handed out).
//!
//! **Rewriting** (the log is full, or the very first save) is copy-on-write and never touches the
//! active sector: the INACTIVE sector is erased, all records are programmed into it, and only
//! then its header, carrying the next generation number, is programmed. That last write is the
//! commit. Until it has completed, the sector has no valid header and the old, intact sector stays
//! active; afterwards the sector with the highest valid generation is the active one. A power
//! failure at any moment therefore leaves either the complete old directory or the complete new
//! one, never an empty or a truncated one (`DirPlan::steps` lists the steps in order; the host
//! tests cut the power after every one of them, and in the middle of every program step).
//!
//! If no sector has a valid header (blank flash, foreign data, an older format) the directory reads
//! as empty and the first save formats sector A. If even a compaction does not fit (more than
//! `MAX_RECS` entries in total: 14 completely used chips) the save is refused (`DirPlan::Full`)
//! instead of forgetting another chip.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use super::ecdsa::{ChipSerial, DIR_ENTRY, DIR_LEN, SLOTS};

pub const PAGE: usize = 4096;
/// The two sectors of the directory (A = index 0, B = index 1).
pub type Sectors<'a> = [&'a [u8]; 2];
pub const MAGIC: [u8; 8] = *b"PFRSDIR\x03";
pub const HEADER_LEN: usize = 16;
pub const REC: usize = 32;
const CHECK_LEN: usize = 6;
const _: () = assert!(9 + 1 + DIR_ENTRY + CHECK_LEN == REC);
pub const MAX_RECS: usize = (PAGE - HEADER_LEN) / REC;

/// What to do with a (non-directory) page to store a new value; also used by `tallylog`.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// The page already holds exactly this.
    Nothing,
    /// Program `data` at byte `offset` of the page (no erase).
    Append { offset: usize, data: Vec<u8> },
    /// Erase the page, then program `data` at its start.
    Rewrite { data: Vec<u8> },
}

/// One flash operation of a directory update. Execute them strictly in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Erase {
        sector: usize,
    },
    Program {
        sector: usize,
        offset: usize,
        data: Vec<u8>,
    },
}

/// What to do to store a new directory (see the module documentation).
#[derive(Debug, PartialEq, Eq)]
pub enum DirPlan {
    /// The directory already holds exactly this.
    Nothing,
    /// Program `data` at byte `offset` of the ACTIVE sector (no erase).
    Append {
        sector: usize,
        offset: usize,
        data: Vec<u8>,
    },
    /// Copy-on-write into the inactive `sector`: erase it, program `records` at `HEADER_LEN`, check
    /// the result, and only then program `header` at offset 0 (the commit).
    Rewrite {
        sector: usize,
        records: Vec<u8>,
        header: [u8; HEADER_LEN],
    },
    /// Does not fit even after compaction: do nothing and report a failure.
    Full,
}

impl DirPlan {
    /// The flash operations, in the order they must run. A power failure after any prefix of them
    /// (or in the middle of one) must leave a directory that `scan` reads as the old or the new one.
    pub fn steps(&self) -> Vec<Step> {
        match self {
            DirPlan::Nothing | DirPlan::Full => Vec::new(),
            DirPlan::Append {
                sector,
                offset,
                data,
            } => {
                alloc::vec![Step::Program {
                    sector: *sector,
                    offset: *offset,
                    data: data.clone()
                }]
            }
            DirPlan::Rewrite {
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

fn check(serial: &ChipSerial, idx: u8, tag: &[u8]) -> [u8; CHECK_LEN] {
    let mut h = Sha256::new();
    h.update(b"pfrs-dir3");
    h.update(serial);
    h.update([idx]);
    h.update(tag);
    let d = h.finalize();
    let mut c = [0u8; CHECK_LEN];
    c.copy_from_slice(&d[..CHECK_LEN]);
    c
}

fn tag_of(dir: &[u8; DIR_LEN], i: usize) -> &[u8] {
    &dir[i * DIR_ENTRY..(i + 1) * DIR_ENTRY]
}

fn record(serial: &ChipSerial, i: usize, tag: &[u8]) -> [u8; REC] {
    let mut r = [0u8; REC];
    r[..9].copy_from_slice(serial);
    r[9] = i as u8;
    r[10..10 + DIR_ENTRY].copy_from_slice(tag);
    r[10 + DIR_ENTRY..].copy_from_slice(&check(serial, i as u8, tag));
    r
}

fn header_check(generation: u32) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(b"pfrs-dirhdr3");
    h.update(generation.to_le_bytes());
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

/// The header that commits a sector as generation `generation`.
pub fn header(generation: u32) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(&MAGIC);
    h[8..12].copy_from_slice(&generation.to_le_bytes());
    h[12..].copy_from_slice(&header_check(generation));
    h
}

/// Generation of a sector with a valid header (`None`: blank, torn, foreign or older format).
fn sector_generation(s: &[u8]) -> Option<u32> {
    if s.len() != PAGE || s[..8] != MAGIC {
        return None;
    }
    let g = u32::from_le_bytes([s[8], s[9], s[10], s[11]]);
    (s[12..HEADER_LEN] == header_check(g)).then_some(g)
}

/// The active sector (index, generation): the valid one with the newer generation (wrapping
/// comparison; on a tie sector A). `None` if neither sector has a valid header.
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

/// Calls `f(serial, slot index, tag)` for every valid record of the active sector in log order;
/// returns the number of record positions in use (valid or not), or `None` if there is no active
/// sector.
fn walk(sectors: Sectors, mut f: impl FnMut(ChipSerial, usize, &[u8])) -> Option<usize> {
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
        let idx = r[9] as usize;
        if idx < SLOTS as usize
            && r[10 + DIR_ENTRY..] == check(&serial, r[9], &r[10..10 + DIR_ENTRY])
        {
            f(serial, idx, &r[10..10 + DIR_ENTRY]);
        }
    }
    Some(used)
}

/// (directory of chip `serial`, record positions in use in the active sector, directory valid).
pub fn scan(sectors: Sectors, serial: &ChipSerial) -> ([u8; DIR_LEN], usize, bool) {
    let mut dir = [0u8; DIR_LEN];
    let used = walk(sectors, |s, idx, tag| {
        if &s == serial {
            dir[idx * DIR_ENTRY..(idx + 1) * DIR_ENTRY].copy_from_slice(tag);
        }
    });
    (dir, used.unwrap_or(0), used.is_some())
}

/// Every entry of every chip (latest record wins, cleared entries left out).
fn entries(sectors: Sectors) -> Vec<(ChipSerial, usize, [u8; DIR_ENTRY])> {
    let mut v: Vec<(ChipSerial, usize, [u8; DIR_ENTRY])> = Vec::new();
    let _ = walk(sectors, |s, idx, tag| {
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
pub fn chips(sectors: Sectors) -> Vec<ChipSerial> {
    let mut v: Vec<ChipSerial> = Vec::new();
    for e in entries(sectors) {
        if !v.contains(&e.0) {
            v.push(e.0);
        }
    }
    v
}

/// (chips that have at least one site recorded, bytes of the ACTIVE sector in use: header + record
/// positions; 0 = no valid directory). For the status display; no hashing for the size.
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
    (chips(sectors), HEADER_LEN + n * REC)
}

/// How to bring the directory to hold `dir` for chip `serial` (the other chips stay as they are).
pub fn plan(sectors: Sectors, serial: &ChipSerial, dir: &[u8; DIR_LEN]) -> DirPlan {
    let (cur, used, valid) = scan(sectors, serial);
    let changed: Vec<usize> = (0..SLOTS as usize)
        .filter(|&i| tag_of(&cur, i) != tag_of(dir, i))
        .collect();
    if changed.is_empty() {
        // Nothing differs (also: nothing to store on a blank flash, which is not worth an erase).
        return DirPlan::Nothing;
    }
    if valid && used + changed.len() <= MAX_RECS {
        let mut data = Vec::with_capacity(changed.len() * REC);
        for &i in &changed {
            data.extend_from_slice(&record(serial, i, tag_of(dir, i)));
        }
        let (sector, _) = active(sectors).expect("valid directory has an active sector");
        return DirPlan::Append {
            sector,
            offset: HEADER_LEN + used * REC,
            data,
        };
    }
    // First use / foreign data / older format, or the log is full: copy-on-write into the inactive
    // sector, one record per entry that is set, the other chips' entries first. The active sector
    // is not touched, so no power failure can lose the directory.
    let (sector, generation) = match active(sectors) {
        Some((a, g)) => (1 - a, g.wrapping_add(1)),
        None => (0, 1),
    };
    let mut records = Vec::with_capacity(REC);
    let mut n = 0;
    if valid {
        for (s, i, t) in entries(sectors).into_iter().filter(|e| &e.0 != serial) {
            records.extend_from_slice(&record(&s, i, &t));
            n += 1;
        }
    }
    for i in 0..SLOTS as usize {
        if tag_of(dir, i).iter().any(|&b| b != 0) {
            records.extend_from_slice(&record(serial, i, tag_of(dir, i)));
            n += 1;
        }
    }
    if n > MAX_RECS {
        return DirPlan::Full;
    }
    DirPlan::Rewrite {
        sector,
        records,
        header: header(generation),
    }
}
