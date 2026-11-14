//! Maps the plaintext 4 KiB log pages of `se/dirlog.rs` and `se/tallylog.rs` onto sealed flash
//! sectors (pure logic, host-tested; the flash access is in `env/dir_flash.rs` and `env/tally_flash.rs`).
//!
//! Those two modules keep working on an ordinary, plaintext, page-shaped byte image (the *logical*
//! page: a 16-byte header followed by fixed-size records, blank = 0xFF) and decide which flash
//! operations an update needs. This module is the only place that knows the data is encrypted on
//! flash (the *physical* sector):
//!
//! ```text
//!   logical : [header 16][rec 0][rec 1] ...                  rec = R bytes
//!   physical: [header 16][sealed rec 0][sealed rec 1] ...    sealed rec = R + 28 bytes (nonce, ct, tag)
//! ```
//!
//! * The 16-byte header (magic, generation / format) is not secret and stays as it is.
//! * Each record is sealed on its own with AES-256-GCM (`seal.rs`), the associated data is
//!   `label || record index (u16 LE)`: a record moved to another position fails authentication.
//!   Records are programmed one after the other exactly like in the plaintext format (append, no
//!   erase), so wear and power-fail behaviour are unchanged: a torn record fails its tag and is
//!   skipped like a record with a bad check before.
//! * Reading yields the logical page: a record that is blank stays blank (end of the log), a record
//!   that is present but does not authenticate (torn write, other key, tampering) becomes an
//!   all-zero record, which the plaintext parsers count as a used position and reject on their own
//!   check.

use alloc::vec::Vec;

use crate::seal::{Sealer, OVERHEAD};

/// Geometry of one sealed region.
pub struct Layout {
    /// Start of every associated-data string (ends before the record index).
    pub label: &'static [u8],
    pub header_len: usize,
    /// Size of a logical (plaintext) record.
    pub rec: usize,
    /// Record positions the plaintext format uses (`MAX_RECS` of dirlog / tallylog).
    pub max_recs: usize,
    /// Size of the logical page the plaintext parsers work on.
    pub logical_len: usize,
    /// Size of the physical region (a multiple of the 4 KiB erase unit).
    pub phys_len: usize,
}

impl Layout {
    /// Size of a sealed record in the physical region.
    pub const fn sealed_rec(&self) -> usize {
        self.rec + OVERHEAD
    }
    /// Does the plaintext format fit the physical region?
    pub const fn fits(&self) -> bool {
        self.header_len + self.max_recs * self.rec <= self.logical_len
            && self.header_len + self.max_recs * self.sealed_rec() <= self.phys_len
    }
}

/// Site directory: 16-byte header, 127 records of 32 bytes (`se/dirlog.rs`), two 4 KiB sectors per region.
pub const DIR: Layout = Layout {
    label: b"pfrs/dir/v1/rec",
    header_len: 16,
    rec: 32,
    max_recs: 127,
    logical_len: 4096,
    phys_len: 8192,
};

/// Signature counter: 16-byte header, 255 records of 16 bytes (`se/tallylog.rs`), three 4 KiB sectors.
pub const TALLY: Layout = Layout {
    label: b"pfrs/tally/v1/rec",
    header_len: 16,
    rec: 16,
    max_recs: 255,
    logical_len: 4096,
    phys_len: 12288,
};

const _: () = core::assert!(DIR.fits() && TALLY.fits());

fn aad(l: &Layout, index: usize) -> Vec<u8> {
    let mut a = Vec::with_capacity(l.label.len() + 2);
    a.extend_from_slice(l.label);
    a.extend_from_slice(&(index as u16).to_le_bytes());
    a
}

/// Reads a physical region into the logical page. A wrong-sized region reads as blank.
pub fn open_page(l: &Layout, s: &Sealer, phys: &[u8]) -> Vec<u8> {
    let mut page = alloc::vec![0xFFu8; l.logical_len];
    if phys.len() != l.phys_len {
        return page;
    }
    page[..l.header_len].copy_from_slice(&phys[..l.header_len]);
    let sr = l.sealed_rec();
    for i in 0..l.max_recs {
        let p = &phys[l.header_len + i * sr..l.header_len + (i + 1) * sr];
        if p.iter().all(|&b| b == 0xFF) {
            break; // first blank position: the end of the log
        }
        let dst = &mut page[l.header_len + i * l.rec..l.header_len + (i + 1) * l.rec];
        match s.open(&aad(l, i), p) {
            Some(plain) => dst.copy_from_slice(&plain),
            None => dst.fill(0x00),
        }
    }
    page
}

/// One flash program operation inside the physical region.
#[derive(Debug, PartialEq, Eq)]
pub struct Write {
    pub offset: usize,
    pub data: Vec<u8>,
}

/// Turns "program `data` at logical `offset`" (as `dirlog` / `tallylog` plan it) into the physical
/// programs: header bytes are copied, whole records are sealed. `None` if the request is not
/// record-aligned or does not fit (the plaintext planners never produce such a request).
pub fn seal_program(l: &Layout, s: &Sealer, offset: usize, data: &[u8]) -> Option<Vec<Write>> {
    let mut out = Vec::new();
    let mut off = offset;
    let mut rest = data;
    if off < l.header_len {
        let n = (l.header_len - off).min(rest.len());
        out.push(Write {
            offset: off,
            data: rest[..n].to_vec(),
        });
        off += n;
        rest = &rest[n..];
    }
    if rest.is_empty() {
        return Some(out);
    }
    let rel = off - l.header_len;
    if !rel.is_multiple_of(l.rec) || !rest.len().is_multiple_of(l.rec) {
        return None;
    }
    let first = rel / l.rec;
    let count = rest.len() / l.rec;
    if first + count > l.max_recs {
        return None;
    }
    let sr = l.sealed_rec();
    let mut buf = alloc::vec![0u8; count * sr];
    for j in 0..count {
        s.seal_into(
            &aad(l, first + j),
            &rest[j * l.rec..(j + 1) * l.rec],
            &mut buf[j * sr..(j + 1) * sr],
        );
    }
    out.push(Write {
        offset: l.header_len + first * sr,
        data: buf,
    });
    Some(out)
}
