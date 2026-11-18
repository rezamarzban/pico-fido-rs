//! Backup of the SRAM-PUF secret in the Pico's flash, one record per chip (pure logic, host-tested;
//! the flash access is in `env/backup_flash.rs`, the policy in `main.rs`).
//!
//! When the PUF gives its secret at start-up and the connected chip can give its backup key, the
//! secret is written to the backup sector sealed (AES-256-GCM, `seal.rs`) with a key derived from
//! that chip's **HMAC digest**: HMAC-SHA-256, computed INSIDE the chip, of a fixed challenge with a
//! random 32-byte key that lives in one of the chip's secret data slots (`se::ecdsa::backup_key`,
//! slot 11). That key was made by the chip's own RNG, is replaced by a new random key whenever a new record is written (`rotate_backup_key`) and never leaves the chip. If
//! the PUF later cannot be read (noisy sample, damaged or lost helper sector), connecting any chip
//! that has a record brings the secret back, and every key derived from it with it.
//!
//! **What this protects against:** a copy of the Pico's flash alone (the backup is useless without
//! the chip: the digest can only be had from the chip) and anyone who only knows public data such as
//! the attestation certificate. **What it does not:** anyone who holds the chip (the board) can ask it for
//! the digest. The secret is the same for every chip, so any ONE chip with a record opens the backup.
//!
//! Sector: a 16-byte header `[magic "PFRSPBK\x02" (8)][8-byte check]` followed by an append-only
//! log of records `[chip id (8)][sealed secret (60)][6-byte check]`. The chip id is a hash of the
//! digest (it names the record, it does not reveal the digest). The newest record of a chip that
//! really opens with that chip's key is its secret; a half-written record fails its check and is
//! skipped. Records are never removed: a chip is written once (again only if the secret changed, each time under a new slot-11 key,
//! after a re-enrolment), up to `MAX_RECS` records; a full sector refuses new chips (`Plan::Full`)
//! and keeps what it has. A sector without a valid header holds no backup and may be formatted
//! (this also drops records of the older, slot-0-public-key format, which cannot be opened any more;
//! they are written again from the live PUF secret).

use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::seal::{Domain, Sealer, OVERHEAD};

pub const PAGE: usize = 4096;
pub const SECRET_LEN: usize = 32;
pub const MAGIC: [u8; 8] = *b"PFRSPBK\x02";
pub const HEADER_LEN: usize = 16;
pub const ID_LEN: usize = 8;
const CHECK_LEN: usize = 6;
pub const SEALED_LEN: usize = SECRET_LEN + OVERHEAD;
pub const REC: usize = ID_LEN + SEALED_LEN + CHECK_LEN;
/// Records (= chips, plus superseded ones) the sector holds.
pub const MAX_RECS: usize = (PAGE - HEADER_LEN) / REC;

pub type ChipId = [u8; ID_LEN];

/// The chip's backup digest (see the module documentation).
pub type Digest32 = [u8; 32];

fn hash(label: &[u8], digest: &Digest32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update(digest);
    h.finalize().into()
}

/// The sealing key of a chip's record.
fn backup_key(digest: &Digest32) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(hash(b"pfrs-puf-backup-v2/key", digest))
}

/// Names a chip's records without revealing its digest.
pub fn chip_id(digest: &Digest32) -> ChipId {
    let d = hash(b"pfrs-puf-backup-v2/id", digest);
    let mut id = [0u8; ID_LEN];
    id.copy_from_slice(&d[..ID_LEN]);
    id
}

fn sealer(digest: &Digest32) -> Sealer {
    Sealer::new(&backup_key(digest), Domain::Backup)
}

fn aad(id: &ChipId) -> [u8; 8 + ID_LEN] {
    let mut a = [0u8; 8 + ID_LEN];
    a[..8].copy_from_slice(b"pfrs/pbk");
    a[8..].copy_from_slice(id);
    a
}

pub fn header() -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(&MAGIC);
    let d = Sha256::digest([b"pfrs-pbk-hdr".as_slice(), &MAGIC].concat());
    h[8..].copy_from_slice(&d[..8]);
    h
}

fn header_ok(sector: &[u8]) -> bool {
    sector.len() == PAGE && sector[..HEADER_LEN] == header()
}

fn rec_check(body: &[u8]) -> [u8; CHECK_LEN] {
    let mut h = Sha256::new();
    h.update(b"pfrs-pbk-rec1");
    h.update(body);
    let d = h.finalize();
    let mut c = [0u8; CHECK_LEN];
    c.copy_from_slice(&d[..CHECK_LEN]);
    c
}

/// The record that backs up `secret` for the chip whose backup digest is `digest`.
pub fn record(digest: &Digest32, secret: &[u8; SECRET_LEN]) -> [u8; REC] {
    let id = chip_id(digest);
    let mut r = [0u8; REC];
    r[..ID_LEN].copy_from_slice(&id);
    r[ID_LEN..ID_LEN + SEALED_LEN].copy_from_slice(&sealer(digest).seal(&aad(&id), secret));
    let c = rec_check(&r[..REC - CHECK_LEN]);
    r[REC - CHECK_LEN..].copy_from_slice(&c);
    r
}

/// Calls `f(record)` for every structurally valid record in log order; returns the record
/// positions in use (valid or not), or `None` if the sector has no valid header.
fn walk<'a>(sector: &'a [u8], mut f: impl FnMut(&'a [u8])) -> Option<usize> {
    if !header_ok(sector) {
        return None;
    }
    let mut used = 0;
    while used < MAX_RECS {
        let r = &sector[HEADER_LEN + used * REC..HEADER_LEN + (used + 1) * REC];
        if r.iter().all(|&b| b == 0xFF) {
            break;
        }
        used += 1;
        if r[REC - CHECK_LEN..] == rec_check(&r[..REC - CHECK_LEN]) {
            f(r);
        }
    }
    Some(used)
}

/// The PUF secret backed up for the chip whose backup digest is `digest` (the newest record that
/// opens with that chip's key), or `None`.
pub fn find(sector: &[u8], digest: &Digest32) -> Option<Zeroizing<[u8; SECRET_LEN]>> {
    let id = chip_id(digest);
    let mut mine: Vec<&[u8]> = Vec::new();
    let _ = walk(sector, |r| {
        if r[..ID_LEN] == id {
            mine.push(&r[ID_LEN..ID_LEN + SEALED_LEN]);
        }
    });
    let s = sealer(digest);
    for sealed in mine.into_iter().rev() {
        if let Some(p) = s.open(&aad(&id), sealed) {
            if p.len() == SECRET_LEN {
                let mut out = Zeroizing::new([0u8; SECRET_LEN]);
                out.copy_from_slice(&p);
                return Some(out);
            }
        }
    }
    None
}

/// How many different chips have a (structurally valid) record, and the record positions in use.
pub fn usage(sector: &[u8]) -> (usize, usize) {
    let mut ids: Vec<ChipId> = Vec::new();
    let used = walk(sector, |r| {
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&r[..ID_LEN]);
        if !ids.contains(&id) {
            ids.push(id);
        }
    });
    (ids.len(), used.unwrap_or(0))
}

/// What to do to the sector so that the chip with backup digest `digest` has `secret` backed up.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// The chip already has exactly this backed up.
    Nothing,
    /// Program `data` at byte `offset` of the sector (no erase).
    Append { offset: usize, data: Vec<u8> },
    /// No valid header: erase the sector, then program `data` (header and first record) at its start.
    Format { data: Vec<u8> },
    /// No room for one more record.
    Full,
}

pub fn plan(sector: &[u8], digest: &Digest32, secret: &[u8; SECRET_LEN]) -> Plan {
    let rec = record(digest, secret);
    if !header_ok(sector) {
        let mut data = Vec::with_capacity(HEADER_LEN + REC);
        data.extend_from_slice(&header());
        data.extend_from_slice(&rec);
        return Plan::Format { data };
    }
    if find(sector, digest).is_some_and(|s| *s == *secret) {
        return Plan::Nothing;
    }
    let (_, used) = usage(sector);
    if used >= MAX_RECS {
        return Plan::Full;
    }
    Plan::Append {
        offset: HEADER_LEN + used * REC,
        data: rec.to_vec(),
    }
}

/// State of the helper sector at start-up (mirrors `puf::Status`, kept apart so that the decision
/// below is pure and host-tested).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Helper {
    /// Erased: a new device, or the helper sector was lost.
    Blank,
    /// Holds something that is not a valid enrolment.
    Damaged,
    /// Valid, but this boot's RAM sample does not decode.
    Noisy,
    /// Valid and the sample decodes.
    Ready,
}

/// Why the firmware halts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Halt {
    Noisy,
    Damaged,
    /// The helper sector is erased but the device was enrolled before (other chips have a backup,
    /// or the backup cannot be read) and this chip has no record: wiping would destroy data that
    /// another chip could still unlock.
    Lost,
}

/// What start-up does about the flash key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boot {
    /// The PUF gives its secret.
    Go,
    /// Take the secret from this chip's backup record (and write a new helper sector if possible).
    Restore,
    /// Brand-new device: wipe, enrol, then back up.
    FirstStart,
    Halt(Halt),
}

/// The start-up policy. `has_backup`: the connected chip has a record that opens;
/// `chips_in_backup`: chips with a record; `sector_readable`: the backup sector could be read.
pub fn boot_decision(
    helper: Helper,
    has_backup: bool,
    chips_in_backup: usize,
    sector_readable: bool,
) -> Boot {
    match helper {
        Helper::Ready => Boot::Go,
        _ if has_backup => Boot::Restore,
        Helper::Noisy => Boot::Halt(Halt::Noisy),
        Helper::Damaged => Boot::Halt(Halt::Damaged),
        Helper::Blank if chips_in_backup > 0 || !sector_readable => Boot::Halt(Halt::Lost),
        Helper::Blank => Boot::FirstStart,
    }
}
