//! Crash-safe storage of the master-key record in two flash sectors (slots 0 and 1) plus a PIN
//! retry counter in a third sector.
//!
//! Record (110 bytes, "FK03"):
//!   magic[4] | seq u32 LE | wrapped u8 | argon2 m_kib u32 LE | argon2 t u8 | salt[16] |
//!   body[32] | tag[32] | first 16 bytes of SHA-256 over the previous 94 bytes
//! * `wrapped = 0`: `body` is the plain master key (no PIN set), salt/tag/params are zero.
//! * `wrapped = 1`: `body` is the master key encrypted under a key derived from the PIN
//!   (wrap.rs), `tag` authenticates it. The plain key is NOT in flash.
//! The older 56-byte "FK02" record (plain key only) is still read, and replaced on the next write.
//!
//! Rules:
//! * The newest valid record wins. "Newest" uses wrap-around (serial number) arithmetic on `seq`.
//! * An update ALWAYS starts by reading and validating *both* slots. It never relies on a position
//!   remembered in RAM, and it never treats an unreadable or unknown slot as "blank".
//! * The new record goes into the slot that does not hold the newest valid record, with
//!   `seq = newest + 1`, so it beats every older record even if wiping the old slot fails later.
//! * The new record is written, read back and compared. Only then is the old slot wiped.
//! * If an update fails, [`replace_record`] re-reads the flash and reports what the next boot will
//!   load, so the running firmware can use exactly that state instead of guessing.
//! * Blank flash (all 0xFF) means "first boot". Anything else without a valid record is
//!   reported as `Corrupt`: it is never silently replaced by a fresh key on boot.
//!
//! PIN retry counter: 16 pages of one flag byte each. An attempt is written as STARTED *before*
//! the PIN guess is evaluated (so cutting power cannot undo it) and marked DONE only after the
//! PIN was correct. The failure count is the number of STARTED flags after the last DONE flag.
//! A correct PIN therefore needs no erase; the sector is only erased when it is full or on reset.
use sha2::{Digest, Sha256};

pub const REC_LEN: usize = 110;
pub const TRIES_MAX: usize = 8;
pub const TRIES_PAGES: usize = 16;
const T_START: u8 = 0x7F;
const T_DONE: u8 = 0x00;
const MAGIC: [u8; 4] = *b"FK03";
const MAGIC_V2: [u8; 4] = *b"FK02";

pub trait Sectors {
    type Error;
    fn read(&mut self, slot: usize, buf: &mut [u8; REC_LEN]) -> Result<(), Self::Error>;
    fn erase(&mut self, slot: usize) -> Result<(), Self::Error>;
    fn write(&mut self, slot: usize, rec: &[u8; REC_LEN]) -> Result<(), Self::Error>;
    /// First byte of each of the `TRIES_PAGES` pages of the counter sector.
    fn tries_read(&mut self, out: &mut [u8; TRIES_PAGES]) -> Result<(), Self::Error>;
    /// Programs one flag byte (can only clear bits) into page `page` of the counter sector.
    fn tries_mark(&mut self, page: usize, val: u8) -> Result<(), Self::Error>;
    fn tries_clear(&mut self) -> Result<(), Self::Error>;
}

/// The persistent state the CTAP layer needs. `store::replace_record` and the counter functions
/// below implement it on top of [`Sectors`]; the firmware wraps them with logging (keys.rs).
pub trait Vault {
    fn replace(&mut self, rec: &Record) -> Replaced;
    /// Number of failed PIN attempts since the last correct one.
    fn tries_used(&mut self) -> Result<u8, ()>;
    /// Persists "one attempt started" and returns its page. Call BEFORE evaluating the PIN.
    fn begin_try(&mut self) -> Result<usize, ()>;
    /// The PIN was correct: forgive all earlier failed attempts.
    fn finish_try(&mut self, page: usize) -> Result<(), ()>;
    /// Forgets all attempts (new PIN / reset).
    fn clear_tries(&mut self) -> Result<(), ()>;
}

/// The key material stored in a slot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Record {
    pub wrapped: bool,
    pub m_kib: u32,
    pub t_cost: u8,
    pub salt: [u8; 16],
    pub body: [u8; 32],
    pub tag: [u8; 32],
}

impl Record {
    /// A record holding the plain master key (no PIN).
    pub fn plain(key: [u8; 32]) -> Self {
        Record {
            wrapped: false,
            m_kib: 0,
            t_cost: 0,
            salt: [0; 16],
            body: key,
            tag: [0; 32],
        }
    }
}

/// Where a record lives.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pos {
    pub seq: u32,
    pub slot: usize,
}

#[derive(PartialEq, Eq, Debug)]
pub enum Loaded {
    Rec(Record, Pos),
    Blank,
    Corrupt,
}

/// A record was committed.
#[derive(PartialEq, Eq, Debug)]
pub struct Saved {
    pub pos: Pos,
    /// False if the previous slot could not be wiped. The new record still wins on every
    /// boot (higher `seq`), but old key material may remain readable in flash.
    pub old_wiped: bool,
}

/// What a failed or successful replacement means for the running firmware.
#[derive(PartialEq, Eq, Debug)]
pub enum Replaced {
    /// The new record is durable and is what the next boot loads.
    New(Saved),
    /// The update failed and nothing changed: the next boot loads this (previous) record.
    Kept(Record),
    /// The update failed and flash holds no valid record (blank or damaged).
    NoKey,
    /// The update failed and the flash state could not be read back. The caller must stop
    /// using any key until the next boot / reset: it cannot know which record the loader picks.
    Unknown,
}

#[derive(PartialEq, Eq, Debug)]
pub enum SaveError {
    Io,
    Verify,
}

fn encode(rec: &Record, seq: u32) -> [u8; REC_LEN] {
    let mut r = [0u8; REC_LEN];
    r[..4].copy_from_slice(&MAGIC);
    r[4..8].copy_from_slice(&seq.to_le_bytes());
    r[8] = rec.wrapped as u8;
    r[9..13].copy_from_slice(&rec.m_kib.to_le_bytes());
    r[13] = rec.t_cost;
    r[14..30].copy_from_slice(&rec.salt);
    r[30..62].copy_from_slice(&rec.body);
    r[62..94].copy_from_slice(&rec.tag);
    let h = Sha256::digest(&r[..94]);
    r[94..].copy_from_slice(&h[..16]);
    r
}

fn decode(r: &[u8; REC_LEN]) -> Option<(Record, u32)> {
    let seq = u32::from_le_bytes(r[4..8].try_into().unwrap());
    if r[..4] == MAGIC && Sha256::digest(&r[..94])[..16] == r[94..] {
        let wrapped = match r[8] {
            0 => false,
            1 => true,
            _ => return None,
        };
        return Some((
            Record {
                wrapped,
                m_kib: u32::from_le_bytes(r[9..13].try_into().unwrap()),
                t_cost: r[13],
                salt: r[14..30].try_into().unwrap(),
                body: r[30..62].try_into().unwrap(),
                tag: r[62..94].try_into().unwrap(),
            },
            seq,
        ));
    }
    // legacy plain-key record
    if r[..4] == MAGIC_V2 && Sha256::digest(&r[..40])[..16] == r[40..56] {
        return Some((Record::plain(r[8..40].try_into().unwrap()), seq));
    }
    None
}

/// `a` is newer than `b` (serial number arithmetic, survives wrap-around).
fn newer(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

type Best = Option<(Record, Pos)>;

/// Reads both slots. Any read error is an error: an unknown slot is never assumed to be blank.
/// Returns the newest valid record and whether both slots are completely blank.
fn scan<S: Sectors>(s: &mut S) -> Result<(Best, bool), S::Error> {
    let mut best: Best = None;
    let mut blank = true;
    for slot in 0..2 {
        let mut r = [0u8; REC_LEN];
        s.read(slot, &mut r)?;
        blank &= r.iter().all(|&b| b == 0xFF);
        if let Some((rec, seq)) = decode(&r) {
            let better = match &best {
                None => true,
                Some((_, p)) => newer(seq, p.seq),
            };
            if better {
                best = Some((rec, Pos { seq, slot }));
            }
        }
    }
    Ok((best, blank))
}

pub fn load<S: Sectors>(s: &mut S) -> Result<Loaded, S::Error> {
    let (best, blank) = scan(s)?;
    Ok(match best {
        Some((k, p)) => Loaded::Rec(k, p),
        None if blank => Loaded::Blank,
        None => Loaded::Corrupt,
    })
}

fn write_verified<S: Sectors>(
    s: &mut S,
    slot: usize,
    rec: &[u8; REC_LEN],
) -> Result<(), SaveError> {
    s.erase(slot).map_err(|_| SaveError::Io)?;
    s.write(slot, rec).map_err(|_| SaveError::Io)?;
    let mut back = [0u8; REC_LEN];
    s.read(slot, &mut back).map_err(|_| SaveError::Io)?;
    if back != *rec {
        return Err(SaveError::Verify);
    }
    Ok(())
}

/// Reads `slot` back and checks that it no longer holds a valid record. (Software read-back
/// shows what the flash returns; it is not proof of physical erasure.)
fn slot_is_dead<S: Sectors>(s: &mut S, slot: usize) -> bool {
    let mut back = [0u8; REC_LEN];
    s.read(slot, &mut back).is_ok() && decode(&back).is_none()
}

/// Destroys whatever is in `slot`. Erase is tried twice and every "successful" erase is read back;
/// if the sector will not erase, the record is overwritten with zeros (programming can only clear
/// bits, so this works without an erase) and checked again. Returns whether the slot was verified
/// to no longer hold a valid record.
fn wipe<S: Sectors>(s: &mut S, slot: usize) -> bool {
    for _ in 0..2 {
        if s.erase(slot).is_ok() && slot_is_dead(s, slot) {
            return true;
        }
    }
    if s.write(slot, &[0u8; REC_LEN]).is_err() {
        return false;
    }
    slot_is_dead(s, slot)
}

/// Destroys an older, still valid record that an earlier update could not wipe (see
/// `Saved::old_wiped`). Call at boot. `Ok(true)` = nothing stale remains, `Ok(false)` = a stale
/// record is still readable. The newest record is never touched.
pub fn purge_stale<S: Sectors>(s: &mut S) -> Result<bool, SaveError> {
    let (best, _) = scan(s).map_err(|_| SaveError::Io)?;
    let Some((_, p)) = best else {
        return Ok(true);
    };
    let other = p.slot ^ 1;
    let mut r = [0u8; REC_LEN];
    s.read(other, &mut r).map_err(|_| SaveError::Io)?;
    if decode(&r).is_none() {
        return Ok(true);
    }
    Ok(wipe(s, other))
}

/// Stores `rec` as the newest record. The target slot and sequence number are always derived
/// from a fresh read of both slots. On error the new record may or may not be durable: callers
/// that must keep RAM and flash consistent use [`replace_record`], which reconciles with flash.
pub fn save<S: Sectors>(s: &mut S, rec: &Record) -> Result<Saved, SaveError> {
    let (best, _) = scan(s).map_err(|_| SaveError::Io)?;
    let pos = match best {
        Some((_, p)) => Pos {
            seq: p.seq.wrapping_add(1),
            slot: p.slot ^ 1,
        },
        None => Pos { seq: 1, slot: 0 },
    };
    let raw = encode(rec, pos.seq);
    if let Err(e) = write_verified(s, pos.slot, &raw) {
        // Best effort: take the half-done record back out so the previous record stays the only one.
        let _ = s.erase(pos.slot);
        return Err(e);
    }
    // The new record is committed and verified: now destroy everything else.
    let old_wiped = wipe(s, pos.slot ^ 1);
    Ok(Saved { pos, old_wiped })
}

/// Replaces the stored record and reports the resulting persistent state, whatever happened.
/// After any failure the flash is re-read, so the answer always matches what the next boot loads.
pub fn replace_record<S: Sectors>(s: &mut S, rec: &Record) -> Replaced {
    if let Ok(saved) = save(s, rec) {
        return Replaced::New(saved);
    }
    match load(s) {
        Ok(Loaded::Rec(k, p)) if k == *rec => {
            // the write became durable even though a later step failed
            let old_wiped = wipe(s, p.slot ^ 1);
            Replaced::New(Saved { pos: p, old_wiped })
        }
        Ok(Loaded::Rec(k, _)) => Replaced::Kept(k),
        Ok(_) => Replaced::NoKey,
        Err(_) => Replaced::Unknown,
    }
}

// ---- PIN retry counter ------------------------------------------------------------------------

/// (failed attempts since the last DONE flag, first free page)
fn analyse(f: &[u8; TRIES_PAGES]) -> (u8, Option<usize>) {
    let mut fails = 0u8;
    for (i, &b) in f.iter().enumerate() {
        match b {
            0xFF => return (fails, Some(i)),
            T_DONE => fails = 0,
            _ => fails = fails.saturating_add(1), // STARTED, or anything torn: counts against the user
        }
    }
    (fails, None)
}

fn read_tries<S: Sectors>(s: &mut S) -> Result<[u8; TRIES_PAGES], SaveError> {
    let mut f = [0xFFu8; TRIES_PAGES];
    s.tries_read(&mut f).map_err(|_| SaveError::Io)?;
    Ok(f)
}

pub fn count_tries<S: Sectors>(s: &mut S) -> Result<u8, SaveError> {
    Ok(analyse(&read_tries(s)?).0)
}

/// Persists a STARTED flag and returns its page. Fails (without writing) if the limit is reached.
pub fn begin_try<S: Sectors>(s: &mut S) -> Result<usize, SaveError> {
    let f = read_tries(s)?;
    let (fails, free) = analyse(&f);
    if fails as usize >= TRIES_MAX {
        return Err(SaveError::Io);
    }
    let page = match free {
        Some(p) => p,
        None => {
            // Sector full: erase and re-write the pending failures (0 in the usual case).
            s.tries_clear().map_err(|_| SaveError::Io)?;
            for p in 0..fails as usize {
                s.tries_mark(p, T_START).map_err(|_| SaveError::Io)?;
            }
            fails as usize
        }
    };
    s.tries_mark(page, T_START).map_err(|_| SaveError::Io)?;
    let g = read_tries(s)?;
    if g[page] != T_START || analyse(&g).0 != fails + 1 {
        return Err(SaveError::Verify);
    }
    Ok(page)
}

/// The PIN was correct: marks the attempt DONE, which forgives all earlier failures.
pub fn finish_try<S: Sectors>(s: &mut S, page: usize) -> Result<(), SaveError> {
    s.tries_mark(page, T_DONE).map_err(|_| SaveError::Io)?;
    if read_tries(s)?[page] != T_DONE {
        return Err(SaveError::Verify);
    }
    Ok(())
}

/// Erases the counter (only if it holds anything).
pub fn reset_tries<S: Sectors>(s: &mut S) -> Result<(), SaveError> {
    if read_tries(s)?.iter().all(|&b| b == 0xFF) {
        return Ok(());
    }
    s.tries_clear().map_err(|_| SaveError::Io)?;
    if !read_tries(s)?.iter().all(|&b| b == 0xFF) {
        return Err(SaveError::Verify);
    }
    Ok(())
}

/// Plain [`Vault`] on top of [`Sectors`] (used by tests and the host FFI; the firmware adds logging).
#[allow(dead_code)]
pub struct SectorVault<'a, S: Sectors>(pub &'a mut S);

#[allow(dead_code)]
impl<S: Sectors> Vault for SectorVault<'_, S> {
    fn replace(&mut self, rec: &Record) -> Replaced {
        replace_record(self.0, rec)
    }
    fn tries_used(&mut self) -> Result<u8, ()> {
        count_tries(self.0).map_err(|_| ())
    }
    fn begin_try(&mut self) -> Result<usize, ()> {
        begin_try(self.0).map_err(|_| ())
    }
    fn finish_try(&mut self, page: usize) -> Result<(), ()> {
        finish_try(self.0, page).map_err(|_| ())
    }
    fn clear_tries(&mut self) -> Result<(), ()> {
        reset_tries(self.0).map_err(|_| ())
    }
}
