//! Crash-safe storage of the 32-byte master key in two flash sectors (slots 0 and 1).
//!
//! Record (56 bytes): "FK02" | seq u32 LE | key[32] | first 16 bytes of SHA-256 over the previous 40 bytes.
//!
//! Rules:
//! * The newest valid record wins. "Newest" uses wrap-around (serial number) arithmetic on `seq`.
//! * An update ALWAYS starts by reading and validating *both* slots. It never relies on a position
//!   remembered in RAM, and it never treats an unreadable or unknown slot as "blank".
//! * The new record goes into the slot that does not hold the newest valid record, with
//!   `seq = newest + 1`, so it beats every older record even if wiping the old slot fails later.
//! * The new record is written, read back and compared. Only then is the old slot wiped.
//! * If an update fails, [`replace`] re-reads the flash and reports what the next boot will load,
//!   so the running firmware can use exactly that key (or none) instead of guessing.
//! * Blank flash (all 0xFF) means "first boot". Anything else without a valid record is
//!   reported as `Corrupt`: it is never silently replaced by a fresh key on boot.
use sha2::{Digest, Sha256};

pub const REC_LEN: usize = 56;
const MAGIC: [u8; 4] = *b"FK02";

pub trait Sectors {
    type Error;
    fn read(&mut self, slot: usize, buf: &mut [u8; REC_LEN]) -> Result<(), Self::Error>;
    fn erase(&mut self, slot: usize) -> Result<(), Self::Error>;
    fn write(&mut self, slot: usize, rec: &[u8; REC_LEN]) -> Result<(), Self::Error>;
}

/// Where a record lives.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pos {
    pub seq: u32,
    pub slot: usize,
}

#[derive(PartialEq, Eq, Debug)]
pub enum Loaded {
    Key([u8; 32], Pos),
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

/// What a failed or successful key replacement means for the running firmware.
#[derive(PartialEq, Eq, Debug)]
pub enum Replaced {
    /// The new key is durable and is what the next boot loads.
    New(Saved),
    /// The update failed and nothing changed: the next boot loads this (previous) key.
    Kept([u8; 32]),
    /// The update failed and flash holds no valid record (blank or damaged).
    NoKey,
    /// The update failed and the flash state could not be read back. The caller must stop
    /// using any key until the next boot / reset: it cannot know which key the loader picks.
    Unknown,
}

#[derive(PartialEq, Eq, Debug)]
pub enum SaveError {
    Io,
    Verify,
}

fn encode(key: &[u8; 32], seq: u32) -> [u8; REC_LEN] {
    let mut r = [0u8; REC_LEN];
    r[..4].copy_from_slice(&MAGIC);
    r[4..8].copy_from_slice(&seq.to_le_bytes());
    r[8..40].copy_from_slice(key);
    let h = Sha256::digest(&r[..40]);
    r[40..].copy_from_slice(&h[..16]);
    r
}

fn decode(r: &[u8; REC_LEN]) -> Option<([u8; 32], u32)> {
    if r[..4] != MAGIC || Sha256::digest(&r[..40])[..16] != r[40..] {
        return None;
    }
    Some((
        r[8..40].try_into().unwrap(),
        u32::from_le_bytes(r[4..8].try_into().unwrap()),
    ))
}

/// `a` is newer than `b` (serial number arithmetic, survives wrap-around).
fn newer(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

type Best = Option<([u8; 32], Pos)>;

/// Reads both slots. Any read error is an error: an unknown slot is never assumed to be blank.
/// Returns the newest valid record and whether both slots are completely blank.
fn scan<S: Sectors>(s: &mut S) -> Result<(Best, bool), S::Error> {
    let mut best: Best = None;
    let mut blank = true;
    for slot in 0..2 {
        let mut r = [0u8; REC_LEN];
        s.read(slot, &mut r)?;
        blank &= r.iter().all(|&b| b == 0xFF);
        if let Some((key, seq)) = decode(&r) {
            let better = match &best {
                None => true,
                Some((_, p)) => newer(seq, p.seq),
            };
            if better {
                best = Some((key, Pos { seq, slot }));
            }
        }
    }
    Ok((best, blank))
}

pub fn load<S: Sectors>(s: &mut S) -> Result<Loaded, S::Error> {
    let (best, blank) = scan(s)?;
    Ok(match best {
        Some((k, p)) => Loaded::Key(k, p),
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

/// Destroys whatever is in `slot`. Erase is tried twice; if the sector will not erase, the record
/// is overwritten with zeros (programming can only clear bits, so this works without an erase)
/// and checked to no longer be valid. Returns whether the slot no longer holds a valid record.
fn wipe<S: Sectors>(s: &mut S, slot: usize) -> bool {
    for _ in 0..2 {
        if s.erase(slot).is_ok() {
            return true;
        }
    }
    if s.write(slot, &[0u8; REC_LEN]).is_err() {
        return false;
    }
    let mut back = [0u8; REC_LEN];
    s.read(slot, &mut back).is_ok() && decode(&back).is_none()
}

/// Stores `key` as the newest record. The target slot and sequence number are always derived
/// from a fresh read of both slots. On error the new record may or may not be durable: callers
/// that must keep RAM and flash consistent use [`replace`], which reconciles with the flash.
pub fn save<S: Sectors>(s: &mut S, key: &[u8; 32]) -> Result<Saved, SaveError> {
    let (best, _) = scan(s).map_err(|_| SaveError::Io)?;
    let pos = match best {
        Some((_, p)) => Pos {
            seq: p.seq.wrapping_add(1),
            slot: p.slot ^ 1,
        },
        None => Pos { seq: 1, slot: 0 },
    };
    let rec = encode(key, pos.seq);
    if let Err(e) = write_verified(s, pos.slot, &rec) {
        // Best effort: take the half-done record back out so the previous key stays the only one.
        let _ = s.erase(pos.slot);
        return Err(e);
    }
    // The new record is committed and verified: now destroy everything else.
    let old_wiped = wipe(s, pos.slot ^ 1);
    Ok(Saved { pos, old_wiped })
}

/// Replaces the master key and reports the resulting persistent state, whatever happened.
/// After any failure the flash is re-read, so the answer always matches what the next boot loads.
pub fn replace<S: Sectors>(s: &mut S, key: &[u8; 32]) -> Replaced {
    if let Ok(saved) = save(s, key) {
        return Replaced::New(saved);
    }
    match load(s) {
        Ok(Loaded::Key(k, p)) if k == *key => {
            // the write became durable even though a later step failed
            let old_wiped = wipe(s, p.slot ^ 1);
            Replaced::New(Saved { pos: p, old_wiped })
        }
        Ok(Loaded::Key(k, _)) => Replaced::Kept(k),
        Ok(_) => Replaced::NoKey,
        Err(_) => Replaced::Unknown,
    }
}
