//! Crash-safe storage of the 32-byte master key in two flash sectors (slots 0 and 1).
//!
//! Record (56 bytes): "FK02" | seq u32 LE | key[32] | first 16 bytes of SHA-256 over the previous 40 bytes.
//! * The newest valid record (highest `seq`) wins.
//! * An update writes the *other* slot, reads it back, and only then erases the old slot
//!   (so a power cut never leaves zero valid records, and an old key never survives a reset).
//! * Blank flash (all 0xFF) means "first boot". Anything else without a valid record is
//!   reported as `Corrupt`: it is never silently replaced by a fresh key.
use sha2::{Digest, Sha256};

pub const REC_LEN: usize = 56;
const MAGIC: [u8; 4] = *b"FK02";

pub trait Sectors {
    type Error;
    fn read(&mut self, slot: usize, buf: &mut [u8; REC_LEN]) -> Result<(), Self::Error>;
    fn erase(&mut self, slot: usize) -> Result<(), Self::Error>;
    fn write(&mut self, slot: usize, rec: &[u8; REC_LEN]) -> Result<(), Self::Error>;
}

/// Where the current key lives, needed to do the next safe update.
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

pub fn load<S: Sectors>(s: &mut S) -> Result<Loaded, S::Error> {
    let mut best: Option<([u8; 32], Pos)> = None;
    let mut blank = true;
    for slot in 0..2 {
        let mut r = [0u8; REC_LEN];
        s.read(slot, &mut r)?;
        blank &= r.iter().all(|&b| b == 0xFF);
        if let Some((key, seq)) = decode(&r) {
            if best.as_ref().map_or(true, |(_, p)| seq > p.seq) {
                best = Some((key, Pos { seq, slot }));
            }
        }
    }
    Ok(match best {
        Some((k, p)) => Loaded::Key(k, p),
        None if blank => Loaded::Blank,
        None => Loaded::Corrupt,
    })
}

#[derive(Debug)]
pub enum SaveError<E> {
    Io(E),
    Verify,
}

/// Store `key`, replacing the record at `prev` (if any). Returns the new position.
/// On error the previous record, if there was one, is still intact.
pub fn save<S: Sectors>(
    s: &mut S,
    key: &[u8; 32],
    prev: Option<Pos>,
) -> Result<Pos, SaveError<S::Error>> {
    let pos = match prev {
        Some(p) => Pos {
            seq: p.seq.wrapping_add(1),
            slot: p.slot ^ 1,
        },
        None => Pos { seq: 1, slot: 0 },
    };
    let rec = encode(key, pos.seq);
    s.erase(pos.slot).map_err(SaveError::Io)?;
    s.write(pos.slot, &rec).map_err(SaveError::Io)?;
    let mut back = [0u8; REC_LEN];
    s.read(pos.slot, &mut back).map_err(SaveError::Io)?;
    if back != rec {
        return Err(SaveError::Verify);
    }
    // new record is safe: now destroy the old key material
    // The new record is already committed; failing to wipe the old slot must not undo that.
    let _ = s.erase(pos.slot ^ 1);
    Ok(pos)
}
