//! OpenSK `Persist` on top of the power-fail-safe `wasefire-store` key-value store, with **every
//! value sealed with AES-256-GCM** under a key derived from the SRAM PUF (`seal.rs`, `puf.rs`).
//!
//! Only the four primitive accessors are implemented; everything else (PIN state, retry counters,
//! credentials, large blobs, attestation) uses OpenSK's default methods built on them, so the PIN
//! hash, the master keys that encrypt credential IDs, resident-credential data, the attestation
//! certificate and the counters are all ciphertext in flash. A stored value is
//! `[format 1][nonce 12][ciphertext][GCM tag 16]` (29 bytes more than the plaintext); the store
//! key (id) is the associated data, so a value moved to another key fails authentication.
//!
//! Not hidden: the store key ids and the value lengths (a resident credential is visible as "an
//! entry of about this size"), and when entries are written. The private keys of the credentials are
//! not in the store at all (they are in the secure element); a credential ID only holds a slot handle.
//!
//! The store takes values of at most 1023 bytes. OpenSK's large-blob shards (`keys::LARGE_BLOB_SHARDS`)
//! are exactly that long, so once sealed they no longer fit: a sealed shard is split over two
//! entries, the second one under `key + OVERFLOW_OFFSET` (format byte 2), written in ONE store
//! transaction so a power cut leaves the old or the new shard. `iter()` hides the second entries
//! and `remove` deletes both. Any other value longer than `MAX_PLAIN` (994 bytes) is refused with
//! `CTAP2_ERR_KEY_STORE_FULL` (OpenSK has none).
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::RefCell;
use defmt::{error, warn};
use opensk::api::persist::{keys, Persist, PersistIter};
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};
use wasefire_store::{Store, StoreError, StoreUpdate};

use super::flash_store::FlashStorage;
use crate::keys::Fl;
use crate::puf;
use crate::seal::{Domain, OVERHEAD};

pub struct PicoPersist {
    store: Store<FlashStorage>,
}

impl PicoPersist {
    /// Opens the store. An area that does not hold a valid store (first boot after the old
    /// firmware, or foreign data) is erased once and started empty; blank flash is already valid.
    pub fn new(flash: &'static RefCell<Fl>) -> Self {
        let storage = FlashStorage::new(flash);
        let store = match Store::new(storage) {
            Ok(store) => store,
            // A flash I/O or argument error says nothing about the data: never erase the store
            // (credentials, pending reset marker) because of it. Stop; a re-plug retries.
            Err((StoreError::StorageError, _)) => defmt::panic!(
                "flash: I/O error opening the key-value store - not formatting, re-plug"
            ),
            Err((
                StoreError::InvalidArgument | StoreError::NoCapacity | StoreError::NoLifetime,
                _,
            )) => {
                defmt::panic!(
                    "flash: unexpected error opening the key-value store - not formatting"
                )
            }
            // InvalidStorage: foreign data, the layout of an older firmware, or corruption (the
            // store cannot tell them apart). Only this case is erased and started empty.
            Err((StoreError::InvalidStorage, mut storage)) => {
                warn!("flash: no valid key-value store found, formatting the store area");
                if storage.format().is_err() {
                    defmt::panic!("flash: cannot erase the store area");
                }
                match Store::new(storage) {
                    Ok(store) => store,
                    Err(_) => defmt::panic!("flash: cannot create the key-value store"),
                }
            }
        };
        PicoPersist { store }
    }
}

/// Same mapping as OpenSK's own `From<StoreError>` (which is only compiled with its `std` feature).
fn convert(error: StoreError) -> Ctap2StatusCode {
    match error {
        // Expected: the store is full or the flash is out of life.
        StoreError::NoCapacity | StoreError::NoLifetime => {
            Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL
        }
        // Expected if a precondition is violated (e.g. a value that is too long).
        StoreError::InvalidArgument => Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR,
        // Not expected: the storage has been tampered with.
        StoreError::InvalidStorage => {
            error!("flash: store reports invalid storage");
            Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE
        }
        // Not expected: the flash driver failed.
        StoreError::StorageError => Ctap2StatusCode::CTAP1_ERR_OTHER,
    }
}

/// Format byte of a sealed value stored in one entry / in two entries (see the module documentation).
const FORMAT_ONE: u8 = 1;
const FORMAT_SPLIT: u8 = 2;
/// The longest value the key-value store takes (OpenSK's own `VALUE_LENGTH`).
const STORE_MAX_VALUE: usize = 1023;
/// The longest plaintext that still fits one entry once sealed.
const MAX_PLAIN: usize = STORE_MAX_VALUE - 1 - OVERHEAD;
/// A large-blob shard may be one entry longer than it is in plain form: its second part is stored
/// at `key + OVERFLOW_OFFSET`. OpenSK keeps 0 and 2048+ free ("reserved for migration"): 3000..3004
/// are not used by it (api/persist/keys.rs).
const OVERFLOW_OFFSET: usize = 1000;

fn is_shard(key: usize) -> bool {
    keys::LARGE_BLOB_SHARDS.contains(&key)
}

fn is_overflow(key: usize) -> bool {
    key >= keys::LARGE_BLOB_SHARDS.start + OVERFLOW_OFFSET
        && key < keys::LARGE_BLOB_SHARDS.end + OVERFLOW_OFFSET
}

/// Associated data of a value: which store key it belongs to.
fn aad(key: usize) -> [u8; 17] {
    let mut a = [0u8; 17];
    a[..13].copy_from_slice(b"pfrs/store/v1");
    a[13..].copy_from_slice(&(key as u32).to_le_bytes());
    a
}

/// The sealed form of a value: `[format][nonce][ciphertext][tag]`.
fn seal_value(key: usize, value: &[u8]) -> CtapResult<Vec<u8>> {
    let longest = if is_shard(key) {
        2 * STORE_MAX_VALUE - 1 - OVERHEAD
    } else {
        MAX_PLAIN
    };
    if value.len() > longest {
        warn!("flash: value of {} bytes is too long to be sealed", value.len());
        return Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL);
    }
    let sealer = puf::sealer(Domain::Store);
    let mut out = Vec::with_capacity(1 + OVERHEAD + value.len());
    out.push(if 1 + OVERHEAD + value.len() > STORE_MAX_VALUE {
        FORMAT_SPLIT
    } else {
        FORMAT_ONE
    });
    out.extend_from_slice(&sealer.seal(&aad(key), value));
    Ok(out)
}

/// Opens a sealed value; `rest` is the second entry of a split one.
fn open_value(key: usize, blob: &[u8], rest: Option<&[u8]>) -> CtapResult<Vec<u8>> {
    let fail = |why: &str| {
        error!("flash: store entry {} {}", key, why);
        Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE
    };
    let joined: Vec<u8>;
    let body: &[u8] = match (blob.first(), rest) {
        (Some(&FORMAT_ONE), _) => &blob[1..],
        (Some(&FORMAT_SPLIT), Some(r)) => {
            let mut j = Vec::with_capacity(blob.len() - 1 + r.len());
            j.extend_from_slice(&blob[1..]);
            j.extend_from_slice(r);
            joined = j;
            &joined
        }
        _ => return Err(fail("is not a sealed value")),
    };
    let sealer = puf::sealer(Domain::Store);
    // Changed, moved or written under another key: nothing of it is used.
    sealer
        .open(&aad(key), body)
        .ok_or_else(|| fail("failed authentication"))
}

impl PicoPersist {
    /// (used, total, erase budget used, erase budget total) in store words, for the display.
    /// Reads the store: call rarely.
    pub fn stats(&self) -> Option<(u32, u32, u32, u32)> {
        let c = self.store.capacity().ok()?;
        let l = self.store.lifetime().ok()?;
        Some((
            c.used() as u32,
            c.total() as u32,
            l.used() as u32,
            l.total() as u32,
        ))
    }
}

impl Persist for PicoPersist {
    fn find(&self, key: usize) -> CtapResult<Option<Vec<u8>>> {
        let Some(blob) = self.store.find(key).map_err(convert)? else {
            return Ok(None);
        };
        let rest = if blob.first() == Some(&FORMAT_SPLIT) {
            self.store.find(key + OVERFLOW_OFFSET).map_err(convert)?
        } else {
            None
        };
        Ok(Some(open_value(key, &blob, rest.as_deref())?))
    }

    fn insert(&mut self, key: usize, value: &[u8]) -> CtapResult<()> {
        let blob = seal_value(key, value)?;
        if blob[0] == FORMAT_SPLIT {
            // First entry full, the rest in the second one: one transaction (all or nothing).
            self.store
                .transaction(&[
                    StoreUpdate::Insert {
                        key,
                        value: &blob[..STORE_MAX_VALUE],
                    },
                    StoreUpdate::Insert {
                        key: key + OVERFLOW_OFFSET,
                        value: &blob[STORE_MAX_VALUE..],
                    },
                ])
                .map_err(convert)
        } else if is_shard(key) {
            // A shard that fits one entry again: drop a second part left by an earlier, longer one.
            self.store
                .transaction(&[
                    StoreUpdate::Insert { key, value: &blob[..] },
                    StoreUpdate::Remove {
                        key: key + OVERFLOW_OFFSET,
                    },
                ])
                .map_err(convert)
        } else {
            self.store.insert(key, &blob).map_err(convert)
        }
    }

    fn remove(&mut self, key: usize) -> CtapResult<()> {
        if is_shard(key) {
            self.store
                .transaction(&[
                    StoreUpdate::<&[u8]>::Remove { key },
                    StoreUpdate::Remove {
                        key: key + OVERFLOW_OFFSET,
                    },
                ])
                .map_err(convert)
        } else {
            self.store.remove(key).map_err(convert)
        }
    }

    fn iter(&self) -> CtapResult<PersistIter<'_>> {
        Ok(Box::new(
            self.store
                .iter()
                .map_err(convert)?
                .map(|handle| match handle {
                    Ok(handle) => Ok(handle.get_key()),
                    Err(error) => Err(convert(error)),
                })
                // The second parts of split shards belong to their first entry.
                .filter(|k| !matches!(k, Ok(k) if is_overflow(*k))),
        ))
    }
}
