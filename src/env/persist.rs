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
//! The store takes at most 1023 bytes per entry, which leaves 994 bytes of plaintext once sealed.
//! A longer value (OpenSK's large-blob shards are 1023 bytes) is split in two entries, the second
//! at `key + 2048`, written in one store transaction (`spill.rs`); the continuation keys are hidden
//! from `iter`. Values over 1988 bytes are refused with `CTAP2_ERR_KEY_STORE_FULL`.
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::RefCell;
use defmt::{error, warn};
use opensk::api::persist::{Persist, PersistIter};
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};
use wasefire_store::{Store, StoreError, StoreUpdate};

use super::flash_store::FlashStorage;
use crate::keys::Fl;
use crate::puf;
use crate::seal::{Domain, OVERHEAD};
use crate::spill::{self, Op, FORMAT_HEAD, FORMAT_WHOLE, SPILL};

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

/// Associated data of an entry: which store key and which format it belongs to.
fn aad(key: usize, format: u8) -> [u8; 18] {
    let mut a = [0u8; 18];
    a[..13].copy_from_slice(b"pfrs/store/v2");
    a[13..17].copy_from_slice(&(key as u32).to_le_bytes());
    a[17] = format;
    a
}

/// `[format][nonce][ciphertext][tag]` for one store entry.
fn seal_entry(key: usize, format: u8, data: &[u8]) -> Vec<u8> {
    let sealer = puf::sealer(Domain::Store);
    let mut out = Vec::with_capacity(1 + OVERHEAD + data.len());
    out.push(format);
    out.extend_from_slice(&sealer.seal(&aad(key, format), data));
    out
}

/// The format and plaintext of one store entry.
fn open_entry(key: usize, blob: &[u8]) -> CtapResult<(u8, Vec<u8>)> {
    let format = match blob.first() {
        Some(&f) if f == FORMAT_WHOLE || f == FORMAT_HEAD => f,
        _ => {
            error!("flash: store entry {} is not a sealed value", key);
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE);
        }
    };
    let sealer = puf::sealer(Domain::Store);
    match sealer.open(&aad(key, format), &blob[1..]) {
        Some(v) => Ok((format, v)),
        None => {
            // Changed, moved or written under another key: nothing of it is used.
            error!("flash: store entry {} failed authentication", key);
            Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE)
        }
    }
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
        if key >= SPILL {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        let Some(blob) = self.store.find(key).map_err(convert)? else {
            return Ok(None);
        };
        let (format, head) = open_entry(key, &blob)?;
        if format == FORMAT_WHOLE {
            return Ok(Some(head));
        }
        // The first part of a long value: the rest must be there and be a whole entry.
        let tail = self.store.find(key + SPILL).map_err(convert)?;
        let Some(tail) = tail else {
            error!("flash: store entry {} lost its continuation", key);
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE);
        };
        match open_entry(key + SPILL, &tail)? {
            (FORMAT_WHOLE, tail) => Ok(Some(spill::join(&head, &tail))),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE),
        }
    }

    fn insert(&mut self, key: usize, value: &[u8]) -> CtapResult<()> {
        let spill_present = key < SPILL && self.store.find(key + SPILL).map_err(convert)?.is_some();
        let Some(ops) = spill::plan(key, value, spill_present) else {
            warn!("flash: value of {} bytes cannot be stored", value.len());
            return Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL);
        };
        let updates: Vec<StoreUpdate<Vec<u8>>> = ops
            .iter()
            .map(|op| match op {
                Op::Put { key, format, data } => StoreUpdate::Insert {
                    key: *key,
                    value: seal_entry(*key, *format, data),
                },
                Op::Remove { key } => StoreUpdate::Remove { key: *key },
            })
            .collect();
        self.store.transaction(&updates).map_err(convert)
    }

    fn remove(&mut self, key: usize) -> CtapResult<()> {
        let mut updates: Vec<StoreUpdate<Vec<u8>>> = alloc::vec![StoreUpdate::Remove { key }];
        if key < SPILL && self.store.find(key + SPILL).map_err(convert)?.is_some() {
            updates.push(StoreUpdate::Remove { key: key + SPILL });
        }
        self.store.transaction(&updates).map_err(convert)
    }

    fn iter(&self) -> CtapResult<PersistIter<'_>> {
        // The continuation entries (keys from SPILL on) are not OpenSK's keys.
        Ok(Box::new(
            self.store
                .iter()
                .map_err(convert)?
                .map(|handle| match handle {
                    Ok(handle) => Ok(handle.get_key()),
                    Err(error) => Err(convert(error)),
                })
                .filter(|k| !matches!(k, Ok(k) if *k >= SPILL)),
        ))
    }
}
