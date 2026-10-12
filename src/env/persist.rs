//! OpenSK `Persist` on top of the power-fail-safe `wasefire-store` key-value store.
//!
//! Only the four primitive accessors are implemented; everything else (PIN state, retry counters,
//! credentials, large blobs, attestation) uses OpenSK's default methods built on them.
//!
//! What this means for security: OpenSK keeps its key material and the PIN hash in this store in
//! clear. Anyone who can read the flash can read them (no secure element on the RP2040).
use alloc::boxed::Box;
use alloc::vec::Vec;
use defmt::{error, warn};
use opensk::api::persist::{Persist, PersistIter};
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};
use wasefire_store::{Store, StoreError};

use super::flash_store::FlashStorage;
use crate::keys::Fl;

pub struct PicoPersist {
    store: Store<FlashStorage>,
}

impl PicoPersist {
    /// Opens the store. An area that does not hold a valid store (first boot after the old
    /// firmware, or foreign data) is erased once and started empty; blank flash is already valid.
    pub fn new(flash: Fl) -> Self {
        let storage = FlashStorage::new(flash);
        let store = match Store::new(storage) {
            Ok(store) => store,
            Err((_, mut storage)) => {
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
        StoreError::NoCapacity | StoreError::NoLifetime => Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL,
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

impl Persist for PicoPersist {
    fn find(&self, key: usize) -> CtapResult<Option<Vec<u8>>> {
        self.store.find(key).map_err(convert)
    }

    fn insert(&mut self, key: usize, value: &[u8]) -> CtapResult<()> {
        self.store.insert(key, value).map_err(convert)
    }

    fn remove(&mut self, key: usize) -> CtapResult<()> {
        self.store.remove(key).map_err(convert)
    }

    fn iter(&self) -> CtapResult<PersistIter<'_>> {
        Ok(Box::new(self.store.iter().map_err(convert)?.map(
            |handle| match handle {
                Ok(handle) => Ok(handle.get_key()),
                Err(error) => Err(convert(error)),
            },
        )))
    }
}
