//! Flash access for the PUF-secret backup sector (the format is in `puf_backup.rs`, the policy,
//! when to back up and when to restore, in `init_flash_key` in `main.rs`).

use alloc::vec::Vec;
use core::cell::RefCell;

use super::flash_io;
use crate::keys::Fl;
use crate::layout::{BACKUP_START, PAGE};
use crate::puf_backup::Plan;

/// The whole backup sector, or `None` if it could not be read (never taken for a blank sector).
pub fn read(flash: &RefCell<Fl>) -> Option<Vec<u8>> {
    let mut v = alloc::vec![0u8; PAGE];
    flash
        .borrow_mut()
        .blocking_read(BACKUP_START as u32, &mut v)
        .ok()?;
    Some(v)
}

/// Runs `plan` and reads the result back. False if it was `Full`, a flash operation failed or the
/// bytes read back differ.
pub fn apply(flash: &RefCell<Fl>, plan: &Plan) -> bool {
    let mut f = flash.borrow_mut();
    let (offset, data) = match plan {
        Plan::Nothing => return true,
        Plan::Full | Plan::Refuse => return false,
        Plan::Append { offset, data } => (*offset, data),
        Plan::Format { data } => {
            // Blank, torn or legacy sector (`puf_backup::classify`): nothing in it can be opened, so erasing
            // loses nothing. A damaged sector never gets here (`Plan::Refuse`).
            if flash_io::erase(&mut f, BACKUP_START, PAGE).is_err() {
                return false;
            }
            (0, data)
        }
    };
    if flash_io::program(&mut f, BACKUP_START + offset, data).is_err() {
        return false;
    }
    let mut back = alloc::vec![0u8; data.len()];
    f.blocking_read((BACKUP_START + offset) as u32, &mut back)
        .is_ok()
        && back == *data
}
