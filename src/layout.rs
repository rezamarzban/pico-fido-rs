//! Flash layout, from the end of flash downwards. build.rs keeps exactly this area (`RESERVED`)
//! out of the linker's FLASH region: change them together.
//!
//! ```text
//!   end of flash
//!   72 KiB   OpenSK key-value store                      (every value sealed, env/persist.rs)
//!    8 KiB   site directory sector A                     (every record sealed, env/dir_flash.rs)
//!    8 KiB   site directory sector B                     (every record sealed, env/dir_flash.rs)
//!   12 KiB   signature counter                           (every record sealed, env/tally_flash.rs)
//!    4 KiB   SRAM-PUF helper data                        (public by design, puf.rs)
//!    4 KiB   backup of the PUF secret, one record per chip (sealed with the chip's slot-0 public key, puf_backup.rs)
//!   ---- 108 KiB in total ----
//!   firmware image
//! ```
//!
//! The directory sectors and the counter are larger than before (they were 4 KiB each) because every
//! record carries a 12-byte nonce and a 16-byte GCM tag (`seal::OVERHEAD`): the plaintext log formats
//! of `se/dirlog.rs` and `se/tallylog.rs` are unchanged, `sealed_log.rs` maps them onto these sectors.

use crate::{FLASH_SIZE, STORE_PAGES};

pub const PAGE: usize = 4096;
/// Start of the memory-mapped flash (XIP window).
pub const XIP_BASE: usize = 0x1000_0000;

pub const STORE_BYTES: usize = STORE_PAGES * PAGE;
pub const STORE_START: usize = FLASH_SIZE - STORE_BYTES;

/// One sealed site-directory sector (a logical 4 KiB `dirlog` page of 127 records of 32 bytes).
pub const DIR_PHYS: usize = 2 * PAGE;
pub const DIR_A_START: usize = STORE_START - DIR_PHYS;
pub const DIR_B_START: usize = DIR_A_START - DIR_PHYS;

/// The sealed signature counter (a logical 4 KiB `tallylog` page of 255 records of 16 bytes).
pub const TALLY_PHYS: usize = 3 * PAGE;
pub const TALLY_START: usize = DIR_B_START - TALLY_PHYS;

/// SRAM-PUF helper sector.
pub const PUF_START: usize = TALLY_START - PAGE;

/// Backup of the PUF secret. It lies BELOW the helper sector, outside the area that the first start
/// wipes (`PUF_START + PAGE ..`), so a lost helper sector does not take the backup with it.
pub const BACKUP_START: usize = PUF_START - PAGE;

/// Everything from `BACKUP_START` to the end of flash is outside the firmware image.
pub const RESERVED: usize = FLASH_SIZE - BACKUP_START;
const _: () = core::assert!(RESERVED == 108 * 1024, "build.rs reserves 108 KiB");
