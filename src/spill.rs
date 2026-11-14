//! Values longer than one store entry (pure logic, host-tested; `env/persist.rs` seals and stores).
//!
//! The key-value store takes at most 1023 bytes per entry, and sealing takes `1 + OVERHEAD` of
//! them, so one entry holds `CHUNK` = 994 bytes of plaintext. OpenSK's large-blob shards are 1023
//! bytes. A longer value (up to `MAX_LEN` = 2 * CHUNK) is split in two: the first `CHUNK` bytes go
//! in the entry of its own key (marked `FORMAT_HEAD`), the rest in a second entry whose key is
//! `key + SPILL`. OpenSK's keys are all below `SPILL` (1..2048) and the store's keys go up to 4095,
//! so the continuation keys are free; `env/persist.rs` hides them from `iter` and writes both
//! entries in ONE store transaction (all or nothing), also when a long value is replaced by a short
//! one (the continuation is removed in the same transaction).

use crate::seal::OVERHEAD;
use alloc::vec::Vec;

/// Offset of the key of a continuation entry.
pub const SPILL: usize = 2048;
/// A whole value in one entry.
pub const FORMAT_WHOLE: u8 = 1;
/// The first `CHUNK` bytes of a value that continues at `key + SPILL`.
pub const FORMAT_HEAD: u8 = 2;
/// The longest value the store takes in one entry.
pub const STORE_MAX_VALUE: usize = 1023;
/// Plaintext bytes in one entry (format byte and sealing overhead taken off).
pub const CHUNK: usize = STORE_MAX_VALUE - 1 - OVERHEAD;
pub const MAX_LEN: usize = 2 * CHUNK;

/// One store operation of a transaction (the data is still plaintext).
#[derive(Debug, PartialEq, Eq)]
pub enum Op<'a> {
    Put {
        key: usize,
        format: u8,
        data: &'a [u8],
    },
    Remove {
        key: usize,
    },
}

/// The operations that store `value` under `key`. `spill_present`: the store already holds a
/// continuation entry for this key (it is removed if the new value is short). `None`: the key or the
/// value is out of range.
pub fn plan(key: usize, value: &[u8], spill_present: bool) -> Option<Vec<Op<'_>>> {
    if key >= SPILL || value.len() > MAX_LEN {
        return None;
    }
    if value.len() <= CHUNK {
        let mut ops = alloc::vec![Op::Put {
            key,
            format: FORMAT_WHOLE,
            data: value
        }];
        if spill_present {
            ops.push(Op::Remove { key: key + SPILL });
        }
        Some(ops)
    } else {
        Some(alloc::vec![
            Op::Put {
                key,
                format: FORMAT_HEAD,
                data: &value[..CHUNK]
            },
            Op::Put {
                key: key + SPILL,
                format: FORMAT_WHOLE,
                data: &value[CHUNK..]
            },
        ])
    }
}

/// The value from its two parts.
pub fn join(head: &[u8], tail: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(head.len() + tail.len());
    v.extend_from_slice(head);
    v.extend_from_slice(tail);
    v
}
