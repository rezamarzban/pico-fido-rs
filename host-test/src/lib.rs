extern crate alloc;
#[path = "../../src/cbor.rs"] pub mod cbor;
#[path = "../../src/ctap.rs"] pub mod ctap;
#[path = "../../src/ctaphid.rs"] pub mod ctaphid;
#[path = "../../src/health.rs"] pub mod health;
#[path = "../../src/pin.rs"] pub mod pin;
#[path = "../../src/store.rs"] pub mod store;
#[path = "../../src/wrap.rs"] pub mod wrap;
use ctap::*;
use rand::RngCore;
use std::panic::{catch_unwind, AssertUnwindSafe};
use store::{Pos, Record, Replaced, Saved, Vault};

/// In-RAM stand-in for the flash (the FFI and the CTAP-level tests use it).
/// `mode`: 0 = replace works, 1 = replace fails and the previous record stays, 2 = replace fails
/// and the flash state is unknowable.
pub struct RamVault { pub rec: Option<Record>, pub used: u8, pub mode: u8 }
impl RamVault { pub fn new(rec: Option<Record>) -> Self { RamVault { rec, used: 0, mode: 0 } } }
impl Vault for RamVault {
    fn replace(&mut self, rec: &Record) -> Replaced {
        match self.mode {
            1 => match &self.rec { Some(r) => Replaced::Kept(r.clone()), None => Replaced::NoKey },
            2 => Replaced::Unknown,
            _ => { self.rec = Some(rec.clone()); Replaced::New(Saved { pos: Pos { seq: 1, slot: 0 }, old_wiped: true }) }
        }
    }
    fn tries_used(&mut self) -> Result<u8, ()> { Ok(self.used) }
    fn begin_try(&mut self) -> Result<usize, ()> { if self.used >= 8 { Err(()) } else { self.used += 1; Ok(0) } }
    fn finish_try(&mut self, _page: usize) -> Result<(), ()> { self.used = 0; Ok(()) }
    fn clear_tries(&mut self) -> Result<(), ()> { self.used = 0; Ok(()) }
}

pub struct Handle { ctap: Ctap, vault: RamVault }

/// `master` may be NULL: simulates unreadable/corrupt key storage (fault mode).
#[no_mangle] pub extern "C" fn ctap_new(master: *const u8) -> *mut Handle {
    let rec = if master.is_null() { None } else {
        let mut m = [0u8; 32]; m.copy_from_slice(unsafe { std::slice::from_raw_parts(master, 32) }); Some(Record::plain(m))
    };
    Box::into_raw(Box::new(Handle { ctap: Ctap::new(rec.clone()), vault: RamVault::new(rec) }))
}

/// Simulates unplugging and re-plugging: the RAM state is rebuilt from what is "in flash".
#[no_mangle] pub extern "C" fn ctap_reboot(h: *mut Handle) {
    if h.is_null() { return; }
    let h = unsafe { &mut *h };
    h.ctap = Ctap::new(h.vault.rec.clone());
}
#[no_mangle] pub extern "C" fn ctap_tick(h: *mut Handle, now_ms: u64) { if !h.is_null() { unsafe { &mut *h }.ctap.tick(now_ms) } }
#[no_mangle] pub extern "C" fn ctap_lock(h: *mut Handle) { if !h.is_null() { unsafe { &mut *h }.ctap.lock() } }
/// Failed PIN attempts persisted since the last correct PIN.
#[no_mangle] pub extern "C" fn ctap_tries_used(h: *mut Handle) -> i32 { if h.is_null() { -1 } else { unsafe { &*h }.vault.used as i32 } }

/// Returns response length (>=1), -1 = needs user presence, -2 = invalid arguments / output too small, -3 = panic.
#[no_mangle] pub extern "C" fn ctap_handle(h: *mut Handle, req: *const u8, n: usize, up: i32, now_ms: u64, out: *mut u8, cap: usize) -> i32 {
    if h.is_null() || out.is_null() || cap == 0 || (req.is_null() && n != 0) { return -2; }
    let h = unsafe { &mut *h };
    let req: &[u8] = if n == 0 { &[] } else { unsafe { std::slice::from_raw_parts(req, n) } };
    let o = unsafe { std::slice::from_raw_parts_mut(out, cap) };
    let r = catch_unwind(AssertUnwindSafe(|| {
        let mut rng = |b: &mut [u8]| rand::thread_rng().fill_bytes(b);
        match h.ctap.handle(req, up != 0, now_ms, &mut rng, &mut h.vault) {
            Resp::NeedUp => -1,
            Resp::Err(e) => { o[0] = e; 1 }
            Resp::Ok(v) => if v.len() > cap { -2 } else { o[..v.len()].copy_from_slice(&v); v.len() as i32 },
        }
    }));
    r.unwrap_or(-3)
}

#[cfg(test)]
mod hid_tests {
    use super::ctaphid::*;
    fn pk(cid: u32, cmd: u8, data: &[u8]) -> Pkt { frames(cid, cmd, data)[0] }
    fn bcast_init(h: &mut Hid, t: u64) -> u32 {
        let mut p = [0u8; 64];
        p[..4].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); p[4] = 0x80 | INIT; p[6] = 8; p[7..15].copy_from_slice(&[1,2,3,4,5,6,7,8]);
        let Rx::Reply(0xFFFF_FFFF, INIT, d) = h.rx(&p, t) else { panic!() };
        assert_eq!(&d[..8], &[1,2,3,4,5,6,7,8]); assert_eq!(d[16], 0x0C);
        u32::from_be_bytes(d[8..12].try_into().unwrap())
    }
    fn is_err(r: &Rx, cid: u32, code: u8) -> bool { matches!(r, Rx::Reply(c, ERROR, v) if *c == cid && v == &[code]) }

    #[test] fn init_and_cbor_multipacket() {
        let mut h = Hid::new();
        let cid = bcast_init(&mut h, 0); assert_eq!(cid, 1);
        let msg: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let fr = frames(cid, CBOR, &msg); assert_eq!(fr.len(), 1 + (300 - 57 + 58) / 59);
        let rs: Vec<Rx> = fr.iter().map(|p| h.rx(p, 10)).collect();
        for r in &rs[..rs.len()-1] { assert!(matches!(r, Rx::None)); }
        let Rx::Cbor(c, got) = rs.into_iter().last().unwrap() else { panic!() };
        assert_eq!((c, got), (cid, msg));
    }
    #[test] fn busy_and_cancel_while_active() {
        let mut h = Hid::new(); let a = bcast_init(&mut h, 0); let b = bcast_init(&mut h, 0);
        assert!(matches!(h.rx(&pk(a, CBOR, &[4]), 0), Rx::Cbor(..)));
        assert!(is_err(&h.rx(&pk(b, PING, b"x"), 0), b, 6));
        assert!(matches!(h.rx(&pk(a, CANCEL, &[]), 0), Rx::Cancel));
        h.end();
        assert!(matches!(h.rx(&pk(b, PING, b"x"), 0), Rx::Reply(_, PING, _)));
    }
    #[test] fn unallocated_channel_rejected() {
        let mut h = Hid::new();
        assert!(is_err(&h.rx(&pk(99, PING, b"x"), 0), 99, 0x0B));
        assert!(is_err(&h.rx(&pk(0xFFFF_FFFF, PING, b"x"), 0), 0xFFFF_FFFF, 0x0B));
        let mut p = pk(99, INIT, &[0; 8]); p[4] = 0x80 | INIT;       // INIT on a channel we never allocated
        assert!(is_err(&h.rx(&p, 0), 99, 0x0B));
        let mut p = pk(5, CBOR, &[]); p[4] = 0; assert!(matches!(h.rx(&p, 0), Rx::None)); // stray continuation
    }
    #[test] fn stalled_message_times_out() {
        let mut h = Hid::new(); let a = bcast_init(&mut h, 0); let b = bcast_init(&mut h, 0);
        let long = vec![0u8; 200]; let fr = frames(a, PING, &long);
        assert!(matches!(h.rx(&fr[0], 0), Rx::None));
        assert!(is_err(&h.rx(&pk(b, PING, b"x"), 100), b, 6));                 // still busy at 100 ms
        assert!(matches!(h.rx(&pk(b, PING, b"x"), 700), Rx::Reply(_, PING, _))); // stale message dropped at 700 ms
        assert!(is_err(&h.rx(&fr[1], 750), a, 4) || matches!(h.rx(&fr[1], 750), Rx::None)); // late continuation never completes it
        // continuation arriving after the deadline is answered with ERR_MSG_TIMEOUT
        let mut h = Hid::new(); let a = bcast_init(&mut h, 0);
        let fr = frames(a, PING, &long);
        h.rx(&fr[0], 0); assert!(is_err(&h.rx(&fr[1], 900), a, 5));
        // a message whose packets keep arriving in time is fine
        let mut h = Hid::new(); let a = bcast_init(&mut h, 0);
        let fr = frames(a, PING, &long); let mut t = 0; let mut last = Rx::None;
        for p in &fr { last = h.rx(p, t); t += 400; }
        assert!(matches!(last, Rx::Reply(_, PING, ref d) if d.len() == 200));
    }
    #[test] fn same_channel_init_aborts_active_transaction() {
        let mut h = Hid::new(); let a = bcast_init(&mut h, 0);
        assert!(matches!(h.rx(&pk(a, CBOR, &[4]), 0), Rx::Cbor(..)));
        let mut p = [0u8; 64]; p[..4].copy_from_slice(&a.to_be_bytes()); p[4] = 0x80 | INIT; p[6] = 8; p[7..15].copy_from_slice(&[9; 8]);
        assert!(matches!(h.rx(&p, 5), Rx::Reply(c, INIT, _) if c == a));
        assert!(h.take_abort()); assert!(!h.take_abort());
        assert!(matches!(h.rx(&pk(a, CBOR, &[4]), 6), Rx::Cbor(..)));     // channel usable again
        // a *broadcast* INIT must not abort anyone
        bcast_init(&mut h, 7); assert!(!h.take_abort());
        assert!(matches!(h.rx(&pk(a, CANCEL, &[]), 8), Rx::Cancel));
    }
    #[test] fn same_channel_init_drops_partial_message() {
        let mut h = Hid::new(); let a = bcast_init(&mut h, 0);
        let fr = frames(a, PING, &vec![1u8; 200]); h.rx(&fr[0], 0);
        let mut p = [0u8; 64]; p[..4].copy_from_slice(&a.to_be_bytes()); p[4] = 0x80 | INIT; p[6] = 8;
        h.rx(&p, 1); assert!(matches!(h.rx(&fr[1], 2), Rx::None));
    }
    #[test] fn channel_ids_unique_and_bounded() {
        let mut h = Hid::new(); let mut seen = std::collections::HashSet::new();
        for i in 0..40 { let c = bcast_init(&mut h, i); assert!(c != 0 && c != 0xFFFF_FFFF && seen.insert(c)); }
        let last = bcast_init(&mut h, 99); assert!(matches!(h.rx(&pk(last, PING, b"x"), 99), Rx::Reply(..)));
        assert!(is_err(&h.rx(&pk(1, PING, b"x"), 99), 1, 0x0B)); // oldest evicted
    }
    #[test] fn bad_seq_oversize_msg_wink() {
        let mut h = Hid::new(); let a = bcast_init(&mut h, 0);
        let mut fr = frames(a, PING, &vec![0u8; 200]); fr[1][4] = 3;
        assert!(matches!(h.rx(&fr[0], 0), Rx::None)); assert!(is_err(&h.rx(&fr[1], 0), a, 4));
        let mut p = [0u8; 64]; p[..4].copy_from_slice(&a.to_be_bytes()); p[4] = 0x80 | CBOR; p[5] = 0x20;
        assert!(is_err(&h.rx(&p, 0), a, 3));
        assert!(is_err(&h.rx(&pk(a, MSG, &[0]), 0), a, 1));
        assert!(is_err(&h.rx(&pk(a, 0x08, &[]), 0), a, 1)); // WINK is not supported
    }

    #[test] fn cancel_is_ignored_unless_it_targets_the_active_transaction() {
        let mut h = Hid::new(); let a = bcast_init(&mut h, 0); let b = bcast_init(&mut h, 0);
        // nothing running: ignored, no error reply
        assert!(matches!(h.rx(&pk(a, CANCEL, &[]), 0), Rx::None));
        // unknown channel and broadcast: ignored as well
        assert!(matches!(h.rx(&pk(77, CANCEL, &[]), 0), Rx::None));
        assert!(matches!(h.rx(&pk(0xFFFF_FFFF, CANCEL, &[]), 0), Rx::None));
        // running on `a`: a CANCEL from `b` must not cancel it and must not produce CHANNEL_BUSY
        assert!(matches!(h.rx(&pk(a, CBOR, &[4]), 0), Rx::Cbor(..)));
        assert!(matches!(h.rx(&pk(b, CANCEL, &[]), 0), Rx::None));
        assert!(matches!(h.rx(&pk(a, CANCEL, &[]), 0), Rx::Cancel));
        h.end();
        // a cancel in between does not disturb a partly received message on another channel
        let fr = frames(b, PING, &vec![1u8; 100]);
        assert!(matches!(h.rx(&fr[0], 10), Rx::None));
        assert!(matches!(h.rx(&pk(a, CANCEL, &[]), 11), Rx::None));
        assert!(matches!(h.rx(&fr[1], 12), Rx::Reply(_, PING, ref d) if d.len() == 100));
    }
    #[test] fn cancel_with_payload_is_invalid_length() {
        let mut h = Hid::new(); let a = bcast_init(&mut h, 0);
        let mut p = pk(a, CANCEL, &[]); p[6] = 1;
        assert!(is_err(&h.rx(&p, 0), a, 3));
    }
    #[test] fn zero_length_cbor_is_rejected_by_framing() {
        let mut h = Hid::new(); let a = bcast_init(&mut h, 0);
        assert!(is_err(&h.rx(&pk(a, CBOR, &[]), 0), a, 3));
        // and it did not become an active transaction
        assert!(matches!(h.rx(&pk(a, PING, b"x"), 1), Rx::Reply(_, PING, _)));
        // zero-length PING is legal
        assert!(matches!(h.rx(&pk(a, PING, &[]), 2), Rx::Reply(_, PING, ref d) if d.is_empty()));
    }
    #[test] fn eviction_never_takes_active_channel_and_clears_partial_message() {
        let mut h = Hid::new();
        let first = bcast_init(&mut h, 0);
        // `first` is running a transaction while 8 more clients show up
        assert!(matches!(h.rx(&pk(first, CBOR, &[4]), 0), Rx::Cbor(..)));
        for i in 0..8 { bcast_init(&mut h, 1 + i); }
        h.end();
        assert!(matches!(h.rx(&pk(first, PING, b"x"), 20), Rx::Reply(..)), "active channel must survive eviction");
        // a channel with a partly received message is never evicted either, and nothing is stranded
        let mut h = Hid::new();
        let ids: Vec<u32> = (0..8).map(|i| bcast_init(&mut h, i)).collect();
        let fr = frames(ids[0], PING, &vec![5u8; 200]);
        assert!(matches!(h.rx(&fr[0], 100), Rx::None));
        let newc = bcast_init(&mut h, 101);                               // 9th channel: someone else is evicted
        assert!(matches!(h.rx(&fr[1], 102), Rx::None));                   // ids[0] still owns its message
        assert!(is_err(&h.rx(&pk(newc, PING, b"x"), 103), newc, 6));      // busy while ids[0] assembles
        assert!(matches!(h.rx(&fr[2], 104), Rx::None));
        assert!(matches!(h.rx(&fr[3], 105), Rx::Reply(_, PING, ref d) if d.len() == 200));
    }
    #[test] fn recently_used_channels_are_evicted_last() {
        let mut h = Hid::new();
        let ids: Vec<u32> = (0..8).map(|i| bcast_init(&mut h, i)).collect();
        assert!(matches!(h.rx(&pk(ids[0], PING, b"x"), 10), Rx::Reply(..))); // ids[0] is now the newest
        bcast_init(&mut h, 11);                                               // evicts ids[1], not ids[0]
        assert!(matches!(h.rx(&pk(ids[0], PING, b"x"), 12), Rx::Reply(..)));
        assert!(is_err(&h.rx(&pk(ids[1], PING, b"x"), 12), ids[1], 0x0B));
    }
}

#[cfg(test)]
mod cbor_tests {
    use super::cbor::{validate, W};
    #[test] fn accepts_valid() {
        assert!(validate(&[0xa1, 0x01, 0x41, 0x00]).is_ok());
        assert!(validate(&[0xa2, 0x01, 0xf5, 0x02, 0xf6]).is_ok());                    // true / null
        assert!(validate(&[0xa1, 0x01, 0x81, 0x81, 0x81, 0x00]).is_ok());              // depth 4
        // canonical order: shorter encoded key first, equal lengths bytewise; int and text keys mixed
        assert!(validate(&[0xa3, 0x01, 0x00, 0x18, 0x63, 0x00, 0x61, 0x61, 0x00]).is_ok());
        assert!(validate(&[0xa3, 0x01, 0x00, 0x18, 0x63, 0x00, 0x62, 0x61, 0x61, 0x00]).is_ok());
    }
    #[test] fn floats_and_simple_values_are_allowed_in_unknown_fields() {
        assert!(validate(&[0xa1, 0x01, 0xf9, 0x3c, 0x00]).is_ok());                    // float16 1.0
        assert!(validate(&[0xa1, 0x01, 0xfa, 0x3f, 0x80, 0x00, 0x00]).is_ok());        // float32
        assert!(validate(&[0xa1, 0x01, 0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0]).is_ok());  // float64
        assert!(validate(&[0xa1, 0x01, 0x81, 0xf9, 0x00, 0x00]).is_ok());              // inside an array
        assert!(validate(&[0xa1, 0x01, 0xf7]).is_ok());                                // undefined
        assert_eq!(validate(&[0xa1, 0x01, 0xf9, 0x00]), Err(0x12));                    // truncated float
        assert_eq!(validate(&[0xa1, 0x01, 0xf8, 0x20]), Err(0x12));                    // unassigned simple value
        assert_eq!(validate(&[0xa1, 0x01, 0xff]), Err(0x12));                          // stray break
    }
    #[test] fn rejects_bad() {
        assert_eq!(validate(&[0xa1, 0x18, 0x01, 0x00]), Err(0x12));                    // non-minimal key
        assert_eq!(validate(&[0xa1, 0x01, 0x19, 0x00, 0x05]), Err(0x12));              // non-minimal value
        assert_eq!(validate(&[0xa1, 0x01, 0x58, 0x01, 0x00]), Err(0x12));              // non-minimal length
        assert_eq!(validate(&[0xa2, 0x01, 0x00, 0x01, 0x01]), Err(0x12));              // duplicate key
        assert_eq!(validate(&[0xa1, 0x01, 0x00, 0x00]), Err(0x12));                    // trailing byte
        assert_eq!(validate(&[0xa1, 0x01, 0xc1, 0x00]), Err(0x12));                    // tag
        assert_eq!(validate(&[0xa1, 0x01, 0x81, 0x81, 0x81, 0x81, 0x00]), Err(0x12));  // depth 5
        assert_eq!(validate(&[0xa1, 0x01, 0x9f, 0xff]), Err(0x12));                    // indefinite
        assert_eq!(validate(&[0xa1, 0x01, 0x62, 0xff, 0xff]), Err(0x12));              // bad UTF-8
        assert_eq!(validate(&[0xa1, 0x01]), Err(0x12));                                // truncated
        assert_eq!(validate(&[0xa1]), Err(0x12));                                      // truncated, no key
        assert_eq!(validate(&[0x80]), Err(0x11));                                      // not a map
        assert_eq!(validate(&[]), Err(0x12));
        // duplicate key hidden in a nested map
        assert_eq!(validate(&[0xa1, 0x01, 0xa2, 0x61, 0x61, 0x00, 0x61, 0x61, 0x01]), Err(0x12));
    }
    #[test] fn map_keys_must_be_canonically_ordered() {
        assert_eq!(validate(&[0xa2, 0x02, 0x00, 0x01, 0x00]), Err(0x12));              // 2 before 1
        assert_eq!(validate(&[0xa2, 0x18, 0x63, 0x00, 0x04, 0x00]), Err(0x12));        // longer key first
        assert_eq!(validate(&[0xa2, 0x62, 0x62, 0x62, 0x00, 0x62, 0x61, 0x61, 0x00]), Err(0x12)); // "bb" before "aa"
        assert_eq!(validate(&[0xa2, 0x61, 0x62, 0x00, 0x61, 0x61, 0x00]), Err(0x12));  // "b" before "a"
        assert!(validate(&[0xa2, 0x61, 0x61, 0x00, 0x61, 0x62, 0x00]).is_ok());        // "a", "b"
        assert!(validate(&[0xa2, 0x04, 0x00, 0x18, 0x63, 0x00]).is_ok());              // short key first
        // ordering is enforced in nested maps, too
        assert_eq!(validate(&[0xa1, 0x01, 0xa2, 0x02, 0x00, 0x01, 0x00]), Err(0x12));
        assert!(validate(&[0xa1, 0x01, 0xa2, 0x01, 0x00, 0x02, 0x00]).is_ok());
    }
    #[test] fn map_keys_must_be_integers_or_text() {
        assert_eq!(validate(&[0xa1, 0x41, 0x00, 0x00]), Err(0x11));                    // byte string key
        assert_eq!(validate(&[0xa1, 0x80, 0x00]), Err(0x11));                          // array key
        assert_eq!(validate(&[0xa1, 0xa0, 0x00]), Err(0x11));                          // map key
        assert_eq!(validate(&[0xa1, 0xf5, 0x00]), Err(0x11));                          // bool key
        assert_eq!(validate(&[0xa1, 0x01, 0xa1, 0x80, 0x00]), Err(0x11));              // ... also nested
        assert!(validate(&[0xa1, 0x20, 0x00]).is_ok());                                // negative int key
    }
    #[test] fn writer_encodes_full_64_bit_range() {
        let enc = |v: u64| { let mut w = W::new(); w.uint(v); w.0 };
        assert_eq!(enc(23), [0x17]);
        assert_eq!(enc(24), [0x18, 24]);
        assert_eq!(enc(0xff), [0x18, 0xff]);
        assert_eq!(enc(0x100), [0x19, 0x01, 0x00]);
        assert_eq!(enc(0xffff), [0x19, 0xff, 0xff]);
        assert_eq!(enc(0x1_0000), [0x1a, 0, 1, 0, 0]);
        assert_eq!(enc(0xffff_ffff), [0x1a, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(enc(0x1_0000_0000), [0x1b, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(enc(u64::MAX), [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let mut w = W::new(); w.int(-1); w.int(i64::MIN); assert_eq!(w.0, [0x20, 0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    }
}

#[cfg(test)]
mod store_tests {
    use super::store::*;
    /// Flash simulator with fault injection.
    #[derive(Clone)]
    struct Mock {
        s: [Vec<u8>; 2],
        t: [u8; TRIES_PAGES],             // retry-counter sector
        ops: usize,                       // counts erase+write calls (key slots only)
        crash_at: Option<usize>,          // that op fails half-way and leaves junk (power loss)
        read_err: bool,                   // every read fails
        read_err_once_at: Option<usize>,  // only the n-th read (1-based) fails
        reads: usize,
        erase_fail_from: Option<usize>,   // from this op on, erase fails and leaves the sector UNTOUCHED
        stuck: [bool; 2],                 // erase and write on this slot fail, contents UNTOUCHED
        tries_dead: bool,                 // counter sector cannot be written
    }
    #[derive(Debug)] struct Fault;
    impl Mock {
        fn new() -> Self { Mock { s: [vec![0xFF; REC_LEN], vec![0xFF; REC_LEN]], t: [0xFF; TRIES_PAGES], ops: 0, crash_at: None, read_err: false, read_err_once_at: None, reads: 0, erase_fail_from: None, stuck: [false; 2], tries_dead: false } }
        fn tick(&mut self) -> bool { self.ops += 1; Some(self.ops) == self.crash_at }
    }
    impl Sectors for Mock {
        type Error = Fault;
        fn read(&mut self, slot: usize, buf: &mut [u8; REC_LEN]) -> Result<(), Fault> {
            self.reads += 1;
            if self.read_err || Some(self.reads) == self.read_err_once_at { return Err(Fault) }
            buf.copy_from_slice(&self.s[slot]); Ok(())
        }
        fn erase(&mut self, slot: usize) -> Result<(), Fault> {
            let crash = self.tick();
            if self.stuck[slot] { return Err(Fault) }
            if crash { self.s[slot][..20].fill(0); return Err(Fault) }             // power cut mid-erase leaves junk
            if matches!(self.erase_fail_from, Some(n) if self.ops >= n) { return Err(Fault) } // erase refused, old data intact
            self.s[slot].fill(0xFF); Ok(())
        }
        fn write(&mut self, slot: usize, rec: &[u8; REC_LEN]) -> Result<(), Fault> {
            let crash = self.tick();
            if self.stuck[slot] { return Err(Fault) }
            if crash { self.s[slot][..30].copy_from_slice(&rec[..30]); return Err(Fault) } // power cut mid-write: partial record
            for (d, n) in self.s[slot].iter_mut().zip(rec.iter()) { *d &= *n }       // flash programming can only clear bits
            Ok(())
        }
        fn tries_read(&mut self, out: &mut [u8; TRIES_PAGES]) -> Result<(), Fault> { if self.read_err { return Err(Fault) } *out = self.t; Ok(()) }
        fn tries_mark(&mut self, page: usize, val: u8) -> Result<(), Fault> { if self.tries_dead { return Err(Fault) } self.t[page] &= val; Ok(()) }
        fn tries_clear(&mut self) -> Result<(), Fault> { if self.tries_dead { return Err(Fault) } self.t = [0xFF; TRIES_PAGES]; Ok(()) }
    }
    const K1: [u8; 32] = [1; 32]; const K2: [u8; 32] = [2; 32]; const K3: [u8; 32] = [3; 32];
    fn r(k: [u8; 32]) -> Record { Record::plain(k) }
    fn active(m: &mut Mock) -> Option<[u8; 32]> { match load(m).unwrap() { Loaded::Rec(k, _) => Some(k.body), _ => None } }
    fn pos_of(m: &mut Mock) -> Pos { match load(m).unwrap() { Loaded::Rec(_, p) => p, o => panic!("{o:?}") } }

    #[test] fn blank_then_save_then_update() {
        let mut m = Mock::new(); assert_eq!(load(&mut m).unwrap(), Loaded::Blank);
        let p1 = save(&mut m, &r(K1)).unwrap(); assert_eq!(p1.pos, Pos { seq: 1, slot: 0 }); assert!(p1.old_wiped);
        assert_eq!(load(&mut m).unwrap(), Loaded::Rec(r(K1), p1.pos));
        let p2 = save(&mut m, &r(K2)).unwrap(); assert_eq!((p2.pos.seq, p2.pos.slot), (p1.pos.seq + 1, p1.pos.slot ^ 1));
        assert_eq!(load(&mut m).unwrap(), Loaded::Rec(r(K2), p2.pos));
        assert!(m.s[p1.pos.slot].iter().all(|&b| b == 0xFF), "old key must be wiped after a reset");
    }
    #[test] fn wrapped_record_round_trips_and_plain_key_is_not_in_flash() {
        let rec = Record { wrapped: true, m_kib: 96, t_cost: 24, salt: [7; 16], body: [0xAB; 32], tag: [0xCD; 32] };
        let mut m = Mock::new(); save(&mut m, &rec).unwrap();
        assert!(matches!(load(&mut m).unwrap(), Loaded::Rec(ref g, _) if *g == rec));
    }
    #[test] fn legacy_fk02_record_is_still_read_and_replaced() {
        use sha2::{Digest, Sha256};
        let mut raw = vec![0xFFu8; REC_LEN]; raw[..4].copy_from_slice(b"FK02"); raw[4..8].copy_from_slice(&5u32.to_le_bytes()); raw[8..40].copy_from_slice(&K1);
        let h = Sha256::digest(&raw[..40]); raw[40..56].copy_from_slice(&h[..16]);
        let mut m = Mock::new(); m.s[1] = raw;
        assert!(matches!(load(&mut m).unwrap(), Loaded::Rec(ref g, p) if *g == r(K1) && p.seq == 5 && p.slot == 1));
        assert!(matches!(replace_record(&mut m, &r(K2)), Replaced::New(s) if s.pos.seq == 6 && s.pos.slot == 0));
        assert_eq!(active(&mut m), Some(K2));
    }
    #[test] fn power_loss_at_every_step_never_loses_a_key_and_never_mixes() {
        for crash in 1..=6 {
            for start in [None, Some(())] {
                let mut m = Mock::new(); save(&mut m, &r(K1)).unwrap();
                if start.is_some() { save(&mut m, &r(K2)).unwrap(); }
                let old = if start.is_some() { K2 } else { K1 };
                m.ops = 0; m.crash_at = Some(crash);
                let res = replace_record(&mut m, &r(K3));
                m.crash_at = None;
                match load(&mut m).unwrap() { Loaded::Rec(k, _) => assert!(k.body == old || k.body == K3, "crash {crash}"), o => panic!("crash {crash}: {o:?}") }
                match res { Replaced::New(_) => assert_eq!(active(&mut m), Some(K3), "crash {crash}"),
                            Replaced::Kept(k) => assert_eq!(active(&mut m), Some(k.body), "crash {crash}"),
                            other => panic!("crash {crash}: {other:?}") }
            }
        }
    }
    #[test] fn corruption_is_detected_not_replaced() {
        let mut m = Mock::new(); let p = save(&mut m, &r(K1)).unwrap();
        m.s[p.pos.slot][40] ^= 1;                                       // bit flip inside the key
        assert_eq!(load(&mut m).unwrap(), Loaded::Corrupt);              // NOT Blank
        let mut m = Mock::new(); save(&mut m, &r(K1)).unwrap(); m.s[1] = vec![0x55; REC_LEN]; // junk in other slot
        assert_eq!(active(&mut m), Some(K1));                            // valid slot still used
        let mut m = Mock::new(); m.s[0] = vec![0; REC_LEN]; assert_eq!(load(&mut m).unwrap(), Loaded::Corrupt);
    }
    #[test] fn read_error_is_an_error_not_blank() {
        let mut m = Mock::new(); m.read_err = true; assert!(load(&mut m).is_err());
        assert!(save(&mut m, &r(K1)).is_err(), "an unreadable position is never treated as blank");
        assert_eq!(m.s[0], vec![0xFF; REC_LEN]); assert_eq!(m.s[1], vec![0xFF; REC_LEN]); // nothing was written
    }
    #[test] fn recover_after_corrupt() {
        let mut m = Mock::new(); m.s[0] = vec![0; REC_LEN]; m.s[1] = vec![7; REC_LEN];
        let p = save(&mut m, &r(K2)).unwrap(); assert_eq!(load(&mut m).unwrap(), Loaded::Rec(r(K2), p.pos));
        assert!(matches!(replace_record(&mut m, &r(K3)), Replaced::New(_))); assert_eq!(active(&mut m), Some(K3));
    }

    // ---- the dangerous reset scenarios ----------------------------------------------------------

    /// A valid plain record with a chosen sequence number.
    fn forged(key: &[u8; 32], seq: u32) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut t = Mock::new(); save(&mut t, &r(*key)).unwrap();
        let mut raw = t.s[0].clone();
        raw[4..8].copy_from_slice(&seq.to_le_bytes());
        let h = Sha256::digest(&raw[..94]); raw[94..].copy_from_slice(&h[..16]);
        raw
    }

    #[test] fn reset_with_unknown_position_still_beats_a_surviving_higher_seq_record() {
        let mut m = Mock::new();
        m.s[1] = forged(&K1, 9); m.s[0] = vec![0x5A; REC_LEN];
        assert!(matches!(load(&mut m).unwrap(), Loaded::Rec(ref g, p) if g.body == K1 && p.seq == 9 && p.slot == 1));
        m.stuck[1] = true;
        match replace_record(&mut m, &r(K2)) {
            Replaced::New(s) => { assert!(!s.old_wiped); assert_eq!(s.pos.seq, 10); }
            o => panic!("{o:?}"),
        }
        assert_eq!(active(&mut m), Some(K2), "old key must not come back after reboot");
    }
    #[test] fn erase_failure_that_leaves_the_old_record_intact_cannot_resurrect_it() {
        for stuck_slot in 0..2 {
            let mut m = Mock::new(); save(&mut m, &r(K1)).unwrap();
            let p = save(&mut m, &r(K2)).unwrap().pos;                  // K2 now lives in slot 1
            assert_eq!(p.slot, 1);
            m.stuck[stuck_slot] = true;
            let res = replace_record(&mut m, &r(K3));
            if stuck_slot == 0 {
                assert!(matches!(res, Replaced::Kept(ref g) if g.body == K2), "{res:?}");
                assert_eq!(active(&mut m), Some(K2));
            } else {
                assert!(matches!(res, Replaced::New(ref s) if !s.old_wiped), "{res:?}");
                assert_eq!(active(&mut m), Some(K3));
            }
        }
    }
    #[test] fn erase_refused_everywhere_keeps_the_previous_key_consistently() {
        let mut m = Mock::new(); save(&mut m, &r(K1)).unwrap();
        m.ops = 0; m.erase_fail_from = Some(1);
        let res = replace_record(&mut m, &r(K2));
        assert!(matches!(res, Replaced::Kept(ref g) if g.body == K1), "{res:?}"); assert_eq!(active(&mut m), Some(K1));
    }
    #[test] fn verify_read_failure_after_successful_write_is_reconciled() {
        let mut m = Mock::new(); save(&mut m, &r(K1)).unwrap(); m.reads = 0; m.read_err_once_at = Some(3);
        let res = replace_record(&mut m, &r(K2));
        assert!(matches!(res, Replaced::Kept(ref g) if g.body == K1), "{res:?}"); assert_eq!(active(&mut m), Some(K1));
        let mut m = Mock::new(); save(&mut m, &r(K1)).unwrap();
        m.reads = 0; m.read_err_once_at = Some(3); m.ops = 0; m.erase_fail_from = Some(3);
        let res = replace_record(&mut m, &r(K2));
        assert!(matches!(res, Replaced::New(_)), "{res:?}"); assert_eq!(active(&mut m), Some(K2));
    }
    #[test] fn unreadable_flash_after_failure_is_reported_as_unknown() {
        let mut m = Mock::new(); save(&mut m, &r(K1)).unwrap();
        m.read_err = true;
        assert_eq!(replace_record(&mut m, &r(K2)), Replaced::Unknown);
    }
    #[test] fn sequence_numbers_survive_wrap_around() {
        let mut m = Mock::new();
        m.s[0] = forged(&K2, u32::MAX);
        assert!(matches!(load(&mut m).unwrap(), Loaded::Rec(ref g, p) if g.body == K2 && p.seq == u32::MAX));
        assert!(matches!(replace_record(&mut m, &r(K3)), Replaced::New(s) if s.pos.seq == 0));
        assert_eq!(active(&mut m), Some(K3));
        assert!(matches!(replace_record(&mut m, &r(K1)), Replaced::New(_))); assert_eq!(active(&mut m), Some(K1));
        let _ = pos_of(&mut m);
    }

    // ---- PIN retry counter ---------------------------------------------------------------------

    #[test] fn attempt_is_persisted_before_it_is_evaluated() {
        let mut m = Mock::new();
        assert_eq!(count_tries(&mut m).unwrap(), 0);
        let page = begin_try(&mut m).unwrap();            // power is cut here: no finish_try ever happens
        assert_eq!(count_tries(&mut m).unwrap(), 1, "a started attempt counts as failed");
        finish_try(&mut m, page).unwrap();                 // a correct PIN forgives it
        assert_eq!(count_tries(&mut m).unwrap(), 0);
    }
    #[test] fn eight_failures_block_and_a_correct_pin_forgives_earlier_failures() {
        let mut m = Mock::new();
        for i in 1..=7 { begin_try(&mut m).unwrap(); assert_eq!(count_tries(&mut m).unwrap(), i); }
        let page = begin_try(&mut m).unwrap(); assert_eq!(count_tries(&mut m).unwrap(), 8);
        assert!(begin_try(&mut m).is_err(), "9th attempt must be refused without writing");
        assert_eq!(count_tries(&mut m).unwrap(), 8);
        // the 8th attempt turned out to be the correct PIN
        finish_try(&mut m, page).unwrap(); assert_eq!(count_tries(&mut m).unwrap(), 0);
        begin_try(&mut m).unwrap(); assert_eq!(count_tries(&mut m).unwrap(), 1);
    }
    #[test] fn counter_survives_filling_up_the_sector() {
        let mut m = Mock::new();
        for _ in 0..40 { let p = begin_try(&mut m).unwrap(); finish_try(&mut m, p).unwrap(); assert_eq!(count_tries(&mut m).unwrap(), 0); }
        reset_tries(&mut m).unwrap();
        // fill all 16 pages: 13 correct PINs, then 3 pending failures
        for _ in 0..13 { let p = begin_try(&mut m).unwrap(); finish_try(&mut m, p).unwrap(); }
        for _ in 0..3 { begin_try(&mut m).unwrap(); }
        assert_eq!(count_tries(&mut m).unwrap(), 3); assert!(m.t.iter().all(|&b| b != 0xFF), "sector is full");
        begin_try(&mut m).unwrap();                         // forces a compaction that must keep the 3 failures
        assert_eq!(count_tries(&mut m).unwrap(), 4);
        for _ in 0..20 { if begin_try(&mut m).is_err() { break } }
        assert_eq!(count_tries(&mut m).unwrap(), 8, "failures are never forgotten by compaction");
    }
    #[test] fn counter_write_failure_refuses_the_attempt() {
        let mut m = Mock::new(); m.tries_dead = true;
        assert!(begin_try(&mut m).is_err());
        let mut m = Mock::new(); m.read_err = true; assert!(begin_try(&mut m).is_err() && count_tries(&mut m).is_err());
    }
    #[test] fn reset_tries_clears_everything() {
        let mut m = Mock::new(); for _ in 0..5 { begin_try(&mut m).unwrap(); }
        reset_tries(&mut m).unwrap(); assert_eq!(count_tries(&mut m).unwrap(), 0); assert_eq!(m.t, [0xFF; TRIES_PAGES]);
        reset_tries(&mut m).unwrap();
    }
}

#[cfg(test)]
mod health_tests {
    use super::health::*;
    fn lcg(seed: &mut u64) -> [u8; SAMPLE] { let mut o = [0u8; SAMPLE]; for b in o.iter_mut() { *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); *b = (*seed >> 56) as u8; } o }
    #[test] fn varying_data_passes() { let mut h = Health::new(); let mut s = 1; for _ in 0..2000 { assert!(h.feed(&lcg(&mut s))); } }
    #[test] fn constant_output_fails() { let mut h = Health::new(); assert!(!h.feed(&[0x00; SAMPLE])); let mut h = Health::new(); assert!(!h.feed(&[0xA5; SAMPLE])); }
    #[test] fn frozen_non_uniform_pattern_fails() {
        let mut h = Health::new(); let mut s = 7; let sample = lcg(&mut s);
        assert!(h.feed(&sample)); assert!(!h.feed(&sample), "identical consecutive samples");
    }
    #[test] fn long_runs_fail() {
        let mut h = Health::new(); let mut s = [1u8; SAMPLE]; for (i, b) in s.iter_mut().enumerate() { *b = i as u8; }
        for b in &mut s[10..40] { *b = 9; }                          // 30 identical bytes in a row
        assert!(!h.feed(&s));
    }
    #[test] fn run_spanning_two_samples_fails() {
        let mut h = Health::new(); let mut a = [0u8; SAMPLE]; let mut b = [0u8; SAMPLE];
        for i in 0..SAMPLE { a[i] = (i * 3 + 1) as u8; b[i] = (i * 5 + 2) as u8; }
        for x in &mut a[50..] { *x = 77; } for x in &mut b[..10] { *x = 77; }   // 14 + 10 = 24 in a row
        assert!(h.feed(&a)); assert!(!h.feed(&b));
    }
    #[test] fn heavily_biased_source_fails_adaptive_proportion_test() {
        // 52 of every 64 bytes are 0x42 (never more than 8 in a row, never two equal samples):
        // only the proportion test can catch this.
        let mut h = Health::new(); let mut s = 3u64; let mut ok = true;
        for _ in 0..40 {
            let mut x = lcg(&mut s);
            for (i, b) in x.iter_mut().enumerate() { if i % 5 != 4 { *b = 0x42; } else if *b == 0x42 { *b = 0x43; } }
            ok &= h.feed(&x);
        }
        assert!(!ok);
    }
}

#[cfg(test)]
mod pin_tests {
    use super::pin::*;
    fn hx(s: &str) -> Vec<u8> { (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect() }
    // Reference values computed independently with python 'cryptography' (HKDF, AES-CBC, HMAC).
    #[test] fn protocol2_matches_reference_vectors() {
        let z: Vec<u8> = (0..32).collect(); let sh = Shared::from_z(2, &z);
        assert_eq!(sh.authenticate(&[b"a", b"bc"]), hx("7806f087d00656b3113cd046bc4e2eeb5b72d1a37c7263712c7ab6bbe499cc7c"));
        let iv: [u8; 16] = core::array::from_fn(|i| 100 + i as u8); let pt: Vec<u8> = (0..32).collect();
        let mut want = iv.to_vec(); want.extend(hx("8c0a7dfa40af1d67ae1c9072cc8071c77808d71206f6440bdf0db06bf2b18d8a"));
        assert_eq!(sh.encrypt_iv(&pt, &iv), want);
        assert_eq!(sh.decrypt(&want).unwrap(), pt);
        assert!(sh.verify(&[b"abc"], &hx("7806f087d00656b3113cd046bc4e2eeb5b72d1a37c7263712c7ab6bbe499cc7c")));
        assert!(!sh.verify(&[b"abd"], &hx("7806f087d00656b3113cd046bc4e2eeb5b72d1a37c7263712c7ab6bbe499cc7c")));
        assert!(!sh.verify(&[b"abc"], &hx("7806f087d00656b3113cd046bc4e2eeb")), "truncated MAC is invalid in protocol 2");
    }
    #[test] fn protocol1_matches_reference_vectors() {
        let z: Vec<u8> = (0..32).collect(); let sh = Shared::from_z(1, &z); let pt: Vec<u8> = (0..32).collect();
        let ct = hx("5b1b8c62089fae8afdcde68081977f19e6a0b8d59b6818113cd771f0867e8903");
        assert_eq!(sh.encrypt_iv(&pt, &[0; 16]), ct, "zero IV, no IV on the wire");
        assert_eq!(sh.decrypt(&ct).unwrap(), pt);
        assert_eq!(sh.authenticate(&[b"abc"]), hx("e33b01cabe3d24ef7bf39cfd7f76caf0"));
        assert!(sh.verify(&[b"abc"], &hx("e33b01cabe3d24ef7bf39cfd7f76caf0")));
        assert!(!sh.verify(&[b"abc"], &hx("e33b01cabe3d24ef7bf39cfd7f76caf1")));
    }
    #[test] fn bad_lengths_are_rejected() {
        let z = [9u8; 32]; let s2 = Shared::from_z(2, &z); let s1 = Shared::from_z(1, &z);
        assert!(s2.decrypt(&[0; 16]).is_none() && s2.decrypt(&[0; 33]).is_none() && s2.decrypt(&[]).is_none());
        assert!(s1.decrypt(&[]).is_none() && s1.decrypt(&[0; 17]).is_none());
        assert!(s1.decrypt(&[0; 16]).is_some() && s2.decrypt(&[0; 32]).is_some());
    }
    #[test] fn ecdh_is_symmetric_and_cose_key_round_trips() {
        let mut rng = |b: &mut [u8]| { use rand::RngCore; rand::thread_rng().fill_bytes(b) };
        let a = new_secret(&mut rng); let b = new_secret(&mut rng);
        for v in [1u8, 2] {
            let (sa, sb) = (Shared::derive(v, &a, &b.public_key()), Shared::derive(v, &b, &a.public_key()));
            assert_eq!(sa.authenticate(&[b"x"]), sb.authenticate(&[b"x"]));
        }
        let enc = cose_key(&a.public_key());
        let mut r = super::cbor::R::new(&enc);
        assert_eq!(parse_cose(&mut r).unwrap(), a.public_key());
        assert!(super::cbor::validate(&enc).is_ok(), "COSE key is canonical CBOR");
    }
    #[test] fn invalid_peer_keys_are_rejected() {
        // x, y of the wrong length / not on the curve
        let mut w = super::cbor::W::new(); w.map(2); w.int(-2); w.bytes(&[1; 32]); w.int(-3); w.bytes(&[2; 32]);
        assert_eq!(parse_cose(&mut super::cbor::R::new(&w.0)), Err(0x02));
        let mut w = super::cbor::W::new(); w.map(2); w.int(-2); w.bytes(&[1; 31]); w.int(-3); w.bytes(&[2; 32]);
        assert_eq!(parse_cose(&mut super::cbor::R::new(&w.0)), Err(0x02));
        let mut w = super::cbor::W::new(); w.map(1); w.int(-2); w.bytes(&[1; 32]);
        assert_eq!(parse_cose(&mut super::cbor::R::new(&w.0)), Err(0x14));
    }
}

#[cfg(test)]
mod wrap_tests {
    use super::wrap::*;
    #[test] fn wrap_then_unwrap_with_the_right_pin_only() {
        let master = [0x42u8; 32]; let pin = [1u8; 16];
        let rec = wrap(&master, &pin, [9; 16]).unwrap();
        assert!(rec.wrapped); assert_ne!(rec.body, master, "key must not be stored in the clear");
        assert!(!rec.body.windows(8).any(|w| master.windows(8).any(|m| m == w)));
        assert_eq!(unwrap(&rec, &pin), Some(master));
        let mut wrong = pin; wrong[15] ^= 1; assert_eq!(unwrap(&rec, &wrong), None);
    }
    #[test] fn tampering_with_any_field_is_detected() {
        let master = [0x42u8; 32]; let pin = [1u8; 16]; let rec = wrap(&master, &pin, [9; 16]).unwrap();
        let mut a = rec.clone(); a.body[0] ^= 1; assert_eq!(unwrap(&a, &pin), None);
        let mut a = rec.clone(); a.tag[31] ^= 1; assert_eq!(unwrap(&a, &pin), None);
        let mut a = rec.clone(); a.salt[0] ^= 1; assert_eq!(unwrap(&a, &pin), None);
        let mut a = rec.clone(); a.t_cost += 1; assert_eq!(unwrap(&a, &pin), None);
        let mut a = rec.clone(); a.m_kib += 8; assert_eq!(unwrap(&a, &pin), None);
    }
    #[test] fn absurd_parameters_are_refused_instead_of_exhausting_memory() {
        let pin = [1u8; 16]; let mut rec = wrap(&[1; 32], &pin, [9; 16]).unwrap();
        rec.m_kib = 4_000_000; assert_eq!(unwrap(&rec, &pin), None);
        rec.m_kib = 8; rec.t_cost = 0; assert_eq!(unwrap(&rec, &pin), None);
        assert_eq!(unwrap(&super::store::Record::plain([1; 32]), &pin), None, "plain records are not wrapped");
    }
    #[test] fn every_wrap_uses_its_own_salt_and_keystream() {
        let pin = [1u8; 16]; let a = wrap(&[5; 32], &pin, [1; 16]).unwrap(); let b = wrap(&[5; 32], &pin, [2; 16]).unwrap();
        assert_ne!(a.body, b.body); assert_ne!(a.tag, b.tag);
    }
}

#[cfg(test)]
mod ctap_tests {
    use super::ctap::*;
    use super::cbor::{R, W};
    use super::pin::*;
    use super::store::Record;
    use super::RamVault;
    use hmac::{Hmac, Mac};
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    const PIN: &str = "correct horse battery";
    const CDH: [u8; 32] = [7; 32];

    fn call(c: &mut Ctap, v: &mut RamVault, req: &[u8], now: u64) -> Vec<u8> {
        let mut r = rand::thread_rng(); let mut f = |b: &mut [u8]| r.fill_bytes(b);
        let mut x = c.handle(req, false, now, &mut f, v);
        if let Resp::NeedUp = x { x = c.handle(req, true, now, &mut f, v); }
        match x { Resp::Ok(b) => b, Resp::Err(e) => vec![e], Resp::NeedUp => vec![0xEE] }
    }
    fn enc_u(x: u64) -> Vec<u8> { let mut w = W::new(); w.uint(x); w.0 }
    fn enc_b(b: &[u8]) -> Vec<u8> { let mut w = W::new(); w.bytes(b); w.0 }
    /// Fields must be given in ascending key order (canonical CBOR).
    fn pin_req(fields: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut w = W::new(); w.map(fields.len() as u64);
        for (k, v) in fields { w.uint(*k); w.0.extend_from_slice(v); }
        let mut out = vec![0x06]; out.extend(w.0); out
    }
    fn pad(pin: &str) -> Vec<u8> { let mut b = pin.as_bytes().to_vec(); b.resize(64, 0); b }
    fn hash16(pin: &str) -> Vec<u8> { Sha256::digest(pin.as_bytes())[..16].to_vec() }
    fn enc(sh: &Shared, pt: &[u8]) -> Vec<u8> { let mut r = rand::thread_rng(); sh.encrypt(pt, &mut |b: &mut [u8]| r.fill_bytes(b)) }
    fn token_auth(v: u8, token: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(token).unwrap(); m.update(msg);
        m.finalize().into_bytes()[..if v == 1 { 16 } else { 32 }].to_vec()
    }
    fn setup(master: u8) -> (Ctap, RamVault) { let rec = Record::plain([master; 32]); (Ctap::new(Some(rec.clone())), RamVault::new(Some(rec))) }

    /// What a browser does.
    struct Plat { v: u8, sk: p256::SecretKey, sh: Option<Shared> }
    impl Plat {
        fn new(v: u8) -> Self { let mut r = rand::thread_rng(); Plat { v, sk: new_secret(&mut |b: &mut [u8]| r.fill_bytes(b)), sh: None } }
        fn cose(&self) -> Vec<u8> { cose_key(&self.sk.public_key()) }
        fn agree(&mut self, c: &mut Ctap, v: &mut RamVault) {
            let r = call(c, v, &pin_req(&[(1, enc_u(self.v as u64)), (2, enc_u(2))]), 1000);
            assert_eq!(r[0], 0, "getKeyAgreement");
            let mut rd = R::new(&r[1..]); rd.map().unwrap(); assert_eq!(rd.uint().unwrap(), 1);
            self.sh = Some(Shared::derive(self.v, &self.sk, &parse_cose(&mut rd).unwrap()));
        }
        fn set_pin(&mut self, c: &mut Ctap, v: &mut RamVault, pin: &str) -> u8 {
            self.agree(c, v); let sh = self.sh.as_ref().unwrap();
            let new_enc = enc(sh, &pad(pin)); let auth = sh.authenticate(&[&new_enc]);
            call(c, v, &pin_req(&[(1, enc_u(self.v as u64)), (2, enc_u(3)), (3, self.cose()), (4, enc_b(&auth)), (5, enc_b(&new_enc))]), 1000)[0]
        }
        fn change_pin(&mut self, c: &mut Ctap, v: &mut RamVault, old: &str, new: &str) -> u8 {
            self.agree(c, v); let sh = self.sh.as_ref().unwrap();
            let new_enc = enc(sh, &pad(new)); let hash_enc = enc(sh, &hash16(old)); let auth = sh.authenticate(&[&new_enc, &hash_enc]);
            call(c, v, &pin_req(&[(1, enc_u(self.v as u64)), (2, enc_u(4)), (3, self.cose()), (4, enc_b(&auth)), (5, enc_b(&new_enc)), (6, enc_b(&hash_enc))]), 1000)[0]
        }
        fn token(&mut self, c: &mut Ctap, v: &mut RamVault, pin: &str, now: u64) -> Result<Vec<u8>, u8> {
            self.agree(c, v); let sh = self.sh.as_ref().unwrap();
            let hash_enc = enc(sh, &hash16(pin));
            let r = call(c, v, &pin_req(&[(1, enc_u(self.v as u64)), (2, enc_u(5)), (3, self.cose()), (6, enc_b(&hash_enc))]), now);
            if r[0] != 0 { return Err(r[0]); }
            let mut rd = R::new(&r[1..]); rd.map().unwrap(); assert_eq!(rd.uint().unwrap(), 2);
            Ok(sh.decrypt(rd.bytes().unwrap()).unwrap())
        }
    }
    fn retries(c: &mut Ctap, v: &mut RamVault) -> (u64, bool) {
        let r = call(c, v, &pin_req(&[(2, enc_u(1))]), 1000); assert_eq!(r[0], 0);
        let mut rd = R::new(&r[1..]); let n = rd.map().unwrap(); assert_eq!(rd.uint().unwrap(), 3); let left = rd.uint().unwrap();
        (left, n == 2)
    }
    fn mc_req(pin: Option<(u8, Vec<u8>)>) -> Vec<u8> {
        let mut w = W::new(); w.map(if pin.is_some() { 6 } else { 4 });
        w.uint(1); w.bytes(&CDH);
        w.uint(2); w.map(1); w.text("id"); w.text("example.com");
        w.uint(3); w.map(1); w.text("id"); w.bytes(b"u1");
        w.uint(4); w.arr(1); w.map(2); w.text("alg"); w.int(-7); w.text("type"); w.text("public-key");
        if let Some((v, p)) = pin { w.uint(8); w.bytes(&p); w.uint(9); w.uint(v as u64); }
        let mut out = vec![0x01]; out.extend(w.0); out
    }
    fn ga_req(id: &[u8], pin: Option<(u8, Vec<u8>)>) -> Vec<u8> {
        let mut w = W::new(); w.map(if pin.is_some() { 5 } else { 3 });
        w.uint(1); w.text("example.com"); w.uint(2); w.bytes(&CDH);
        w.uint(3); w.arr(1); w.map(2); w.text("id"); w.bytes(id); w.text("type"); w.text("public-key");
        if let Some((v, p)) = pin { w.uint(6); w.bytes(&p); w.uint(7); w.uint(v as u64); }
        let mut out = vec![0x02]; out.extend(w.0); out
    }
    /// (flags, credential id) of a makeCredential response.
    fn parse_mc(resp: &[u8]) -> (u8, Vec<u8>) {
        assert_eq!(resp[0], 0, "makeCredential status {:#x}", resp[0]);
        let mut r = R::new(&resp[1..]); r.map().unwrap(); r.uint().unwrap(); r.text().unwrap(); r.uint().unwrap();
        let ad = r.bytes().unwrap(); (ad[32], ad[55..119].to_vec())
    }
    fn mc_param(v: u8, tok: &[u8]) -> Vec<u8> { token_auth(v, tok, &CDH) }

    #[test] fn reset_window_is_judged_on_arrival_time() {
        let (mut c, mut v) = setup(9);
        let mut r = rand::thread_rng(); let mut f = |b: &mut [u8]| r.fill_bytes(b);
        assert!(matches!(c.handle(&[7], false, 9_900, &mut f, &mut v), Resp::NeedUp));
        assert!(matches!(c.handle(&[7], true, 9_900, &mut f, &mut v), Resp::Ok(_)));
        assert!(matches!(c.handle(&[7], false, 10_001, &mut f, &mut v), Resp::Err(0x30)));
    }
    #[test] fn broken_storage_makes_the_device_refuse() {
        let mut c = Ctap::new(None); let mut v = RamVault::new(None);
        assert_eq!(call(&mut c, &mut v, &mc_req(None), 0)[0], 0x7F);
        assert_eq!(call(&mut c, &mut v, &[0x06, 0xa2, 0x01, 0x02, 0x02, 0x03], 0)[0], 0x7F, "no PIN commands on broken storage");
        assert_eq!(call(&mut c, &mut v, &[7], 100)[0], 0, "but reset recovers");
        assert!(call(&mut c, &mut v, &mc_req(None), 100)[0] == 0 && v.rec.is_some());
    }

    #[test] fn full_pin_flow_for_both_protocols() {
        for pv in [1u8, 2] {
            let (mut c, mut v) = setup(5); let mut p = Plat::new(pv);
            // a credential made before the PIN must keep working after it (same master key)
            let (flags, cid) = parse_mc(&call(&mut c, &mut v, &mc_req(None), 1000)); assert_eq!(flags, 0x41);
            assert_eq!(p.set_pin(&mut c, &mut v, PIN), 0, "setPIN v{pv}");
            let rec = v.rec.clone().unwrap();
            assert!(rec.wrapped && rec.body != [5; 32], "the plain key must not be what is stored");
            assert!(!c.key_in_ram(), "no PIN session yet: the key must not be in RAM");
            assert_eq!(call(&mut c, &mut v, &mc_req(None), 1000)[0], 0x36, "PIN required");
            assert_eq!(call(&mut c, &mut v, &ga_req(&cid, None), 1000)[0], 0x36);
            // wrong PIN
            assert_eq!(p.token(&mut c, &mut v, "wrong wrong wrong", 2000).unwrap_err(), 0x31);
            assert!(!c.key_in_ram()); assert_eq!(retries(&mut c, &mut v), (7, false));
            // right PIN
            let tok = p.token(&mut c, &mut v, PIN, 3000).unwrap(); assert_eq!(tok.len(), 32);
            assert!(c.key_in_ram(), "session open"); assert_eq!(retries(&mut c, &mut v), (8, false));
            let (flags, _) = parse_mc(&call(&mut c, &mut v, &mc_req(Some((pv, mc_param(pv, &tok)))), 3100)); assert_eq!(flags, 0x45, "UP|AT|UV");
            let r = call(&mut c, &mut v, &ga_req(&cid, Some((pv, mc_param(pv, &tok)))), 3200); assert_eq!(r[0], 0, "old credential still valid");
            let mut rd = R::new(&r[1..]); rd.map().unwrap(); rd.uint().unwrap(); rd.map().unwrap(); rd.text().unwrap(); rd.bytes().unwrap(); rd.text().unwrap(); rd.text().unwrap(); rd.uint().unwrap();
            assert_eq!(rd.bytes().unwrap()[32], 0x05, "UP|UV");
            // forged / wrong-protocol / missing parameters
            let mut bad = mc_param(pv, &tok); bad[0] ^= 1;
            assert_eq!(call(&mut c, &mut v, &mc_req(Some((pv, bad))), 3300)[0], 0x33);
            assert_eq!(call(&mut c, &mut v, &mc_req(Some((3, mc_param(pv, &tok)))), 3300)[0], 0x02);
            assert_eq!(call(&mut c, &mut v, &mc_req(Some((pv, vec![]))), 3300)[0], 0x33);
        }
    }
    #[test] fn session_expires_and_the_key_leaves_ram() {
        let (mut c, mut v) = setup(5); let mut p = Plat::new(2); assert_eq!(p.set_pin(&mut c, &mut v, PIN), 0);
        let tok = p.token(&mut c, &mut v, PIN, 10_000).unwrap(); let par = mc_param(2, &tok);
        c.tick(10_000 + TOKEN_LIFETIME_MS - 1); assert!(c.key_in_ram());
        assert_eq!(call(&mut c, &mut v, &mc_req(Some((2, par.clone()))), 10_000 + TOKEN_LIFETIME_MS - 1)[0], 0);
        c.tick(10_000 + TOKEN_LIFETIME_MS); assert!(!c.key_in_ram(), "expired session must wipe the key");
        assert_eq!(call(&mut c, &mut v, &mc_req(Some((2, par.clone()))), 10_000 + TOKEN_LIFETIME_MS + 1)[0], 0x33);
        // an expired token is refused even if nobody called tick()
        let tok = p.token(&mut c, &mut v, PIN, 500_000).unwrap(); let par = mc_param(2, &tok);
        assert_eq!(call(&mut c, &mut v, &mc_req(Some((2, par.clone()))), 500_000 + TOKEN_LIFETIME_MS)[0], 0x33);
        // USB reset / suspend
        let tok = p.token(&mut c, &mut v, PIN, 900_000).unwrap(); let par = mc_param(2, &tok);
        c.lock(); assert!(!c.key_in_ram());
        assert_eq!(call(&mut c, &mut v, &mc_req(Some((2, par.clone()))), 900_001)[0], 0x33);
    }
    #[test] fn wrong_pins_lock_out_and_a_reboot_does_not_reset_the_counter() {
        let (mut c, mut v) = setup(5); let mut p = Plat::new(2); assert_eq!(p.set_pin(&mut c, &mut v, PIN), 0);
        assert_eq!(p.token(&mut c, &mut v, "wrong pin number 1", 1).unwrap_err(), 0x31);
        assert_eq!(p.token(&mut c, &mut v, "wrong pin number 2", 1).unwrap_err(), 0x31);
        assert_eq!(p.token(&mut c, &mut v, "wrong pin number 3", 1).unwrap_err(), 0x34, "3 in a row: power cycle needed");
        assert_eq!(retries(&mut c, &mut v), (5, true));
        assert_eq!(p.token(&mut c, &mut v, PIN, 1).unwrap_err(), 0x34, "even the right PIN is refused until a power cycle");
        assert_eq!(v.used, 3, "refused attempts do not use up tries");
        c = Ctap::new(v.rec.clone()); // power cycle
        assert_eq!(retries(&mut c, &mut v), (5, false), "persistent counter survives the power cycle");
        for i in 0..2 { assert_eq!(p.token(&mut c, &mut v, "wrong pin number x", 1).unwrap_err(), 0x31, "{i}"); }
        assert_eq!(p.token(&mut c, &mut v, "wrong pin number x", 1).unwrap_err(), 0x34); // 6 used
        c = Ctap::new(v.rec.clone());
        assert_eq!(p.token(&mut c, &mut v, "wrong pin number y", 1).unwrap_err(), 0x31); // 7
        assert_eq!(p.token(&mut c, &mut v, "wrong pin number y", 1).unwrap_err(), 0x32, "8th failure blocks the PIN");
        c = Ctap::new(v.rec.clone());
        assert_eq!(p.token(&mut c, &mut v, PIN, 1).unwrap_err(), 0x32, "blocked: only a reset helps");
        assert_eq!(retries(&mut c, &mut v), (0, false));
        assert_eq!(call(&mut c, &mut v, &[7], 5000)[0], 0, "reset");
        assert!(!v.rec.as_ref().unwrap().wrapped && v.used == 0);
        assert_eq!(p.set_pin(&mut c, &mut v, PIN), 0); assert!(p.token(&mut c, &mut v, PIN, 6000).is_ok());
    }
    #[test] fn a_correct_pin_after_failures_forgives_them() {
        let (mut c, mut v) = setup(5); let mut p = Plat::new(2); p.set_pin(&mut c, &mut v, PIN);
        p.token(&mut c, &mut v, "wrong pin number 1", 1).unwrap_err(); p.token(&mut c, &mut v, "wrong pin number 2", 1).unwrap_err();
        assert!(p.token(&mut c, &mut v, PIN, 1).is_ok()); assert_eq!(retries(&mut c, &mut v), (8, false));
        // ... including the boot-time failure streak
        p.token(&mut c, &mut v, "wrong pin number 3", 1).unwrap_err(); assert_eq!(p.token(&mut c, &mut v, "wrong pin number 4", 1).unwrap_err(), 0x31);
    }
    #[test] fn change_pin_rewraps_and_locks() {
        for pv in [1u8, 2] {
            let (mut c, mut v) = setup(5); let mut p = Plat::new(pv); p.set_pin(&mut c, &mut v, PIN);
            let new = "another long passphrase";
            assert_eq!(p.change_pin(&mut c, &mut v, "wrong wrong wrong", new), 0x31, "wrong old PIN");
            let before = v.rec.clone();
            assert_eq!(p.change_pin(&mut c, &mut v, PIN, new), 0); assert!(v.rec != before); assert!(!c.key_in_ram());
            assert_eq!(p.token(&mut c, &mut v, PIN, 1).unwrap_err(), 0x31, "old PIN no longer works");
            assert!(p.token(&mut c, &mut v, new, 1).is_ok());
            // the master key did not change
            let tok = p.token(&mut c, &mut v, new, 1).unwrap();
            let (_, cid) = parse_mc(&call(&mut c, &mut v, &mc_req(Some((pv, mc_param(pv, &tok)))), 1));
            assert_eq!(cid.len(), 64);
        }
    }
    #[test] fn pin_policy_and_state_errors() {
        let (mut c, mut v) = setup(5); let mut p = Plat::new(2);
        assert_eq!(p.set_pin(&mut c, &mut v, "short"), 0x37); assert!(!v.rec.as_ref().unwrap().wrapped);
        assert_eq!(p.set_pin(&mut c, &mut v, &"x".repeat(64)), 0x37, "no room for the terminator");
        assert_eq!(p.set_pin(&mut c, &mut v, &"é".repeat(10)), 0, "10 code points (20 bytes) are fine");
        assert_eq!(p.set_pin(&mut c, &mut v, PIN), 0x33, "PIN already set -> use changePIN");
        // no PIN set yet
        let (mut c2, mut v2) = setup(6); let mut p2 = Plat::new(2);
        assert_eq!(p2.token(&mut c2, &mut v2, PIN, 1).unwrap_err(), 0x35);
        assert_eq!(p2.change_pin(&mut c2, &mut v2, PIN, PIN), 0x35);
        // a request MAC'd with the wrong shared secret is rejected, and setting the PIN needs a valid MAC
        p2.agree(&mut c2, &mut v2); let sh = p2.sh.as_ref().unwrap(); let new_enc = enc(sh, &pad(PIN));
        let req = pin_req(&[(1, enc_u(2)), (2, enc_u(3)), (3, p2.cose()), (4, enc_b(&[0; 32])), (5, enc_b(&new_enc))]);
        assert_eq!(call(&mut c2, &mut v2, &req, 1)[0], 0x33); assert!(!v2.rec.as_ref().unwrap().wrapped);
        // unsupported protocol / subcommand, plain authenticators reject PIN parameters
        assert_eq!(call(&mut c2, &mut v2, &pin_req(&[(1, enc_u(3)), (2, enc_u(2))]), 1)[0], 0x02);
        assert_eq!(call(&mut c2, &mut v2, &pin_req(&[(1, enc_u(2)), (2, enc_u(9))]), 1)[0], 0x02);
        assert_eq!(call(&mut c2, &mut v2, &mc_req(Some((2, vec![0; 32]))), 1)[0], 0x35);
    }
    #[test] fn reset_removes_the_pin_and_needs_the_window() {
        let (mut c, mut v) = setup(5); let mut p = Plat::new(2); p.set_pin(&mut c, &mut v, PIN);
        assert_eq!(call(&mut c, &mut v, &[7], 20_000)[0], 0x30, "too late");
        assert!(v.rec.as_ref().unwrap().wrapped);
        assert_eq!(call(&mut c, &mut v, &[7], 9_000)[0], 0);
        assert!(!v.rec.as_ref().unwrap().wrapped && c.key_in_ram());
        assert_eq!(parse_mc(&call(&mut c, &mut v, &mc_req(None), 9_100)).0, 0x41, "works without a PIN again");
        // old credentials are gone: the master key changed
    }
    #[test] fn failed_pin_writes_leave_session_and_flash_consistent() {
        // flash refuses the write, previous (plain) record stays
        let (mut c, mut v) = setup(5); let mut p = Plat::new(2); v.mode = 1;
        assert_eq!(p.set_pin(&mut c, &mut v, PIN), 0x7F);
        assert!(c.key_in_ram() && !v.rec.as_ref().unwrap().wrapped, "still a plain, usable key, as on the next boot");
        // flash state unknowable: refuse to work rather than guess
        v.mode = 2; assert_eq!(p.set_pin(&mut c, &mut v, PIN), 0x7F);
        assert!(!c.key_in_ram()); assert_eq!(call(&mut c, &mut v, &mc_req(None), 1)[0], 0x7F);
        v.mode = 0; assert_eq!(call(&mut c, &mut v, &[7], 100)[0], 0, "reset recovers");
        // failed changePIN: previous wrapped record stays, still locked
        let (mut c, mut v) = setup(5); let mut p = Plat::new(2); p.set_pin(&mut c, &mut v, PIN);
        v.mode = 1; assert_eq!(p.change_pin(&mut c, &mut v, PIN, "another long passphrase"), 0x7F);
        v.mode = 0; assert!(p.token(&mut c, &mut v, PIN, 1).is_ok(), "old PIN still valid");
    }
    #[test] fn getinfo_reports_pin_state() {
        let (mut c, mut v) = setup(5); let mut p = Plat::new(2);
        let has_pin = |c: &mut Ctap, v: &mut RamVault| -> bool {
            let r = call(c, v, &[4], 1); let mut rd = R::new(&r[1..]); rd.map().unwrap();
            let mut found = None;
            for _ in 0..6 { match rd.uint().unwrap() {
                4 => { for _ in 0..rd.map().unwrap() { let k = rd.text().unwrap(); let b = rd.bool().unwrap(); if k == "clientPin" { found = Some(b); } } }
                6 => { assert_eq!(rd.array().unwrap(), 2); assert_eq!((rd.uint().unwrap(), rd.uint().unwrap()), (2, 1)); }
                _ => rd.skip().unwrap(),
            } }
            found.expect("clientPin option present")
        };
        assert!(!has_pin(&mut c, &mut v)); p.set_pin(&mut c, &mut v, PIN); assert!(has_pin(&mut c, &mut v));
        assert!(super::cbor::validate(&call(&mut c, &mut v, &[4], 1)[1..]).is_ok(), "getInfo is canonical CBOR");
    }
}
