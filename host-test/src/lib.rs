extern crate alloc;
#[path = "../../src/cbor.rs"] pub mod cbor;
#[path = "../../src/ctap.rs"] pub mod ctap;
#[path = "../../src/ctaphid.rs"] pub mod ctaphid;
#[path = "../../src/health.rs"] pub mod health;
#[path = "../../src/store.rs"] pub mod store;
use ctap::*;
use rand::RngCore;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// `master` may be NULL: simulates unreadable/corrupt key storage (fault mode).
#[no_mangle] pub extern "C" fn ctap_new(master: *const u8) -> *mut Ctap {
    let m = if master.is_null() { None } else {
        let mut m = [0u8; 32]; m.copy_from_slice(unsafe { std::slice::from_raw_parts(master, 32) }); Some(m)
    };
    Box::into_raw(Box::new(Ctap::new(m)))
}

/// Returns response length (>=1), -1 = needs user presence, -2 = invalid arguments / output too small, -3 = panic.
#[no_mangle] pub extern "C" fn ctap_handle(c: *mut Ctap, req: *const u8, n: usize, up: i32, now_ms: u64, out: *mut u8, cap: usize) -> i32 {
    if c.is_null() || out.is_null() || cap == 0 || (req.is_null() && n != 0) { return -2; }
    let c = unsafe { &mut *c };
    let req: &[u8] = if n == 0 { &[] } else { unsafe { std::slice::from_raw_parts(req, n) } };
    let o = unsafe { std::slice::from_raw_parts_mut(out, cap) };
    let r = catch_unwind(AssertUnwindSafe(|| {
        let mut rng = |b: &mut [u8]| rand::thread_rng().fill_bytes(b);
        match c.handle(req, up != 0, now_ms, &mut rng) {
            Resp::NeedUp => -1,
            Resp::Err(e) => { o[0] = e; 1 }
            Resp::Ok(v) => if v.len() > cap { -2 } else { o[..v.len()].copy_from_slice(&v); v.len() as i32 },
            Resp::Reset(k) => { c.set_key(Some(k)); o[0] = 0; 1 }
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
        ops: usize,                       // counts erase+write calls
        crash_at: Option<usize>,          // that op fails half-way and leaves junk (power loss)
        read_err: bool,                   // every read fails
        read_err_once_at: Option<usize>,  // only the n-th read (1-based) fails
        reads: usize,
        erase_fail_from: Option<usize>,   // from this op on, erase fails and leaves the sector UNTOUCHED
        stuck: [bool; 2],                 // erase and write on this slot fail, contents UNTOUCHED
    }
    #[derive(Debug)] struct Fault;
    impl Mock {
        fn new() -> Self { Mock { s: [vec![0xFF; REC_LEN], vec![0xFF; REC_LEN]], ops: 0, crash_at: None, read_err: false, read_err_once_at: None, reads: 0, erase_fail_from: None, stuck: [false; 2] } }
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
    }
    const K1: [u8; 32] = [1; 32]; const K2: [u8; 32] = [2; 32]; const K3: [u8; 32] = [3; 32];
    fn active(m: &mut Mock) -> Option<[u8; 32]> { match load(m).unwrap() { Loaded::Key(k, _) => Some(k), _ => None } }

    #[test] fn blank_then_save_then_update() {
        let mut m = Mock::new(); assert_eq!(load(&mut m).unwrap(), Loaded::Blank);
        let p1 = save(&mut m, &K1).unwrap(); assert_eq!(p1.pos, Pos { seq: 1, slot: 0 }); assert!(p1.old_wiped);
        assert_eq!(load(&mut m).unwrap(), Loaded::Key(K1, p1.pos));
        let p2 = save(&mut m, &K2).unwrap(); assert_eq!((p2.pos.seq, p2.pos.slot), (p1.pos.seq + 1, p1.pos.slot ^ 1));
        assert_eq!(load(&mut m).unwrap(), Loaded::Key(K2, p2.pos));
        assert!(m.s[p1.pos.slot].iter().all(|&b| b == 0xFF), "old key must be wiped after a reset");
    }
    #[test] fn power_loss_at_every_step_never_loses_a_key_and_never_mixes() {
        for crash in 1..=6 {
            for start in [None, Some(())] {
                let mut m = Mock::new(); save(&mut m, &K1).unwrap();
                if start.is_some() { save(&mut m, &K2).unwrap(); }
                let old = if start.is_some() { K2 } else { K1 };
                m.ops = 0; m.crash_at = Some(crash);
                let r = replace(&mut m, &K3);
                m.crash_at = None;
                match load(&mut m).unwrap() { Loaded::Key(k, _) => assert!(k == old || k == K3, "crash {crash}"), o => panic!("crash {crash}: {o:?}") }
                // whatever replace() reported must match what the next boot loads
                match r { Replaced::New(_) => assert_eq!(active(&mut m), Some(K3), "crash {crash}"),
                          Replaced::Kept(k) => assert_eq!(active(&mut m), Some(k), "crash {crash}"),
                          other => panic!("crash {crash}: {other:?}") }
            }
        }
    }
    #[test] fn corruption_is_detected_not_replaced() {
        let mut m = Mock::new(); let p = save(&mut m, &K1).unwrap();
        m.s[p.pos.slot][20] ^= 1;                                       // bit flip inside the key
        assert_eq!(load(&mut m).unwrap(), Loaded::Corrupt);              // NOT Blank
        let mut m = Mock::new(); save(&mut m, &K1).unwrap(); m.s[1] = vec![0x55; REC_LEN]; // junk in other slot
        assert!(matches!(load(&mut m).unwrap(), Loaded::Key(K1, _)));    // valid slot still used
        let mut m = Mock::new(); m.s[0] = vec![0; REC_LEN]; assert_eq!(load(&mut m).unwrap(), Loaded::Corrupt);
    }
    #[test] fn read_error_is_an_error_not_blank() {
        let mut m = Mock::new(); m.read_err = true; assert!(load(&mut m).is_err());
        assert!(save(&mut m, &K1).is_err(), "an unreadable position is never treated as blank");
        assert_eq!(m.s[0], vec![0xFF; REC_LEN]); assert_eq!(m.s[1], vec![0xFF; REC_LEN]); // nothing was written
    }
    #[test] fn recover_after_corrupt() {
        let mut m = Mock::new(); m.s[0] = vec![0; REC_LEN]; m.s[1] = vec![7; REC_LEN];
        let p = save(&mut m, &K2).unwrap(); assert_eq!(load(&mut m).unwrap(), Loaded::Key(K2, p.pos));
        assert!(matches!(replace(&mut m, &K3), Replaced::New(_))); assert_eq!(active(&mut m), Some(K3));
    }

    // ---- the dangerous reset scenarios ----------------------------------------------------------

    /// A valid record with a chosen sequence number.
    fn forged(key: &[u8; 32], seq: u32) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut t = Mock::new(); save(&mut t, key).unwrap();
        let mut r = t.s[0].clone();
        r[4..8].copy_from_slice(&seq.to_le_bytes());
        let h = Sha256::digest(&r[..40]); r[40..].copy_from_slice(&h[..16]);
        r
    }

    #[test] fn reset_with_unknown_position_still_beats_a_surviving_higher_seq_record() {
        // Slot 1 holds the live key with a high sequence number, slot 0 is junk, and the old slot
        // can neither be erased nor overwritten. The old code assumed "blank, seq 1, slot 0" here.
        let mut m = Mock::new();
        m.s[1] = forged(&K1, 9); m.s[0] = vec![0x5A; REC_LEN];
        assert!(matches!(load(&mut m).unwrap(), Loaded::Key(K1, p) if p.seq == 9 && p.slot == 1));
        m.stuck[1] = true;
        match replace(&mut m, &K2) {
            Replaced::New(s) => { assert!(!s.old_wiped); assert_eq!(s.pos.seq, 10); }
            o => panic!("{o:?}"),
        }
        assert_eq!(active(&mut m), Some(K2), "old key must not come back after reboot");
    }

    #[test] fn erase_failure_that_leaves_the_old_record_intact_cannot_resurrect_it() {
        for stuck_slot in 0..2 {
            let mut m = Mock::new(); save(&mut m, &K1).unwrap();
            let p = save(&mut m, &K2).unwrap().pos;                  // K2 now lives in slot 1
            assert_eq!(p.slot, 1);
            m.stuck[stuck_slot] = true;
            let r = replace(&mut m, &K3);
            if stuck_slot == 0 {
                // the slot needed for the new record is unusable: nothing may change
                assert!(matches!(r, Replaced::Kept(K2)), "{r:?}");
                assert_eq!(active(&mut m), Some(K2));
            } else {
                // only the old slot cannot be wiped: the new record still wins on every boot
                assert!(matches!(r, Replaced::New(ref s) if !s.old_wiped), "{r:?}");
                assert_eq!(active(&mut m), Some(K3));
            }
        }
    }
    #[test] fn erase_refused_everywhere_keeps_the_previous_key_consistently() {
        let mut m = Mock::new(); save(&mut m, &K1).unwrap();
        m.ops = 0; m.erase_fail_from = Some(1);                    // every erase is refused, data untouched
        let r = replace(&mut m, &K2);
        assert!(matches!(r, Replaced::Kept(K1)), "{r:?}"); assert_eq!(active(&mut m), Some(K1));
    }
    #[test] fn verify_read_failure_after_successful_write_is_reconciled() {
        // read #1 and #2 are the scan, read #3 is the verify read-back
        let mut m = Mock::new(); save(&mut m, &K1).unwrap(); m.reads = 0; m.read_err_once_at = Some(3);
        let r = replace(&mut m, &K2);
        // the unverified record is rolled back (erase works): previous key stays, session and boot agree
        assert!(matches!(r, Replaced::Kept(K1)), "{r:?}"); assert_eq!(active(&mut m), Some(K1));

        // same failure, but the rollback erase is refused: the new record stays durable.
        // replace() must say so instead of reporting failure while the next boot loads the new key.
        let mut m = Mock::new(); save(&mut m, &K1).unwrap();
        m.reads = 0; m.read_err_once_at = Some(3); m.ops = 0; m.erase_fail_from = Some(3);
        let r = replace(&mut m, &K2);
        assert!(matches!(r, Replaced::New(_)), "{r:?}"); assert_eq!(active(&mut m), Some(K2));
    }
    #[test] fn unreadable_flash_after_failure_is_reported_as_unknown() {
        let mut m = Mock::new(); save(&mut m, &K1).unwrap();
        m.read_err = true;
        assert_eq!(replace(&mut m, &K2), Replaced::Unknown);
    }
    #[test] fn sequence_numbers_survive_wrap_around() {
        let mut m = Mock::new();
        m.s[0] = forged(&K2, u32::MAX);
        assert!(matches!(load(&mut m).unwrap(), Loaded::Key(K2, p) if p.seq == u32::MAX));
        assert!(matches!(replace(&mut m, &K3), Replaced::New(s) if s.pos.seq == 0));
        assert_eq!(active(&mut m), Some(K3));
        assert!(matches!(replace(&mut m, &K1), Replaced::New(_))); assert_eq!(active(&mut m), Some(K1));
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
mod ctap_tests {
    use super::ctap::*;
    fn run(c: &mut Ctap, req: &[u8], up: bool, now: u64) -> Resp {
        let mut rng = |b: &mut [u8]| { for (i, x) in b.iter_mut().enumerate() { *x = i as u8 ^ 0x5C; } };
        c.handle(req, up, now, &mut rng)
    }

    #[test] fn reset_window_is_judged_on_arrival_time() {
        let mut c = Ctap::new(Some([9; 32]));
        // request arrived at 9.9 s: needs a touch first, and is accepted after it with the SAME arrival time
        assert!(matches!(run(&mut c, &[7], false, 9_900), Resp::NeedUp));
        assert!(matches!(run(&mut c, &[7], true, 9_900), Resp::Reset(_)));
        // a request that arrived after the window is refused before any touch is asked for
        assert!(matches!(run(&mut c, &[7], false, 10_001), Resp::Err(0x30)));
    }
    #[test] fn set_key_none_makes_the_device_refuse() {
        let mut c = Ctap::new(Some([9; 32])); c.set_key(None);
        let mut req = vec![0x02]; req.extend_from_slice(&[0xa2, 0x01, 0x6b]); req.extend_from_slice(b"example.com"); req.extend_from_slice(&[0x02, 0x58, 0x20]); req.extend_from_slice(&[0u8; 32]);
        assert!(matches!(run(&mut c, &req, false, 0), Resp::Err(0x7F)));
    }
}
