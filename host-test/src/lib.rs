extern crate alloc;
#[path = "../../src/cbor.rs"] pub mod cbor;
#[path = "../../src/ctap.rs"] pub mod ctap;
#[path = "../../src/ctaphid.rs"] pub mod ctaphid;
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
            Resp::Reset(k) => { c.install_key(k); o[0] = 0; 1 }
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
}

#[cfg(test)]
mod cbor_tests {
    use super::cbor::validate;
    #[test] fn accepts_valid() {
        assert!(validate(&[0xa1, 0x01, 0x41, 0x00]).is_ok());
        assert!(validate(&[0xa2, 0x01, 0xf5, 0x02, 0xf6]).is_ok());                    // true / null
        assert!(validate(&[0xa1, 0x01, 0x81, 0x81, 0x81, 0x00]).is_ok());              // depth 4
    }
    #[test] fn rejects_bad() {
        assert_eq!(validate(&[0xa1, 0x18, 0x01, 0x00]), Err(0x12));                    // non-minimal key
        assert_eq!(validate(&[0xa1, 0x01, 0x19, 0x00, 0x05]), Err(0x12));              // non-minimal value
        assert_eq!(validate(&[0xa1, 0x01, 0x58, 0x01, 0x00]), Err(0x12));              // non-minimal length
        assert_eq!(validate(&[0xa2, 0x01, 0x00, 0x01, 0x01]), Err(0x12));              // duplicate key
        assert_eq!(validate(&[0xa1, 0x01, 0x00, 0x00]), Err(0x12));                    // trailing byte
        assert_eq!(validate(&[0xa1, 0x01, 0xc1, 0x00]), Err(0x12));                    // tag
        assert_eq!(validate(&[0xa1, 0x01, 0xf9, 0x00, 0x00]), Err(0x12));              // float
        assert_eq!(validate(&[0xa1, 0x01, 0x81, 0x81, 0x81, 0x81, 0x00]), Err(0x12));  // depth 5
        assert_eq!(validate(&[0xa1, 0x01, 0x9f, 0xff]), Err(0x12));                    // indefinite
        assert_eq!(validate(&[0xa1, 0x01, 0x62, 0xff, 0xff]), Err(0x12));              // bad UTF-8
        assert_eq!(validate(&[0xa1, 0x01]), Err(0x12));                                // truncated
        assert_eq!(validate(&[0x80]), Err(0x11));                                      // not a map
        assert_eq!(validate(&[]), Err(0x12));
        // duplicate key hidden in a nested map
        assert_eq!(validate(&[0xa1, 0x01, 0xa2, 0x61, 0x61, 0x00, 0x61, 0x61, 0x01]), Err(0x12));
    }
}

#[cfg(test)]
mod store_tests {
    use super::store::*;
    #[derive(Clone)]
    struct Mock { s: [Vec<u8>; 2], ops: usize, crash_at: Option<usize>, read_err: bool }
    #[derive(Debug)] struct Crash;
    impl Mock {
        fn new() -> Self { Mock { s: [vec![0xFF; REC_LEN], vec![0xFF; REC_LEN]], ops: 0, crash_at: None, read_err: false } }
        fn tick(&mut self) -> Result<(), Crash> { self.ops += 1; if Some(self.ops) == self.crash_at { Err(Crash) } else { Ok(()) } }
    }
    impl Sectors for Mock {
        type Error = Crash;
        fn read(&mut self, slot: usize, buf: &mut [u8; REC_LEN]) -> Result<(), Crash> { if self.read_err { return Err(Crash) } buf.copy_from_slice(&self.s[slot]); Ok(()) }
        fn erase(&mut self, slot: usize) -> Result<(), Crash> { if self.tick().is_err() { self.s[slot][..20].fill(0); return Err(Crash) } self.s[slot].fill(0xFF); Ok(()) } // crash mid-erase leaves junk
        fn write(&mut self, slot: usize, rec: &[u8; REC_LEN]) -> Result<(), Crash> { if self.tick().is_err() { self.s[slot][..30].copy_from_slice(&rec[..30]); return Err(Crash) } self.s[slot].copy_from_slice(rec); Ok(()) } // crash mid-write: partial record
    }
    const K1: [u8; 32] = [1; 32]; const K2: [u8; 32] = [2; 32]; const K3: [u8; 32] = [3; 32];

    #[test] fn blank_then_save_then_update() {
        let mut m = Mock::new(); assert_eq!(load(&mut m).unwrap(), Loaded::Blank);
        let p1 = save(&mut m, &K1, None).unwrap(); assert_eq!(load(&mut m).unwrap(), Loaded::Key(K1, p1));
        let p2 = save(&mut m, &K2, Some(p1)).unwrap(); assert_eq!((p2.seq, p2.slot), (p1.seq + 1, p1.slot ^ 1));
        assert_eq!(load(&mut m).unwrap(), Loaded::Key(K2, p2));
        assert!(m.s[p1.slot].iter().all(|&b| b == 0xFF), "old key must be wiped after a reset");
    }
    #[test] fn power_loss_at_every_step_never_loses_a_key() {
        for crash in 1..=5 {
            for start in [None, Some(())] {
                let mut m = Mock::new(); let p1 = save(&mut m, &K1, None).unwrap();
                let p2 = if start.is_some() { save(&mut m, &K2, Some(p1)).unwrap() } else { p1 };
                let (old, oldp) = if start.is_some() { (K2, p2) } else { (K1, p1) };
                m.ops = 0; m.crash_at = Some(crash);
                let _ = save(&mut m, &K3, Some(oldp));
                m.crash_at = None;
                match load(&mut m).unwrap() { Loaded::Key(k, _) => assert!(k == old || k == K3, "crash {crash}"), o => panic!("crash {crash}: {o:?}") }
            }
        }
    }
    #[test] fn corruption_is_detected_not_replaced() {
        let mut m = Mock::new(); let p = save(&mut m, &K1, None).unwrap();
        m.s[p.slot][20] ^= 1;                                           // bit flip inside the key
        assert_eq!(load(&mut m).unwrap(), Loaded::Corrupt);              // NOT Blank
        let mut m = Mock::new(); save(&mut m, &K1, None).unwrap(); m.s[1] = vec![0x55; REC_LEN]; // junk in other slot
        assert!(matches!(load(&mut m).unwrap(), Loaded::Key(K1, _)));    // valid slot still used
        let mut m = Mock::new(); m.s[0] = vec![0; REC_LEN]; assert_eq!(load(&mut m).unwrap(), Loaded::Corrupt);
    }
    #[test] fn read_error_is_an_error_not_blank() {
        let mut m = Mock::new(); m.read_err = true; assert!(load(&mut m).is_err());
    }
    #[test] fn recover_after_corrupt() {
        let mut m = Mock::new(); m.s[0] = vec![0; REC_LEN]; m.s[1] = vec![7; REC_LEN];
        let p = save(&mut m, &K2, None).unwrap(); assert_eq!(load(&mut m).unwrap(), Loaded::Key(K2, p));
    }
}
