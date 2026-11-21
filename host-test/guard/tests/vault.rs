use guard_host_tests::store::*;

struct Mock { s: [[u8; REC_LEN]; 2], t: [u8; TRIES_PAGES], bad_erase: [bool; 2], bad_write: [bool; 2], half_erase: [bool; 2], clear_fails: Vec<u8>, clear_err: bool }
impl Mock { fn new() -> Self { Mock { s: [[0xFF; REC_LEN]; 2], t: [0xFF; TRIES_PAGES], bad_erase: [false; 2], bad_write: [false; 2], half_erase: [false; 2], clear_fails: Vec::new(), clear_err: false } } }
impl Sectors for Mock {
    type Error = ();
    fn read(&mut self, slot: usize, buf: &mut [u8; REC_LEN]) -> Result<(), ()> { *buf = self.s[slot]; Ok(()) }
    fn erase(&mut self, slot: usize) -> Result<(), ()> {
        if self.bad_erase[slot] { return Err(()); }
        if self.half_erase[slot] { for b in self.s[slot][..20].iter_mut() { *b = 0xFF; } return Ok(()); } // "succeeds", leaves seed bytes
        self.s[slot] = [0xFF; REC_LEN]; Ok(())
    }
    fn write(&mut self, slot: usize, rec: &[u8; REC_LEN]) -> Result<(), ()> {
        if self.bad_write[slot] { return Err(()); }
        for (a, b) in self.s[slot].iter_mut().zip(rec) { *a &= b; } Ok(())
    }
    fn tries_read(&mut self, o: &mut [u8; TRIES_PAGES]) -> Result<(), ()> { *o = self.t; Ok(()) }
    fn tries_mark(&mut self, p: usize, v: u8) -> Result<(), ()> { self.t[p] &= v; Ok(()) }
    fn tries_clear(&mut self) -> Result<(), ()> {
        if self.clear_err { return Err(()); }
        // failures that were pending (since the last DONE flag) at the moment of the erase
        let pending = self.t.iter().take_while(|&&b| b != 0xFF).fold(0u8, |f, &b| if b == 0x00 { 0 } else { f + 1 });
        self.clear_fails.push(pending);
        self.t = [0xFF; TRIES_PAGES]; Ok(())
    }
}
fn wrapped() -> Record { Record { wrapped: true, puf: false, puf_slot: 0, m_kib: 0, t_cost: 0, salt: [5; 16], body: [6; 32], tag: [7; 32] } }

#[test]
fn old_plain_record_wiped_normally() {
    let mut m = Mock::new();
    let plain = Record::plain([0xAB; 32]);
    assert!(matches!(replace_record(&mut m, &plain), Replaced::New(s) if s.old_wiped));
    match replace_record(&mut m, &wrapped()) { Replaced::New(s) => assert!(s.old_wiped), r => panic!("{:?}", r) }
    assert!(!m.s.iter().any(|sl| sl.windows(32).any(|w| w == [0xAB; 32])), "plain seed still in flash");
}

#[test]
fn unwipeable_old_record_is_reported_and_retry_works() {
    let mut m = Mock::new();
    replace_record(&mut m, &Record::plain([0xAB; 32]));
    m.bad_erase[0] = true; m.bad_write[0] = true;           // slot 0 holds the plain seed
    match replace_record(&mut m, &wrapped()) { Replaced::New(s) => assert!(!s.old_wiped), r => panic!("{:?}", r) }
    assert_eq!(purge_stale(&mut m), Ok(false));              // retry still fails
    assert!(m.s[0].windows(32).any(|w| w == [0xAB; 32]));    // and the seed really is still there
    m.bad_erase[0] = false; m.bad_write[0] = false;          // flash recovers
    assert_eq!(purge_stale(&mut m), Ok(true));
    assert!(!m.s.iter().any(|sl| sl.windows(32).any(|w| w == [0xAB; 32])));
}

#[test]
fn erase_that_leaves_seed_bytes_is_not_accepted() {
    let mut m = Mock::new();
    replace_record(&mut m, &Record::plain([0xAB; 32]));
    m.half_erase[0] = true; m.bad_write[0] = true;
    // erase "succeeds" but leaves bytes behind and zero-programming fails: must be reported
    match replace_record(&mut m, &wrapped()) { Replaced::New(s) => assert!(!s.old_wiped), r => panic!("{:?}", r) }
}

#[test]
fn failed_write_keeps_old_record() {
    let mut m = Mock::new();
    replace_record(&mut m, &Record::plain([1; 32]));
    m.bad_write[1] = true;
    assert!(matches!(replace_record(&mut m, &wrapped()), Replaced::Kept(r) if !r.wrapped));
}

#[test]
fn record_debug_does_not_leak() {
    let s = format!("{:?}", Record::plain([0x5A; 32]));
    assert!(!s.contains("90") && !s.contains("body") && !s.contains("5A"), "{}", s);
}

#[test]
fn puf_slot_survives_a_save_and_load() {
    let mut m = Mock::new();
    let mut rec = Record::plain([3; 32]);
    rec.puf = true;
    rec.puf_slot = 1;
    assert!(matches!(replace_record(&mut m, &rec), Replaced::New(_)));
    match load(&mut m) {
        Ok(Loaded::Rec(r, _)) => { assert!(r.puf); assert_eq!(r.puf_slot, 1); }
        r => panic!("{:?}", r),
    }
}

#[test]
fn counter_sector_is_never_erased_with_failures_pending() {
    let mut m = Mock::new();
    // 200 rounds of 0..=7 wrong guesses followed by one correct PIN: the sector fills up many times.
    for round in 0..200usize {
        let wrong = round % 8;
        for _ in 0..wrong { begin_try(&mut m).unwrap(); }
        assert_eq!(count_tries(&mut m).unwrap() as usize, wrong);
        let p = begin_try(&mut m).unwrap();
        finish_try(&mut m, p).unwrap();
        assert_eq!(count_tries(&mut m).unwrap(), 0);
    }
    assert!(!m.clear_fails.is_empty(), "the sector should have been recycled");
    assert!(m.clear_fails.iter().all(|&f| f == 0), "erased with failures pending: {:?}", m.clear_fails);
}

#[test]
fn eight_failures_block_even_after_recycling() {
    let mut m = Mock::new();
    for _ in 0..50 { let p = begin_try(&mut m).unwrap(); finish_try(&mut m, p).unwrap(); }
    for _ in 0..TRIES_MAX { begin_try(&mut m).unwrap(); }
    assert_eq!(count_tries(&mut m).unwrap() as usize, TRIES_MAX);
    assert!(begin_try(&mut m).is_err());
}

const D: u8 = 0x00; // DONE flag
const S: u8 = 0x7F; // STARTED flag
fn counter(m: &mut Mock, flags: &[u8]) { m.t = [0xFF; TRIES_PAGES]; m.t[..flags.len()].copy_from_slice(flags); }

#[test]
fn full_sector_with_pending_failures_fails_closed_without_erasing() {
    // A full sector with 7 pending failures (an earlier recycle failed). The old code erased it
    // and re-wrote the marks; a power cut in between zeroed the counter.
    let mut m = Mock::new();
    let mut flags = vec![D; TRIES_PAGES - 7];
    flags.extend([S; 7]);
    counter(&mut m, &flags);
    let before = m.t;
    assert!(begin_try(&mut m).is_err());
    assert!(m.clear_fails.is_empty(), "erased with failures pending: {:?}", m.clear_fails);
    assert_eq!(m.t, before, "the counter must stay untouched");
    assert_eq!(count_tries(&mut m).unwrap(), 7);
    // and it stays closed
    assert!(begin_try(&mut m).is_err());
    assert_eq!(count_tries(&mut m).unwrap(), 7);
}

#[test]
fn failing_recycle_never_lets_the_counter_reset() {
    let mut m = Mock::new();
    m.clear_err = true; // every erase of the counter sector fails
    // correct PINs fill the sector (finish_try ignores the failed recycle)
    for _ in 0..TRIES_PAGES { let p = begin_try(&mut m).unwrap(); finish_try(&mut m, p).unwrap(); }
    // full, nothing pending, erase fails: no attempt is possible, nothing is lost
    assert!(begin_try(&mut m).is_err());
    // the erase works again: normal service resumes
    m.clear_err = false;
    for _ in 0..5 { begin_try(&mut m).unwrap(); }
    assert_eq!(count_tries(&mut m).unwrap(), 5);
    assert!(m.clear_fails.iter().all(|&f| f == 0));
}

#[test]
fn recycles_before_the_first_failure_not_in_the_middle() {
    let mut m = Mock::new();
    counter(&mut m, &[D; 10]); // 6 free pages left, nothing pending
    begin_try(&mut m).unwrap();
    assert_eq!(m.clear_fails, vec![0], "room is made while nothing is pending");
    for _ in 0..TRIES_MAX - 1 { begin_try(&mut m).unwrap(); }
    assert_eq!(count_tries(&mut m).unwrap() as usize, TRIES_MAX);
    assert_eq!(m.clear_fails, vec![0], "no further erase with failures pending");
    assert!(begin_try(&mut m).is_err());
}

#[test]
fn failed_recycle_with_pages_left_still_counts_every_failure() {
    let mut m = Mock::new();
    m.clear_err = true;
    counter(&mut m, &[D; 10]);
    for _ in 0..6 { begin_try(&mut m).unwrap(); } // uses the 6 remaining pages
    assert_eq!(count_tries(&mut m).unwrap(), 6);
    assert!(begin_try(&mut m).is_err(), "full with failures pending: closed");
    assert_eq!(count_tries(&mut m).unwrap(), 6);
}
