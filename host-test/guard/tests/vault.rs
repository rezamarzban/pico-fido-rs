use guard_host_tests::store::*;

struct Mock { s: [[u8; REC_LEN]; 2], t: [u8; TRIES_PAGES], bad_erase: [bool; 2], bad_write: [bool; 2], half_erase: [bool; 2] }
impl Mock { fn new() -> Self { Mock { s: [[0xFF; REC_LEN]; 2], t: [0xFF; TRIES_PAGES], bad_erase: [false; 2], bad_write: [false; 2], half_erase: [false; 2] } } }
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
    fn tries_clear(&mut self) -> Result<(), ()> { self.t = [0xFF; TRIES_PAGES]; Ok(()) }
}
fn wrapped() -> Record { Record { wrapped: true, puf: false, m_kib: 64, t_cost: 3, salt: [5; 16], body: [6; 32], tag: [7; 32] } }

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
