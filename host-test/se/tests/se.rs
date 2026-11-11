//! Host tests for src/se: the real driver code runs against a byte-level software model of the
//! ATECC608A (frame parsing, CRC, wake/idle/sleep, busy NACKs, GenKey/Sign/Counter/Random, the
//! unlimited signing without any counter, chip identity, the attestation slot) and the site directory,
//! which lives in the Pico's flash (a `DirStore`), never in the chip.

extern crate alloc;

mod se {
    #[path = "../../../../src/se/proto.rs"]
    pub mod proto;
    #[path = "../../../../src/se/chip.rs"]
    pub mod chip;
    #[path = "../../../../src/se/ecdsa.rs"]
    pub mod ecdsa;
    #[path = "../../../../src/se/crypto.rs"]
    pub mod crypto;
    #[path = "../../../../src/se/dirlog.rs"]
    pub mod dirlog;
    #[path = "../../../../src/se/tallylog.rs"]
    pub mod tallylog;
}

use opensk::api::crypto::ec_signing::{EcPublicKey, EcSecretKey, EcSignature};
use opensk::api::crypto::Crypto;
use opensk::api::rng::Rng;
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_chacha::ChaCha8Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use se::chip::{Atecc, Bus, ChipOps};
use se::ecdsa::{self, ChipSerial, DirStore, SeEcdsa, SigTally, SeSecretKey, ATTEST_SLOT, COUNTER_MAX, DIR_LEN, FIRST_CRED_SLOT, HANDLE_ATTEST, SLOTS};
use se::dirlog::{self, Plan};
use se::tallylog;
use se::proto::{self, Error};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------- the chip model

#[derive(Default)]
struct Model {
    awake: bool,
    resp: Vec<u8>,
    pos: usize,
    busy_polls: u32,
    tempkey: Option<[u8; 32]>,
    keys: Vec<Option<SigningKey>>,
    counters: [u32; 2],
    limited: bool, // slots are LimitedUse -> Sign increments counter 0 and stops at COUNTER_MAX
    rng: Option<ChaCha8Rng>,
    commands: Vec<u8>, // opcodes seen
    wakes: u32,
    fail_next_wake: u32,
    no_genkey: Vec<usize>, // slots where GenKey fails (execution error)
    created: Vec<usize>,   // slots where GenKey(create) ran, in order
    config: Vec<u8>,       // 128-byte config zone (serial number, I2C address, lock bytes)
    page: Vec<u8>,         // the directory page of the Pico's flash (all chips), NOT in the chip
    tpage: Vec<u8>,        // the signature-count page of the Pico's flash (all chips)
    stash: Vec<(ChipSerial, Vec<Option<SigningKey>>)>, // chips that are currently "unplugged": their keys
    dir_fails: bool,       // the flash directory cannot be saved
    dir_writes: u32,       // saves of the directory seen
}

/// Programs / erases a flash page like `env/dir_flash.rs` does (erased = 0xFF, programming ANDs).
fn apply(page: &mut Vec<u8>, p: Plan) -> bool {
    let program = |page: &mut Vec<u8>, offset: usize, data: &[u8]| {
        for (i, b) in data.iter().enumerate() {
            page[offset + i] &= b;
        }
    };
    match p {
        Plan::Nothing => {}
        Plan::Full => return false,
        Plan::Append { offset, data } => program(page, offset, &data),
        Plan::Rewrite { data } => {
            *page = vec![0xFF; dirlog::PAGE];
            program(page, 0, &data);
        }
    }
    true
}

impl Model {
    /// Serial number of the chip that is "plugged in" (SN0-3 and SN4-8 of the config zone).
    fn serial(&self) -> ChipSerial {
        let mut s = [0u8; 9];
        s[..4].copy_from_slice(&self.config[..4]);
        s[4..].copy_from_slice(&self.config[8..13]);
        s
    }

    /// Unplugs this chip and plugs in the one with serial byte SN6 = `tag` (a chip seen before comes back
    /// with its keys; a new one is empty). The Pico's flash pages stay.
    fn swap_chip(&mut self, tag: u8) {
        let old = self.serial();
        let keys = std::mem::take(&mut self.keys);
        self.stash.push((old, keys));
        self.config[10] = tag;
        let new = self.serial();
        self.keys = match self.stash.iter().position(|e| e.0 == new) {
            Some(i) => self.stash.remove(i).1,
            None => (0..16).map(|_| None).collect(),
        };
        self.tempkey = None;
    }

    /// The site directory of the connected chip, read from the flash page.
    fn dir(&self) -> [u8; DIR_LEN] {
        dirlog::scan(&self.page, &self.serial()).0
    }

    fn set_dir(&mut self, d: [u8; DIR_LEN]) {
        let p = dirlog::plan(&self.page, &self.serial(), &d);
        assert!(apply(&mut self.page, p));
    }

    /// Signatures counted for chip `serial`.
    fn sigs(&self, serial: &ChipSerial) -> u32 {
        tallylog::scan(&self.tpage, serial).0
    }
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut f = vec![(payload.len() + 3) as u8];
    f.extend_from_slice(payload);
    let crc = proto::crc16(&f).to_le_bytes();
    f.extend_from_slice(&crc);
    f
}

fn status(code: u8) -> Vec<u8> {
    frame(&[code])
}

/// A config zone like a provisioned ATECC608A: serial 01 23 .. EE, revision 00 00 60 03, I2C
/// address 0xC0 (8-bit), LockValue/LockConfig = 0x00 (both zones locked).
fn config_zone() -> Vec<u8> {
    let mut c = vec![0u8; 128];
    c[..4].copy_from_slice(&[0x01, 0x23, 0xA1, 0xB2]);
    c[4..8].copy_from_slice(&[0x00, 0x00, 0x60, 0x03]);
    c[8..13].copy_from_slice(&[0xC3, 0xD4, 0xE5, 0xF6, 0xEE]);
    c[16] = 0xC0;
    c[86] = 0x00;
    c[87] = 0x00;
    c
}

impl Model {
    fn new(limited: bool, counter0: u32) -> Self {
        Model {
            keys: (0..16).map(|_| None).collect(),
            counters: [counter0, 0],
            limited,
            rng: Some(ChaCha8Rng::seed_from_u64(7)),
            config: config_zone(),
            page: vec![0xFF; dirlog::PAGE],
            tpage: vec![0xFF; dirlog::PAGE],
            ..Default::default()
        }
    }

    fn execute(&mut self, op: u8, p1: u8, p2: u16, data: &[u8]) -> Vec<u8> {
        self.commands.push(op);
        match op {
            proto::OP_RANDOM => {
                let mut r = [0u8; 32];
                self.rng.as_mut().unwrap().fill_bytes(&mut r);
                frame(&r)
            }
            proto::OP_GENKEY => {
                let slot = p2 as usize;
                if slot >= 16 {
                    return status(0x0F);
                }
                if p1 == proto::GENKEY_CREATE {
                    if self.no_genkey.contains(&slot) {
                        return status(0x0F);
                    }
                    let k = SigningKey::random(self.rng.as_mut().unwrap());
                    self.keys[slot] = Some(k);
                    self.created.push(slot);
                } else if p1 != proto::GENKEY_PUBLIC {
                    return status(0x03);
                }
                match &self.keys[slot] {
                    Some(k) => {
                        let pt = VerifyingKey::from(k).to_encoded_point(false);
                        frame(&pt.as_bytes()[1..])
                    }
                    None => status(0x0F),
                }
            }
            proto::OP_NONCE => {
                if p1 != proto::NONCE_PASSTHROUGH || data.len() != 32 {
                    return status(0x03);
                }
                let mut t = [0u8; 32];
                t.copy_from_slice(data);
                self.tempkey = Some(t);
                status(0x00)
            }
            proto::OP_SIGN => {
                let slot = p2 as usize;
                let (Some(t), true) = (self.tempkey, p1 == proto::SIGN_EXTERNAL && slot < 16) else {
                    return status(0x0F);
                };
                let Some(k) = &self.keys[slot] else { return status(0x0F) };
                // The provisioned config has no LimitedUse bit: the chip does not count signatures.
                let sig: Signature = k.sign_prehash(&t).unwrap();
                frame(&sig.to_bytes())
            }
            proto::OP_COUNTER => {
                let id = p2 as usize;
                if id > 1 {
                    return status(0x03);
                }
                if p1 == proto::COUNTER_INC {
                    if self.counters[id] >= COUNTER_MAX {
                        return status(0x0F);
                    }
                    self.counters[id] += 1;
                } else if p1 != proto::COUNTER_READ {
                    return status(0x03);
                }
                frame(&self.counters[id].to_le_bytes())
            }
            proto::OP_INFO => {
                if p1 != proto::INFO_REVISION {
                    return status(0x03);
                }
                frame(&self.config[4..8])
            }
            proto::OP_READ => {
                // Config zone, 32-byte blocks only (the only form the firmware uses).
                let block = (p2 >> 3) as usize;
                if p1 != proto::READ_CONFIG_32 || p2 & 7 != 0 || block > 3 {
                    return status(0x03);
                }
                frame(&self.config[block * 32..block * 32 + 32])
            }
            _ => status(0x03),
        }
    }
}

struct FakeBus(Arc<Mutex<Model>>);

impl Bus for FakeBus {
    fn wake_pulse(&mut self) {
        let mut m = self.0.lock().unwrap();
        m.wakes += 1;
        if m.fail_next_wake > 0 {
            m.fail_next_wake -= 1;
            return; // chip does not wake
        }
        m.awake = true;
        m.resp = vec![0x04, 0x11, 0x33, 0x43];
        m.pos = 0;
    }

    fn write(&mut self, d: &[u8]) -> Result<(), ()> {
        let mut m = self.0.lock().unwrap();
        if !m.awake {
            return Err(());
        }
        match d[0] {
            proto::WORD_IDLE => {
                m.awake = false;
                Ok(())
            }
            proto::WORD_SLEEP => {
                m.awake = false;
                m.tempkey = None;
                Ok(())
            }
            proto::WORD_COMMAND => {
                let count = d[1] as usize;
                assert_eq!(d.len(), count + 1, "count byte must cover the frame");
                let crc = proto::crc16(&d[1..d.len() - 2]).to_le_bytes();
                assert_eq!(&d[d.len() - 2..], &crc, "command CRC");
                let (op, p1, p2) = (d[2], d[3], u16::from_le_bytes([d[4], d[5]]));
                let r = m.execute(op, p1, p2, &d[6..d.len() - 2]);
                m.resp = r;
                m.pos = 0;
                m.busy_polls = 1; // the chip is busy for the first poll
                Ok(())
            }
            _ => Err(()),
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<(), ()> {
        let mut m = self.0.lock().unwrap();
        if !m.awake {
            return Err(());
        }
        if m.pos == 0 && m.busy_polls > 0 {
            m.busy_polls -= 1;
            return Err(());
        }
        if m.pos + buf.len() > m.resp.len() {
            return Err(());
        }
        let (p, n) = (m.pos, buf.len());
        buf.copy_from_slice(&m.resp[p..p + n]);
        m.pos += n;
        Ok(())
    }

    fn delay_ms(&mut self, _ms: u32) {}
}

/// The directory store of the tests: the real page format (`dirlog`) on the model's flash page,
/// one directory per chip serial number.
struct MemDir {
    m: Arc<Mutex<Model>>,
    chip: Option<ChipSerial>,
}

impl DirStore for MemDir {
    fn select(&mut self, chip: &ChipSerial) {
        self.chip = Some(*chip);
    }

    fn load(&mut self) -> [u8; DIR_LEN] {
        match &self.chip {
            Some(c) => dirlog::scan(&self.m.lock().unwrap().page, c).0,
            None => [0u8; DIR_LEN],
        }
    }

    fn save(&mut self, dir: &[u8; DIR_LEN]) -> Result<(), ()> {
        let chip = self.chip.ok_or(())?;
        let mut m = self.m.lock().unwrap();
        if m.dir_fails {
            return Err(());
        }
        let p = dirlog::plan(&m.page, &chip, dir);
        if p == Plan::Nothing {
            return Ok(());
        }
        if !apply(&mut m.page, p) {
            return Err(());
        }
        m.dir_writes += 1;
        Ok(())
    }
}

/// The signature counter of the tests: the real page format (`tallylog`), one count per chip serial number.
struct MemTally {
    m: Arc<Mutex<Model>>,
    chip: Option<ChipSerial>,
    total: u32,
}

impl SigTally for MemTally {
    fn select(&mut self, chip: &ChipSerial) {
        self.chip = Some(*chip);
        self.total = tallylog::scan(&self.m.lock().unwrap().tpage, chip).0;
    }

    fn bump(&mut self) {
        let Some(chip) = self.chip else { return };
        self.total += 1;
        let mut m = self.m.lock().unwrap();
        let p = tallylog::plan(&m.tpage, &chip, self.total);
        apply(&mut m.tpage, p);
    }
}

fn chip(limited: bool, c0: u32) -> (Atecc<FakeBus>, Arc<Mutex<Model>>) {
    let m = Arc::new(Mutex::new(Model::new(limited, c0)));
    (Atecc::new(FakeBus(m.clone())), m)
}

// ---------------------------------------------------------------- protocol

#[test]
fn crc_known_vectors() {
    // Wake-up response and the plain success status frame, from the datasheet.
    assert_eq!(proto::crc16(&[0x04, 0x11]).to_le_bytes(), [0x33, 0x43]);
    assert_eq!(proto::crc16(&[0x04, 0x00]).to_le_bytes(), [0x03, 0x40]);
    // Info(revision) command (opcode 0x30, not used by the firmware) as sent by cryptoauthlib.
    let mut f = [0u8; proto::MAX_CMD];
    let n = proto::build_command(&mut f, 0x30, 0, 0, &[]).unwrap();
    assert_eq!(&f[..n], &[0x03, 0x07, 0x30, 0x00, 0x00, 0x00, 0x03, 0x5D]);
    // The longest frame we send (Nonce pass-through, 32 bytes) fits.
    let n = proto::build_command(&mut f, proto::OP_NONCE, proto::NONCE_PASSTHROUGH, 0, &[0u8; 32]).unwrap();
    assert_eq!(n, 40);
}

#[test]
fn response_parsing() {
    assert_eq!(proto::parse_response(&[0x04, 0x00, 0x03, 0x40]).unwrap(), &[] as &[u8]);
    assert_eq!(proto::parse_response(&status(0x0F)), Err(Error::Status(0x0F)));
    let mut bad = status(0x00);
    bad[3] ^= 1;
    assert_eq!(proto::parse_response(&bad), Err(Error::Crc));
    let f = frame(&[1, 2, 3, 4]);
    assert_eq!(proto::parse_response(&f).unwrap(), &[1, 2, 3, 4]);
    assert_eq!(proto::parse_response(&f[..f.len() - 1]), Err(Error::Crc));
    assert_eq!(proto::counter_value(&[1, 0, 0, 0]).unwrap(), 1);
}

// ---------------------------------------------------------------- command layer

fn verify(pk: &[u8; 64], digest: &[u8], sig: &[u8; 64]) {
    let mut sec1 = vec![4u8];
    sec1.extend_from_slice(pk);
    let vk = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    vk.verify_prehash(digest, &Signature::from_slice(sig).unwrap()).unwrap();
}

#[test]
fn chip_commands() {
    let (mut c, m) = chip(false, 0);
    assert_ne!(c.random().unwrap(), c.random().unwrap());
    let pk = c.gen_key(3).unwrap();
    assert_eq!(c.public_key(3).unwrap(), pk);
    let digest: [u8; 32] = Sha256::digest(b"hello").into();
    let sig = c.sign(3, &digest).unwrap();
    verify(&pk, &digest, &sig);
    assert_eq!(c.counter(0).unwrap(), 0);
    assert_eq!(c.counter_inc(1).unwrap(), 1);
    assert_eq!(c.counter_inc(1).unwrap(), 2);
    assert_eq!(c.gen_key(16), Err(Error::Param));
    assert_eq!(c.counter(2), Err(Error::Param));
    // Signing with an empty slot is an execution error, not a hang.
    assert_eq!(c.sign(9, &digest), Err(Error::Status(0x0F)));
    // Every high-level call is wake ... idle: the chip is asleep between calls.
    assert!(!m.lock().unwrap().awake);
    // Nothing is ever written into the chip's data zone: there is no such command any more.
    assert!(!m.lock().unwrap().commands.contains(&proto::OP_WRITE));
}

#[test]
fn wake_is_retried_then_fails() {
    let (mut c, m) = chip(false, 0);
    m.lock().unwrap().fail_next_wake = 2;
    assert!(c.random().is_ok()); // third wake attempt works
    m.lock().unwrap().fail_next_wake = 100;
    assert_eq!(c.random(), Err(Error::Bus));
}

// ---------------------------------------------------------------- OpenSK ECDSA adapter

/// The adapter reaches the chip through one global: tests that use it must not overlap.
static SERIAL: Mutex<()> = Mutex::new(());

struct TestRng(ChaCha8Rng);
impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 { self.0.next_u32() }
    fn next_u64(&mut self) -> u64 { self.0.next_u64() }
    fn fill_bytes(&mut self, d: &mut [u8]) { self.0.fill_bytes(d) }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> { self.0.try_fill_bytes(d); Ok(()) }
}
impl CryptoRng for TestRng {}
impl Rng for TestRng {}

fn install(limited: bool, c0: u32) -> (std::sync::MutexGuard<'static, ()>, Arc<Mutex<Model>>) {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    ecdsa::uninstall();
    let (c, m) = chip(limited, c0);
    ecdsa::install(Box::leak(Box::new(c)));
    ecdsa::install_dir(Box::leak(Box::new(MemDir { m: m.clone(), chip: None })));
    ecdsa::install_tally(Box::leak(Box::new(MemTally { m: m.clone(), chip: None, total: 0 })));
    (g, m)
}

fn check_sig(k: &SeSecretKey, msg: &[u8]) {
    let der = k.sign(msg).to_der();
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    k.public_key().to_coordinates(&mut x, &mut y);
    let mut sec1 = vec![4u8];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let vk = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let sig = Signature::from_der(&der).expect("valid DER");
    vk.verify_prehash(&Sha256::digest(msg), &sig).expect("signature verifies");
}

#[test]
fn key_lifecycle_through_opensk_traits() {
    let (_g, _m) = install(false, 0);
    let mut rng = TestRng(ChaCha8Rng::seed_from_u64(1));
    let k = SeSecretKey::random(&mut rng);
    let handle = k.export();
    assert_eq!(handle.len(), 32);
    assert_eq!(handle, k.export(), "export is deterministic (OpenSK requirement)");
    check_sig(&k, b"message one");

    let k2 = SeSecretKey::import(&handle).expect("handle imports");
    assert_eq!(k2.export(), handle);
    check_sig(&k2, &[0u8; 0]);
    for i in 0..40u8 {
        check_sig(&k2, &[i; 33]); // exercises DER padding of high-bit r / s
    }

    // Rejected handles.
    assert!(SeSecretKey::import(&handle[..31]).is_none());
    let mut bad = handle.clone();
    bad[0] = 3; // unknown version
    assert!(SeSecretKey::import(&bad).is_none());
    let mut bad = handle.clone();
    bad[0] = HANDLE_ATTEST; // attestation version on a credential slot
    assert!(SeSecretKey::import(&bad).is_none());
    let mut bad = handle.clone();
    bad[1] = ATTEST_SLOT; // credential version on the attestation slot
    assert!(SeSecretKey::import(&bad).is_none());
    let mut bad = handle.clone();
    bad[5] ^= 0xFF; // wrong fingerprint
    assert!(SeSecretKey::import(&bad).is_none());
    let mut bad = handle.clone();
    bad[20] = 1; // junk in the padding
    assert!(SeSecretKey::import(&bad).is_none());
}

fn registration_panics(rng: &mut TestRng) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = SeSecretKey::random(rng);
    }))
    .is_err()
}

#[test]
fn keys_are_never_overwritten_when_all_slots_are_used() {
    let (_g, m) = install(false, 0);
    let mut rng = TestRng(ChaCha8Rng::seed_from_u64(2));
    let keys: Vec<_> = (0..SLOTS as usize).map(|_| SeSecretKey::random(&mut rng)).collect();
    let slots: Vec<u8> = keys.iter().map(|k| k.export()[1]).collect();
    let first = FIRST_CRED_SLOT;
    assert_eq!(slots, (first..first + SLOTS).collect::<Vec<_>>(), "free slots are taken in order 1..=9");
    assert_eq!(ecdsa::used_slots(), None, "no scan was run yet");
    // The 10th registration is refused (panic: the trait cannot return an error) ...
    assert!(registration_panics(&mut rng));
    assert!(registration_panics(&mut rng), "and again: still refused");
    // ... and nothing was regenerated: GenKey ran exactly once per slot, every old key still works.
    {
        let g = m.lock().unwrap();
        assert_eq!(g.created, (first as usize..(first + SLOTS) as usize).collect::<Vec<_>>());
        assert_eq!(g.counters, [0, 0], "no counter is used at all");
        assert!(!g.commands.contains(&proto::OP_COUNTER));
    }
    for k in &keys {
        let again = SeSecretKey::import(&k.export()).expect("handle of an existing key still imports");
        check_sig(&again, b"still the same key");
    }
    assert!(slots.iter().all(|&x| x != ATTEST_SLOT));
}

#[test]
fn used_slots_are_counted_from_the_chip_and_by_new_keys() {
    let (_g, _m) = install(false, 0);
    assert_eq!(ecdsa::scan_slots(), Some(0));
    let mut rng = TestRng(ChaCha8Rng::seed_from_u64(8));
    let _a = SeSecretKey::random(&mut rng);
    let _b = SeSecretKey::random(&mut rng);
    assert_eq!(ecdsa::used_slots(), Some(2));
    // A fresh scan (e.g. after a restart) finds the same keys in the chip.
    assert_eq!(ecdsa::scan_slots(), Some(2));
    // Existing keys are found even if the cache is gone: a new key goes to the next free slot.
    let c = SeSecretKey::random(&mut rng);
    assert_eq!(c.export()[1], FIRST_CRED_SLOT + 2);
    assert_eq!(ecdsa::used_slots(), Some(3));
}

#[test]
fn a_bus_error_never_makes_a_used_slot_look_free() {
    let (_g, m) = install(false, 0);
    let mut rng = TestRng(ChaCha8Rng::seed_from_u64(10));
    let k = SeSecretKey::random(&mut rng);
    // The chip stops waking up: reading the slots fails, it must not be taken for "empty".
    m.lock().unwrap().fail_next_wake = 1000;
    assert!(registration_panics(&mut rng));
    assert_eq!(ecdsa::scan_slots(), None);
    m.lock().unwrap().fail_next_wake = 0;
    assert_eq!(m.lock().unwrap().created, vec![FIRST_CRED_SLOT as usize], "no second GenKey");
    assert!(SeSecretKey::import(&k.export()).is_some());
}

#[test]
fn a_slot_that_refuses_genkey_is_skipped() {
    let (_g, m) = install(false, 0);
    m.lock().unwrap().no_genkey = vec![3, 9];
    let mut rng = TestRng(ChaCha8Rng::seed_from_u64(5));
    let slots: Vec<u8> = (0..SLOTS as usize - 2).map(|_| SeSecretKey::random(&mut rng).export()[1]).collect();
    assert_eq!(slots, vec![1, 2, 4, 5, 6, 7, 8], "slots 3 and 9 are never used");
    assert!(registration_panics(&mut rng), "no usable slot left: refused, nothing overwritten");
}

#[test]
fn signatures_are_unlimited_and_not_counted() {
    // Counter 0 sits at its maximum (a used-up budget of the old firmware): the chip would refuse
    // to count, but nothing is counted any more, so every signature still verifies.
    let (_g, m) = install(true, COUNTER_MAX);
    let mut rng = TestRng(ChaCha8Rng::seed_from_u64(3));
    let k = SeSecretKey::random(&mut rng);
    for i in 0..50u8 {
        check_sig(&k, &[i; 8]);
    }
    let g = m.lock().unwrap();
    assert_eq!(g.counters[0], COUNTER_MAX, "Counter 0 is never touched");
    assert_eq!(g.counters, [COUNTER_MAX, 0], "no counter is touched");
    assert!(!g.commands.contains(&proto::OP_COUNTER), "no counter command is ever sent");
    assert_eq!(g.commands.iter().filter(|&&c| c == proto::OP_SIGN).count(), 50);
}

#[test]
fn signing_does_not_use_counter_commands() {
    let (_g, m) = install(false, 0);
    let mut rng = TestRng(ChaCha8Rng::seed_from_u64(4));
    let k = SeSecretKey::random(&mut rng);
    let before = m.lock().unwrap().commands.len();
    check_sig(&k, b"hello");
    let g = m.lock().unwrap();
    assert_eq!(&g.commands[before..], &[proto::OP_NONCE, proto::OP_SIGN], "Nonce + Sign, nothing else");
}

#[test]
fn chip_info_is_read_from_the_config_zone() {
    let (_g, _m) = install(false, 0);
    let i = ecdsa::chip_info().expect("chip answers");
    assert_eq!(i.serial, [0x01, 0x23, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0xEE]);
    assert_eq!(i.revision, [0x00, 0x00, 0x60, 0x03]);
    assert_eq!(i.i2c_addr, 0x60);
    assert!(i.config_locked && i.data_locked);
}

#[test]
fn chip_info_parsing() {
    let mut b0 = [0u8; 32];
    let mut b2 = [0x55u8; 32]; // unlocked zones read 0x55
    b0[16] = 0xC0;
    let i = proto::parse_info(&[0, 0, 0x60, 2], &b0, &b2).unwrap();
    assert!(!i.config_locked && !i.data_locked);
    b2[86 - 64] = 0x00; // LockValue
    let i = proto::parse_info(&[0, 0, 0x60, 2], &b0, &b2).unwrap();
    assert!(i.data_locked && !i.config_locked);
    b2[87 - 64] = 0x00; // LockConfig
    assert!(proto::parse_info(&[0, 0, 0x60, 2], &b0, &b2).unwrap().config_locked);
    assert_eq!(proto::parse_info(&[0, 0, 0x60], &b0, &b2), Err(Error::Param));
    assert_eq!(proto::parse_info(&[0, 0, 0x60, 2], &b0[..31], &b2), Err(Error::Param));
}

#[test]
fn chip_random_and_missing_chip() {
    let (_g, _m) = install(false, 0);
    let a = ecdsa::chip_random().unwrap();
    let b = ecdsa::chip_random().unwrap();
    assert_ne!(a, b);
    assert_ne!(a, [0u8; 32]);
    ecdsa::uninstall();
    assert_eq!(ecdsa::chip_random(), Err(Error::Bus));
    assert_eq!(ecdsa::chip_info(), None);
    assert_eq!(ecdsa::scan_slots(), None);
    assert!(!ecdsa::installed());
}

#[test]
fn pico_crypto_is_an_opensk_crypto() {
    fn takes<C: Crypto>() {}
    takes::<se::crypto::PicoCrypto>();
    let _ = std::any::type_name::<SeEcdsa>();
}

// ---------------------------------------------------------------- attestation key

/// What the provisioning tool does (atecc608a/tools/make_attest_cert.py): GenKey in the attestation
/// slot, then build the handle that OpenSK's attestation store keeps in place of a private key.
fn provision_attestation(m: &Arc<Mutex<Model>>) -> Vec<u8> {
    let mut g = m.lock().unwrap();
    let k = SigningKey::random(g.rng.as_mut().unwrap());
    let pk: [u8; 64] = VerifyingKey::from(&k).to_encoded_point(false).as_bytes()[1..].try_into().unwrap();
    g.keys[ATTEST_SLOT as usize] = Some(k);
    ecdsa::handle(HANDLE_ATTEST, ATTEST_SLOT, &pk)
}

#[test]
fn attestation_handle_layout_matches_the_python_tool() {
    // make_attest_cert.py: bytes([2, 0]) + sha256(pub)[:6] + 24 zero bytes.
    let pk = [0xA5u8; 64];
    let h = ecdsa::handle(HANDLE_ATTEST, ATTEST_SLOT, &pk);
    assert_eq!(h.len(), 32);
    assert_eq!(&h[..2], &[2, ATTEST_SLOT]);
    assert_eq!(&h[2..8], &Sha256::digest(pk)[..6]);
    assert!(h[8..].iter().all(|&b| b == 0));
}

#[test]
fn attestation_key_signs_without_touching_counter_0() {
    let (_g, m) = install(false, COUNTER_MAX - 3);
    let handle = provision_attestation(&m);
    let k = SeSecretKey::import(&handle).expect("attestation handle imports");
    assert_eq!(k.export(), handle, "re-exported handle is the same (version 2)");
    for _ in 0..10 {
        check_sig(&k, b"authData || clientDataHash");
    }
    assert_eq!(m.lock().unwrap().counters[0], COUNTER_MAX - 3, "no signature is counted");
}

#[test]
fn attestation_handle_is_checked_against_the_chip() {
    let (_g, m) = install(false, 0);
    // Not provisioned yet: the slot is empty, the handle cannot be used.
    let pk = [7u8; 64];
    assert!(SeSecretKey::import(&ecdsa::handle(HANDLE_ATTEST, ATTEST_SLOT, &pk)).is_none());
    let handle = provision_attestation(&m);
    assert!(SeSecretKey::import(&handle).is_some());
    // A handle for another key (wrong fingerprint) is refused.
    let mut bad = handle.clone();
    bad[2] ^= 1;
    assert!(SeSecretKey::import(&bad).is_none());
    // Version 1 handles never reach the attestation slot, version 2 handles never the credential slots.
    let mut bad = handle.clone();
    bad[0] = 1;
    assert!(SeSecretKey::import(&bad).is_none());
    let mut bad = handle.clone();
    bad[1] = FIRST_CRED_SLOT;
    assert!(SeSecretKey::import(&bad).is_none());
}

#[test]
fn credential_registration_never_touches_the_attestation_slot() {
    let (_g, m) = install(false, 0);
    let handle = provision_attestation(&m);
    let mut rng = TestRng(ChaCha8Rng::seed_from_u64(9));
    for _ in 0..SLOTS as usize {
        let k = SeSecretKey::random(&mut rng);
        assert!((FIRST_CRED_SLOT..FIRST_CRED_SLOT + SLOTS).contains(&k.export()[1]));
    }
    assert!(registration_panics(&mut rng));
    assert!(SeSecretKey::import(&handle).is_some(), "attestation key survived all registrations");
    assert!(!m.lock().unwrap().created.contains(&(ATTEST_SLOT as usize)));
}

// ---------------------------------------------------------------- one key per relying party

struct HintRng {
    inner: TestRng,
    hint: Option<[u8; 32]>,
}
impl HintRng {
    fn new(seed: u64) -> Self {
        HintRng { inner: TestRng(ChaCha8Rng::seed_from_u64(seed)), hint: None }
    }
}
impl RngCore for HintRng {
    fn next_u32(&mut self) -> u32 { self.inner.next_u32() }
    fn next_u64(&mut self) -> u64 { self.inner.next_u64() }
    fn fill_bytes(&mut self, d: &mut [u8]) { self.inner.fill_bytes(d) }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> { self.inner.try_fill_bytes(d) }
}
impl CryptoRng for HintRng {}
impl Rng for HintRng {
    fn set_rp_id_hash(&mut self, h: &[u8; 32]) {
        self.hint = Some(*h);
    }
    fn take_rp_id_hash(&mut self) -> Option<[u8; 32]> {
        self.hint.take()
    }
}

/// What OpenSK does for a registration: announce the RP, then create the key.
fn register(rng: &mut HintRng, rp: u8) -> SeSecretKey {
    rng.set_rp_id_hash(&[rp; 32]);
    SeSecretKey::random(rng)
}

fn register_panics(rng: &mut HintRng, rp: u8) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = register(rng, rp);
    }))
    .is_err()
}

#[test]
fn accounts_at_the_same_site_share_one_slot() {
    let (_g, m) = install(false, 0);
    let mut rng = HintRng::new(20);
    let a1 = register(&mut rng, 1);
    let a2 = register(&mut rng, 1);
    let b = register(&mut rng, 2);
    let a3 = register(&mut rng, 1);
    assert_eq!(a1.export(), a2.export(), "same site: same slot and key");
    assert_eq!(a1.export(), a3.export());
    assert_ne!(a1.export()[1], b.export()[1], "another site gets its own slot");
    assert_eq!(a1.export()[1], FIRST_CRED_SLOT);
    assert_eq!(b.export()[1], FIRST_CRED_SLOT + 1);
    assert_eq!(m.lock().unwrap().created, vec![FIRST_CRED_SLOT as usize, FIRST_CRED_SLOT as usize + 1], "GenKey ran once per site");
    check_sig(&a2, b"signed by the shared key");
    check_sig(&b, b"signed by the other key");
}

#[test]
fn the_hint_is_used_once_and_without_it_every_key_is_new() {
    let (_g, m) = install(false, 0);
    let mut rng = HintRng::new(21);
    let a = register(&mut rng, 1);
    // No announcement: not the previous site, a fresh slot (and nothing is recorded for it).
    let c = SeSecretKey::random(&mut rng);
    let d = SeSecretKey::random(&mut rng);
    assert_eq!(a.export()[1], FIRST_CRED_SLOT);
    assert_eq!(c.export()[1], FIRST_CRED_SLOT + 1);
    assert_eq!(d.export()[1], FIRST_CRED_SLOT + 2);
    assert_eq!(m.lock().unwrap().dir_writes, 1, "only the announced registration touched the directory");
}

#[test]
fn the_directory_lives_in_the_pico_flash_and_survives_a_restart() {
    let (_g, m) = install(false, 0);
    let mut rng = HintRng::new(22);
    let a = register(&mut rng, 1).export();
    let b = register(&mut rng, 2).export();
    assert_eq!(&m.lock().unwrap().dir()[..7], &[1u8; 7], "site 1 is in the flash directory, slot 1");
    // A restart: new driver, empty caches, same chip, same flash.
    ecdsa::uninstall();
    ecdsa::install(Box::leak(Box::new(Atecc::new(FakeBus(m.clone())))));
    ecdsa::install_dir(Box::leak(Box::new(MemDir { m: m.clone(), chip: None })));
    assert_eq!(register(&mut rng, 2).export(), b);
    assert_eq!(register(&mut rng, 1).export(), a);
    let g = m.lock().unwrap();
    assert_eq!(g.created.len(), 2, "no new key was made");
    assert!(!g.commands.contains(&proto::OP_WRITE), "nothing was written into the chip, only GenKey");
}

#[test]
fn nine_sites_fill_the_chip_but_known_sites_keep_working() {
    let (_g, m) = install(false, 0);
    let mut rng = HintRng::new(23);
    let slots: Vec<u8> = (1..=SLOTS).map(|rp| register(&mut rng, rp).export()[1]).collect();
    assert_eq!(slots, (FIRST_CRED_SLOT..FIRST_CRED_SLOT + SLOTS).collect::<Vec<_>>());
    // A tenth site is refused, again and again ...
    assert!(register_panics(&mut rng, 100));
    assert!(register_panics(&mut rng, 101));
    // ... but every known site can still register more accounts, also the first and the last one.
    assert_eq!(register(&mut rng, 1).export()[1], FIRST_CRED_SLOT);
    assert_eq!(register(&mut rng, SLOTS).export()[1], FIRST_CRED_SLOT + SLOTS - 1);
    let g = m.lock().unwrap();
    assert_eq!(g.created.len(), SLOTS as usize, "nothing was regenerated");
    drop(g);
    for rp in 1..=SLOTS {
        assert_eq!(register(&mut rng, rp).export()[1], FIRST_CRED_SLOT + rp - 1);
    }
}

#[test]
fn a_directory_that_cannot_be_saved_fails_the_registration_and_loses_no_slot() {
    let (_g, m) = install(false, 0);
    m.lock().unwrap().dir_fails = true;
    let mut rng = HintRng::new(24);
    // The key is made, but the site cannot be recorded: nothing is handed out (no silent sharing).
    assert!(register_panics(&mut rng, 1));
    assert_eq!(m.lock().unwrap().dir_writes, 0);
    assert_eq!(m.lock().unwrap().created, vec![FIRST_CRED_SLOT as usize]);
    // Flash works again: the key that was made but never handed out is taken over, no new GenKey.
    m.lock().unwrap().dir_fails = false;
    let a = register(&mut rng, 1);
    assert_eq!(a.export()[1], FIRST_CRED_SLOT);
    assert_eq!(m.lock().unwrap().created.len(), 1, "the slot was reused, not regenerated");
    check_sig(&a, b"works");
}

#[test]
fn without_a_directory_store_nothing_is_shared_or_taken_over() {
    let (_g, m) = install(false, 0);
    ecdsa::uninstall();
    ecdsa::install(Box::leak(Box::new(Atecc::new(FakeBus(m.clone())))));
    let mut rng = HintRng::new(27);
    let a1 = register(&mut rng, 1);
    let a2 = register(&mut rng, 1);
    assert_ne!(a1.export()[1], a2.export()[1], "no directory: every key is new");
    assert_eq!(m.lock().unwrap().dir_writes, 0);
}

#[test]
fn an_entry_without_a_key_behind_it_is_ignored() {
    let (_g, m) = install(false, 0);
    // A directory entry for site 1 in slot 3, but slot 3 holds no key (interrupted registration).
    {
        let mut g = m.lock().unwrap();
        let mut d = g.dir();
        d[2 * 7..3 * 7].copy_from_slice(&[1u8; 7]);
        g.set_dir(d);
    }
    let mut rng = HintRng::new(25);
    let a = register(&mut rng, 1);
    assert_eq!(a.export()[1], FIRST_CRED_SLOT, "first free slot, not the stale one");
    assert!(!m.lock().unwrap().created.contains(&(FIRST_CRED_SLOT as usize + 2)));
    assert_eq!(register(&mut rng, 1).export(), a.export(), "from now on the real entry wins");
}

#[test]
fn slots_that_already_hold_a_key_are_taken_over_one_per_site() {
    let (_g, m) = install(false, 0);
    // Slots 1 and 2 already hold keys, the flash directory is empty (e.g. a freshly erased Pico).
    let mut rng = HintRng::new(26);
    let _ = SeSecretKey::random(&mut rng);
    let _ = SeSecretKey::random(&mut rng);
    assert_eq!(m.lock().unwrap().created.len(), 2);
    let k1 = register(&mut rng, 1);
    let k2 = register(&mut rng, 2);
    assert_eq!(k1.export()[1], FIRST_CRED_SLOT, "site 1 takes the key in slot 1");
    assert_eq!(k2.export()[1], FIRST_CRED_SLOT + 1, "site 2 takes the key in slot 2");
    assert_eq!(m.lock().unwrap().created.len(), 2, "no GenKey: the existing keys were used as they are");
    check_sig(&k1, b"existing key signs");
    check_sig(&k2, b"existing key signs");
    // Both are recorded: the same sites find the same slots again.
    assert_eq!(register(&mut rng, 1).export(), k1.export());
    assert_eq!(register(&mut rng, 2).export(), k2.export());
    // Site 3: no key left to take over, so the first EMPTY slot gets a new key.
    let k3 = register(&mut rng, 3);
    assert_eq!(k3.export()[1], FIRST_CRED_SLOT + 2);
    assert_eq!(m.lock().unwrap().created.len(), 3);
}

#[test]
fn a_mix_of_keyed_and_empty_slots_uses_the_keyed_ones_first() {
    let (_g, m) = install(false, 0);
    // Keys in slots 3 and 5 only (made directly in the chip), everything else empty.
    {
        let mut g = m.lock().unwrap();
        for slot in [3usize, 5] {
            let k = SigningKey::random(g.rng.as_mut().unwrap());
            g.keys[slot] = Some(k);
        }
    }
    let mut rng = HintRng::new(28);
    let slots: Vec<u8> = (1..=4u8).map(|rp| register(&mut rng, rp).export()[1]).collect();
    // Sites 1 and 2 take the existing keys (slots 3, 5); sites 3 and 4 get GenKey in slots 1, 2.
    assert_eq!(slots, vec![3, 5, 1, 2]);
    assert_eq!(m.lock().unwrap().created, vec![1, 2]);
}

#[test]
fn a_slot_owned_by_another_site_is_never_taken_over() {
    let (_g, m) = install(false, 0);
    let mut rng = HintRng::new(29);
    let slots: Vec<u8> = (1..=SLOTS).map(|rp| register(&mut rng, rp).export()[1]).collect();
    assert_eq!(slots, (FIRST_CRED_SLOT..FIRST_CRED_SLOT + SLOTS).collect::<Vec<_>>());
    // All nine slots hold keys and belong to sites 1..=9: a tenth site gets nothing.
    assert!(register_panics(&mut rng, 50));
    assert_eq!(m.lock().unwrap().created.len(), SLOTS as usize);
    // After the Pico's flash was erased (directory gone) the same keys are handed out again, one per site.
    m.lock().unwrap().page = vec![0xFF; dirlog::PAGE]; // the Pico's flash was erased
    let again: Vec<u8> = (101..101 + SLOTS).map(|rp| register(&mut rng, rp).export()[1]).collect();
    assert_eq!(again, slots, "every site gets one of the existing keys, no GenKey");
    assert_eq!(m.lock().unwrap().created.len(), SLOTS as usize);
}

// ---------------------------------------------------------------- flash page of the directory

/// A flash page: erased = 0xFF, programming only clears bits (AND), like the real thing.
const S1: ChipSerial = [0x01, 0x23, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0xEE];
const S2: ChipSerial = [0x01, 0x23, 0xA1, 0xB2, 0xC3, 0xD4, 0x77, 0xF6, 0xEE];

struct Page(Vec<u8>);
impl Page {
    fn blank() -> Self {
        Page(vec![0xFF; dirlog::PAGE])
    }
    fn apply(&mut self, p: Plan) {
        assert!(apply(&mut self.0, p), "page full");
    }
    fn program(&mut self, offset: usize, data: &[u8]) {
        for (i, b) in data.iter().enumerate() {
            self.0[offset + i] &= b;
        }
    }
    fn save(&mut self, dir: &[u8; DIR_LEN]) {
        let p = dirlog::plan(&self.0, &S1, dir);
        self.apply(p);
    }
    fn load(&self) -> [u8; DIR_LEN] {
        dirlog::scan(&self.0, &S1).0
    }
}

fn dir_with(entries: &[(usize, u8)]) -> [u8; DIR_LEN] {
    let mut d = [0u8; DIR_LEN];
    for &(i, v) in entries {
        d[i * 7..(i + 1) * 7].copy_from_slice(&[v; 7]);
    }
    d
}

#[test]
fn a_blank_or_foreign_page_reads_as_an_empty_directory_and_is_formatted_on_the_first_save() {
    assert_eq!(Page::blank().load(), [0u8; DIR_LEN]);
    assert_eq!(dirlog::plan(&Page::blank().0, &S1, &[0u8; DIR_LEN]), Plan::Rewrite { data: dirlog::HEADER.to_vec() });
    let mut old = Page(vec![0x5A; dirlog::PAGE]); // old firmware code
    assert_eq!(old.load(), [0u8; DIR_LEN]);
    let d = dir_with(&[(0, 1)]);
    old.save(&d);
    assert_eq!(old.load(), d);
}

#[test]
fn sites_are_appended_without_an_erase_and_survive_reloading() {
    let mut p = Page::blank();
    let mut d = [0u8; DIR_LEN];
    p.save(&dir_with(&[(0, 1)])); // formats
    for (i, v) in [(0usize, 1u8), (1, 2), (2, 3), (8, 9)] {
        d[i * 7..(i + 1) * 7].copy_from_slice(&[v; 7]);
        let plan = dirlog::plan(&p.0, &S1, &d);
        if i != 0 {
            assert!(matches!(plan, Plan::Append { .. }), "adding a site never erases the page");
        }
        p.apply(plan);
        assert_eq!(p.load(), d);
    }
    assert_eq!(dirlog::plan(&p.0, &S1, &d), Plan::Nothing, "saving the same directory writes nothing");
}

#[test]
fn a_half_written_record_is_ignored_and_the_old_entries_stay() {
    let mut p = Page::blank();
    let d1 = dir_with(&[(0, 1), (1, 2)]);
    p.save(&d1);
    // Power fails while programming the record of slot index 2: only some of its bytes are written.
    let d2 = dir_with(&[(0, 1), (1, 2), (2, 3)]);
    if let Plan::Append { offset, data } = dirlog::plan(&p.0, &S1, &d2) {
        p.program(offset, &data[..11]);
    } else {
        panic!("expected an append");
    }
    assert_eq!(p.load(), d1, "the torn record fails its check");
    // The next save goes after the torn record and works.
    p.save(&d2);
    assert_eq!(p.load(), d2);
}

#[test]
fn the_latest_record_of_a_slot_wins_and_a_full_log_is_compacted() {
    let mut p = Page::blank();
    p.save(&dir_with(&[(0, 1)]));
    // Rewrite the same slot over and over: the log fills up, then the page is formatted again.
    let mut erased = 0;
    for v in 2..=255u8 {
        let d = dir_with(&[(0, v), (1, 77)]);
        if matches!(dirlog::plan(&p.0, &S1, &d), Plan::Rewrite { .. }) {
            erased += 1;
        }
        p.save(&d);
        assert_eq!(p.load(), d);
    }
    for v in 1..=255u8 {
        let d = dir_with(&[(0, v), (1, 77)]);
        p.save(&d);
        assert_eq!(p.load(), d);
    }
    assert!(erased >= 1 || dirlog::MAX_RECS > 255, "a full log is compacted, entries are kept");
}

#[test]
fn a_record_with_a_wrong_check_or_slot_index_is_ignored() {
    let mut p = Page::blank();
    p.save(&dir_with(&[(3, 5)]));
    assert_eq!(p.load(), dir_with(&[(3, 5)]));
    let rec = dirlog::HEADER.len();
    p.0[rec + 10] ^= 0x01; // a flipped tag bit: check fails
    assert_eq!(p.load(), [0u8; DIR_LEN]);
    p.0[rec + 10] ^= 0x01;
    p.0[rec + 9] = SLOTS; // slot index out of range (the check is over the index too)
    assert_eq!(p.load(), [0u8; DIR_LEN]);
}

// ---------------------------------------------------------------- several chips

#[test]
fn each_chip_has_its_own_directory_page_records() {
    let mut p = Page::blank();
    let (da, db) = (dir_with(&[(0, 1), (1, 2)]), dir_with(&[(0, 9), (4, 8)]));
    let pa = dirlog::plan(&p.0, &S1, &da);
    p.apply(pa);
    let pb = dirlog::plan(&p.0, &S2, &db);
    assert!(matches!(pb, Plan::Append { .. }), "a second chip is appended, nothing is erased");
    p.apply(pb);
    assert_eq!(dirlog::scan(&p.0, &S1).0, da);
    assert_eq!(dirlog::scan(&p.0, &S2).0, db);
    assert_eq!(dirlog::scan(&p.0, &[0u8; 9]).0, [0u8; DIR_LEN], "a chip never seen has an empty directory");
    assert_eq!(dirlog::chips(&p.0), vec![S1, S2]);
}

#[test]
fn compaction_keeps_every_other_chip() {
    let mut p = Page::blank();
    let other = dir_with(&[(2, 5), (3, 6)]);
    let pb = dirlog::plan(&p.0, &S2, &other);
    p.apply(pb);
    // Chip 1 rewrites one slot until the log is full and compacted.
    let mut compacted = false;
    for v in 1..=200u8 {
        let d = dir_with(&[(0, v), (1, 7)]);
        let plan = dirlog::plan(&p.0, &S1, &d);
        compacted |= matches!(plan, Plan::Rewrite { .. });
        p.apply(plan);
        assert_eq!(dirlog::scan(&p.0, &S1).0, d);
        assert_eq!(dirlog::scan(&p.0, &S2).0, other, "the other chip's entries survive compaction");
    }
    assert!(compacted);
}

#[test]
fn a_page_that_cannot_hold_another_entry_refuses_instead_of_forgetting_a_chip() {
    let mut p = Page::blank();
    // 14 chips with all 9 slots in use = 126 records, a 15th chip with one more = 127 (the maximum).
    for c in 0..14u8 {
        let mut s = S1;
        s[8] = c;
        let plan = dirlog::plan(&p.0, &s, &dir_with(&(0..9).map(|i| (i, 1 + c)).collect::<Vec<_>>()));
        p.apply(plan);
    }
    let mut last = S1;
    last[8] = 100;
    let plan = dirlog::plan(&p.0, &last, &dir_with(&[(0, 50)]));
    p.apply(plan);
    let before = p.0.clone();
    assert_eq!(dirlog::plan(&p.0, &last, &dir_with(&[(0, 50), (1, 51)])), Plan::Full);
    assert_eq!(p.0, before);
    for c in 0..14u8 {
        let mut s = S1;
        s[8] = c;
        assert_eq!(dirlog::scan(&p.0, &s).0, dir_with(&(0..9).map(|i| (i, 1 + c)).collect::<Vec<_>>()));
    }
}

#[test]
fn a_page_of_the_older_single_chip_format_is_not_read_as_a_directory() {
    let mut p = Page::blank();
    let mut old = dirlog::HEADER;
    old[12] = 1; // version 1 had no serial number in its records
    p.0[..16].copy_from_slice(&old);
    p.0[16..32].copy_from_slice(&[7u8; 16]);
    assert_eq!(dirlog::scan(&p.0, &S1), ([0u8; DIR_LEN], 0, false));
    let d = dir_with(&[(0, 3)]);
    p.save(&d); // formats the page
    assert_eq!(p.load(), d);
}

#[test]
fn signature_counts_are_kept_per_chip() {
    let mut p = vec![0xFFu8; dirlog::PAGE];
    for (serial, n) in [(S1, 3u32), (S2, 2), (S1, 4)] {
        let plan = tallylog::plan(&p, &serial, n);
        assert!(apply(&mut p, plan));
    }
    assert_eq!(tallylog::scan(&p, &S1).0, 4);
    assert_eq!(tallylog::scan(&p, &S2).0, 2);
    assert_eq!(tallylog::scan(&p, &[9u8; 9]).0, 0);
    assert_eq!(tallylog::totals(&p), vec![(S1, 4), (S2, 2)]);
    assert_eq!(tallylog::plan(&p, &S2, 2), Plan::Nothing);
}

#[test]
fn a_full_signature_log_is_compacted_and_keeps_every_chip() {
    let mut p = vec![0xFFu8; dirlog::PAGE];
    let (mut a, mut erased) = (0u32, 0);
    let plan = tallylog::plan(&p, &S2, 41);
    assert!(apply(&mut p, plan));
    for _ in 0..600 {
        a += 1;
        let plan = tallylog::plan(&p, &S1, a);
        erased += matches!(plan, Plan::Rewrite { .. }) as u32;
        assert!(apply(&mut p, plan));
        assert_eq!(tallylog::scan(&p, &S1).0, a);
        assert_eq!(tallylog::scan(&p, &S2).0, 41, "the other chip's count survives the compaction");
    }
    assert!(erased >= 2 && erased <= 4, "an erase only every ~250 signatures, got {erased}");
}

#[test]
fn a_torn_signature_record_is_ignored() {
    let mut p = vec![0xFFu8; dirlog::PAGE];
    let plan = tallylog::plan(&p, &S1, 10);
    assert!(apply(&mut p, plan));
    if let Plan::Append { offset, data } = tallylog::plan(&p, &S1, 11) {
        for (i, b) in data[..10].iter().enumerate() {
            p[offset + i] &= b;
        }
    } else {
        panic!("expected an append");
    }
    assert_eq!(tallylog::scan(&p, &S1).0, 10);
}

#[test]
fn many_chips_in_the_signature_log_are_limited_to_the_highest_totals() {
    let serial = |c: u8| {
        let mut s = S1;
        s[8] = c;
        s
    };
    let mut p = vec![0xFFu8; dirlog::PAGE];
    for c in 0..40u8 {
        let plan = tallylog::plan(&p, &serial(c), 1000 + c as u32);
        assert!(apply(&mut p, plan));
    }
    // One more chip counts until the log is full and gets compacted.
    let x = serial(200);
    let mut n = 0;
    loop {
        n += 1;
        let plan = tallylog::plan(&p, &x, n);
        let compacted = matches!(plan, Plan::Rewrite { .. });
        assert!(apply(&mut p, plan));
        if compacted {
            break;
        }
    }
    assert_eq!(tallylog::totals(&p).len(), tallylog::MAX_CHIPS);
    assert_eq!(tallylog::scan(&p, &x).0, n, "the chip that is counting keeps its total");
    for c in 0..9u8 {
        assert_eq!(tallylog::scan(&p, &serial(c)).0, 0, "the lowest totals are dropped");
    }
    for c in 9..40u8 {
        assert_eq!(tallylog::scan(&p, &serial(c)).0, 1000 + c as u32);
    }
}

fn plug(m: &Arc<Mutex<Model>>, tag: u8) {
    m.lock().unwrap().swap_chip(tag);
    // What the firmware does at start-up with the chip that is connected.
    assert!(ecdsa::chip_info().is_some());
}

#[test]
fn swapping_the_chip_switches_to_that_chips_own_directory_keys_and_count() {
    let (_g, m) = install(false, 0);
    let chip_a = m.lock().unwrap().serial();
    let tag_a = 0xE5; // SN6 of the model's default chip
    let mut rng = HintRng::new(40);
    // Chip A: two sites, three signatures.
    let a1 = register(&mut rng, 1);
    let a2 = register(&mut rng, 2);
    for i in 0..3u8 {
        check_sig(&a1, &[i]);
    }
    assert_eq!(m.lock().unwrap().sigs(&chip_a), 3);

    // Another chip B is plugged in: empty, its own directory (site 1 gets a NEW key in B's slot 1).
    plug(&m, 0x11);
    let chip_b = m.lock().unwrap().serial();
    assert_ne!(chip_a, chip_b);
    assert_eq!(ecdsa::chip_serial(), Some(chip_b));
    assert_eq!(m.lock().unwrap().dir(), [0u8; DIR_LEN], "chip B has no sites yet");
    let b1 = register(&mut rng, 1);
    assert_eq!(b1.export()[1], FIRST_CRED_SLOT);
    assert_ne!(b1.export(), a1.export(), "B's key is not A's key");
    check_sig(&b1, b"signed by chip B");
    check_sig(&b1, b"signed by chip B again");
    assert_eq!(m.lock().unwrap().sigs(&chip_b), 2);
    assert_eq!(m.lock().unwrap().sigs(&chip_a), 3, "A's count is untouched");

    // Back to chip A: its directory, its keys and its count are used again, nothing new is made.
    let created = m.lock().unwrap().created.len();
    plug(&m, tag_a);
    assert_eq!(ecdsa::chip_serial(), Some(chip_a));
    assert_eq!(register(&mut rng, 1).export(), a1.export());
    assert_eq!(register(&mut rng, 2).export(), a2.export());
    assert_eq!(m.lock().unwrap().created.len(), created, "no GenKey: chip A's own sites were found");
    check_sig(&a1, b"A again");
    assert_eq!(m.lock().unwrap().sigs(&chip_a), 4);
    assert_eq!(m.lock().unwrap().sigs(&chip_b), 2);

    // And B once more.
    plug(&m, 0x11);
    assert_eq!(register(&mut rng, 1).export(), b1.export());
    assert_eq!(m.lock().unwrap().created.len(), created, "chip B's site 1 was found as well");
}

#[test]
fn a_chip_swapped_in_between_registrations_is_noticed_at_the_next_registration() {
    let (_g, m) = install(false, 0);
    let mut rng = HintRng::new(41);
    let a1 = register(&mut rng, 1);
    // Swapped without `chip_info()` (e.g. while powered): the registration reads the serial first.
    m.lock().unwrap().swap_chip(0x22);
    let b1 = register(&mut rng, 1);
    assert_ne!(a1.export(), b1.export());
    assert_eq!(m.lock().unwrap().created.len(), 2, "chip B got its own key for site 1");
    check_sig(&b1, b"B");
    // The directory entry of chip A was not overwritten by chip B's registration.
    m.lock().unwrap().swap_chip(0xE5);
    assert_eq!(register(&mut rng, 1).export(), a1.export());
}

#[test]
fn two_chips_never_share_a_slot_owner_even_with_equal_slot_numbers() {
    let (_g, m) = install(false, 0);
    let mut rng = HintRng::new(42);
    let _ = register(&mut rng, 1); // chip A: slot 1 -> site 1
    plug(&m, 0x33);
    // Chip B has keys in slots 1 and 2 already (e.g. made earlier): site 7 takes slot 1, site 8 slot 2;
    // chip A's "slot 1 belongs to site 1" must not make slot 1 of chip B look owned.
    {
        let mut g = m.lock().unwrap();
        for slot in [1usize, 2] {
            let k = SigningKey::random(g.rng.as_mut().unwrap());
            g.keys[slot] = Some(k);
        }
    }
    assert_eq!(register(&mut rng, 7).export()[1], 1);
    assert_eq!(register(&mut rng, 8).export()[1], 2);
}
