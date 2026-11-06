//! Host tests for src/se: the real driver code runs against a byte-level software model of the
//! ATECC608A (frame parsing, CRC, wake/idle/sleep, busy NACKs, GenKey/Sign/Counter/Random, the
//! unlimited signing without any counter, chip identity, the attestation slot).

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
use se::ecdsa::{self, SeEcdsa, SeSecretKey, ATTEST_SLOT, COUNTER_MAX, FIRST_CRED_SLOT, HANDLE_ATTEST, SLOTS};
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
    config: Vec<u8>,       // 128-byte config zone (serial number, I2C address, lock bytes)
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

#[test]
fn oldest_credential_is_evicted_after_all_slots_are_used() {
    let (_g, m) = install(false, 0);
    let mut rng = TestRng(ChaCha8Rng::seed_from_u64(2));
    let keys: Vec<_> = (0..SLOTS as usize + 2).map(|_| SeSecretKey::random(&mut rng)).collect();
    let slots: Vec<u8> = keys.iter().map(|k| k.export()[1]).collect();
    let first = FIRST_CRED_SLOT;
    assert_eq!(slots[..SLOTS as usize], (first..first + SLOTS).collect::<Vec<_>>()[..], "round robin over slots 1..=9");
    assert_eq!(slots[SLOTS as usize], first);
    assert!(slots.iter().all(|&x| x != ATTEST_SLOT));
    assert_eq!(m.lock().unwrap().counters[1], SLOTS as u32 + 2, "cursor lives in chip counter 1");
    // The first two credential slots were recycled: their old handles are dead, the others still work.
    assert!(SeSecretKey::import(&keys[0].export()).is_none());
    assert!(SeSecretKey::import(&keys[1].export()).is_none());
    for k in &keys[2..] {
        assert!(SeSecretKey::import(&k.export()).is_some());
    }
}

#[test]
fn a_slot_that_refuses_genkey_is_skipped() {
    let (_g, m) = install(false, 0);
    m.lock().unwrap().no_genkey = vec![3, 9];
    let mut rng = TestRng(ChaCha8Rng::seed_from_u64(5));
    let slots: Vec<u8> = (0..14).map(|_| SeSecretKey::random(&mut rng).export()[1]).collect();
    assert!(slots.iter().all(|s| ![3u8, 9, ATTEST_SLOT].contains(s)), "{slots:?}");
    assert!(slots.iter().any(|&s| s == 4), "the slot after the broken one is used");
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
    assert_eq!(g.counters[1], 1, "only Counter 1 (slot cursor, one GenKey) moved");
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
fn chip_info_and_registration_count() {
    let (_g, _m) = install(false, 0);
    let i = ecdsa::chip_info().expect("chip answers");
    assert_eq!(i.serial, [0x01, 0x23, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0xEE]);
    assert_eq!(i.revision, [0x00, 0x00, 0x60, 0x03]);
    assert_eq!(i.i2c_addr, 0x60);
    assert!(i.config_locked && i.data_locked);
    assert_eq!(ecdsa::registrations(), Some(0));
    let mut rng = TestRng(ChaCha8Rng::seed_from_u64(6));
    let _ = SeSecretKey::random(&mut rng);
    let _ = SeSecretKey::random(&mut rng);
    assert_eq!(ecdsa::registrations(), Some(2));
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
    assert_eq!(ecdsa::registrations(), None);
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
    for _ in 0..(3 * SLOTS as usize) {
        let k = SeSecretKey::random(&mut rng);
        assert!((FIRST_CRED_SLOT..FIRST_CRED_SLOT + SLOTS).contains(&k.export()[1]));
    }
    assert!(SeSecretKey::import(&handle).is_some(), "attestation key survived all registrations");
}
