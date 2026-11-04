//! Host tests for src/se: the real driver code runs against a byte-level software model of the
//! ATECC608A (frame parsing, CRC, wake/idle/sleep, busy NACKs, GenKey/Sign/Counter/Random, the
//! LimitedUse counter).

extern crate alloc;

mod se {
    #[path = "../../../../src/se/proto.rs"]
    pub mod proto;
    #[path = "../../../../src/se/auth.rs"]
    pub mod auth;
    #[path = "../../../../src/se/chip.rs"]
    pub mod chip;
    #[path = "../../../../src/se/pin.rs"]
    pub mod pin;
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
use se::auth;
use se::ecdsa::{self, SeEcdsa, SeSecretKey, COUNTER_MAX, SLOTS};
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
    req_auth: bool,          // credential slots have ReqAuth (AuthKey = PIN slot)
    pin_key: Option<[u8; 32]>,
    authorized: bool,
    sn: [u8; 9],
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

impl Model {
    fn new(limited: bool, counter0: u32) -> Self {
        Model {
            keys: (0..16).map(|_| None).collect(),
            counters: [counter0, 0],
            limited,
            sn: [0x01, 0x23, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xEE],
            rng: Some(ChaCha8Rng::seed_from_u64(7)),
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
                    if self.req_auth && !self.authorized {
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
            proto::OP_READ => {
                if p1 != proto::READ_CONFIG_32 || p2 != 0 {
                    return status(0x03);
                }
                let mut c = [0u8; 32];
                c[..4].copy_from_slice(&self.sn[..4]);
                c[8..13].copy_from_slice(&self.sn[4..]);
                frame(&c)
            }
            proto::OP_CHECKMAC => {
                let Some(pk) = self.pin_key else { return status(0x0F) };
                let (Some(tk), true) = (self.tempkey, p1 == proto::CHECKMAC_MODE_TEMPKEY && data.len() == 77) else {
                    return status(0x0F);
                };
                if p2 as u8 != auth::PIN_SLOT {
                    return status(0x0F);
                }
                if self.limited {
                    // the PIN slot is LimitedUse too: every attempt, right or wrong, is one use
                    if self.counters[0] >= COUNTER_MAX {
                        return status(0x0F);
                    }
                    self.counters[0] += 1;
                }
                let mut other = [0u8; 13];
                other.copy_from_slice(&data[64..77]);
                let want = auth::check_mac_response(&pk, &tk, &other, &self.sn);
                self.authorized = data[32..64] == want;
                status(if self.authorized { 0x00 } else { 0x01 })
            }
            proto::OP_NONCE if p1 == proto::NONCE_RANDOM => {
                if data.len() != 20 {
                    return status(0x03);
                }
                let mut rand = [0u8; 32];
                self.rng.as_mut().unwrap().fill_bytes(&mut rand);
                let mut num_in = [0u8; 20];
                num_in.copy_from_slice(data);
                self.tempkey = Some(auth::nonce_tempkey(&rand, &num_in));
                frame(&rand)
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
                if self.req_auth && !self.authorized {
                    return status(0x0F);
                }
                if self.limited {
                    if self.counters[0] >= COUNTER_MAX {
                        return status(0x0F);
                    }
                    self.counters[0] += 1;
                }
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
        m.authorized = false; // a new wake-up starts without any authorisation
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
    chip_pin(limited, c0, None)
}

/// `pin_key`: Some -> credential slots require PIN authorisation (ReqAuth).
fn chip_pin(limited: bool, c0: u32, pin_key: Option<[u8; 32]>) -> (Atecc<FakeBus>, Arc<Mutex<Model>>) {
    let mut model = Model::new(limited, c0);
    model.req_auth = pin_key.is_some();
    model.pin_key = pin_key;
    let m = Arc::new(Mutex::new(model));
    (Atecc::new(FakeBus(m.clone())), m)
}

// ---------------------------------------------------------------- protocol

#[test]
fn crc_known_vectors() {
    // Wake-up response and the plain success status frame, from the datasheet.
    assert_eq!(proto::crc16(&[0x04, 0x11]).to_le_bytes(), [0x33, 0x43]);
    assert_eq!(proto::crc16(&[0x04, 0x00]).to_le_bytes(), [0x03, 0x40]);
    // Info(revision) command as sent by cryptoauthlib.
    let mut f = [0u8; proto::MAX_CMD];
    let n = proto::build_command(&mut f, proto::OP_INFO, 0, 0, &[]).unwrap();
    assert_eq!(&f[..n], &[0x03, 0x07, 0x30, 0x00, 0x00, 0x00, 0x03, 0x5D]);
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
    bad[0] = 2;
    assert!(SeSecretKey::import(&bad).is_none());
    let mut bad = handle.clone();
    bad[1] = SLOTS;
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
    assert_eq!(slots[..SLOTS as usize], (0..SLOTS).collect::<Vec<_>>()[..], "round robin from slot 0");
    assert_eq!(slots[SLOTS as usize], 0);
    assert_eq!(m.lock().unwrap().counters[1], SLOTS as u32 + 2, "cursor lives in chip counter 1");
    // Slots 0 and 1 were recycled: their old handles are dead, the others still work.
    assert!(SeSecretKey::import(&keys[0].export()).is_none());
    assert!(SeSecretKey::import(&keys[1].export()).is_none());
    for k in &keys[2..] {
        assert!(SeSecretKey::import(&k.export()).is_some());
    }
}

#[test]
fn signature_budget_is_enforced_by_the_chip() {
    // 3 signatures left: counter 0 starts at MAX-3.
    let (_g, m) = install(true, COUNTER_MAX - 3);
    let mut rng = TestRng(ChaCha8Rng::seed_from_u64(3));
    let k = SeSecretKey::random(&mut rng);
    assert_eq!(ecdsa::budget_left(), Some(3));
    for _ in 0..3 {
        check_sig(&k, b"ok");
    }
    assert_eq!(ecdsa::budget_left(), Some(0));
    // The adapter cannot report errors: the 4th signature is an all-zero one nobody accepts.
    let der = k.sign(b"too many").to_der();
    let mut x = ([0u8; 32], [0u8; 32]);
    k.public_key().to_coordinates(&mut x.0, &mut x.1);
    let mut sec1 = vec![4u8];
    sec1.extend_from_slice(&x.0);
    sec1.extend_from_slice(&x.1);
    let vk = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    match Signature::from_der(&der) {
        Ok(sig) => assert!(vk.verify_prehash(&Sha256::digest(b"too many"), &sig).is_err()),
        Err(_) => {} // zero r/s is not even a valid signature encoding
    }
    assert_eq!(m.lock().unwrap().counters[0], COUNTER_MAX);
}

#[test]
fn rng_mixing_and_missing_chip() {
    let (_g, _m) = install(false, 0);
    let mut buf = [0u8; 70];
    ecdsa::mix_random(&mut buf);
    assert!(buf.iter().any(|&b| b != 0));
    ecdsa::uninstall();
    let mut buf = [0u8; 8];
    ecdsa::mix_random(&mut buf); // silent no-op
    assert_eq!(buf, [0u8; 8]);
    assert_eq!(ecdsa::budget_left(), None);
    assert!(!ecdsa::installed());
}

#[test]
fn pico_crypto_is_an_opensk_crypto() {
    fn takes<C: Crypto>() {}
    takes::<se::crypto::PicoCrypto>();
    let _ = std::any::type_name::<SeEcdsa>();
}

// ---------------------------------------------------------------- PIN authorisation

fn unhex<const N: usize>(h: &str) -> [u8; N] {
    let mut a = [0u8; N];
    for i in 0..N {
        a[i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
    }
    a
}

/// Generated by cryptoauthlib's own C code (atcah_check_mac, SHA-256 of the nonce message):
/// (slot key, RandOut, NumIn, serial, OtherData, "TempKey:ClientResponse").
const C_VECTORS: &[(&str, &str, &str, &str, &str, &str)] = &[
    ("01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da", "05080b0e1114171a1d202326292c2f3235383b3e4144474a4d505356595c5f62", "0000000000000000000000000000000000000000", "230101010101010101", "00000000000000000000000000", "d1b5b8420b7f40431467d1ec097c9edcf944494e5c9d6fb6e71bb36c88677a75:d55d9cfe7ef4815fb0a93bcb38b70535ff1adfea266d5c15f012d066334ca638"),
    ("20272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f9", "16191c1f2225282b2e3134373a3d404346494c4f5255585b5e6164676a6d7073", "0102030405060708090a0b0c0d0e0f1011121314", "230203040506070809", "01060b10151a1f24292e33383d", "7256571777f1e9baa8fa7eb0fb0f412810eed77e670b819ca99312314bd0f19a:7bf8a7a3c69110e1395e8102e06f4d866184bed139ad7e430b20e0a476bcb72a"),
    ("3f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a1118", "272a2d303336393c3f4245484b4e5154575a5d606366696c6f7275787b7e8184", "02030405060708090a0b0c0d0e0f101112131415", "23030507090b0d0f11", "02070c11161b20252a2f34393e", "62048c7ebb3652b4ff9586106ba2320da8c846dd62ae0193ac4cebaf1f274b6c:30641529efcc468be309a3ff4b2b8a60d7828774fa65b80327896538410e2201"),
    ("5e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b22293037", "383b3e4144474a4d505356595c5f6265686b6e7174777a7d808386898c8f9295", "030405060708090a0b0c0d0e0f10111213141516", "2304070a0d10131619", "03080d12171c21262b30353a3f", "0d52abc61016c7721b1e722bd6041f46fb0ff65d4ab851ee238d224672a25ed4:629d4ecc1e10b0957391cf90cd6c2b420aa1d721da02a7783912dac1f4fa60ba"),
];

#[test]
fn nonce_and_checkmac_match_cryptoauthlib() {
    for (key, rand, numin, sn, other, want) in C_VECTORS {
        let (tk_h, resp_h) = want.split_once(':').unwrap();
        let tk = auth::nonce_tempkey(&unhex(rand), &unhex(numin));
        assert_eq!(tk, unhex::<32>(tk_h), "TempKey");
        let resp = auth::check_mac_response(&unhex(key), &tk, &unhex(other), &unhex(sn));
        assert_eq!(resp, unhex::<32>(resp_h), "CheckMac response");
    }
}

#[test]
fn pin_key_vector_matches_python_tool() {
    // atecc608a/tools/pin_key.py computes the same value for provisioning.
    let sn: auth::Serial = unhex("0123aabbccddeeffee");
    let hash: [u8; 16] = unhex("03ac674216f3e15c761ee1a5e255f067"); // LEFT(SHA-256("1234"), 16)
    assert_eq!(hex(&auth::pin_key(&sn, &hash)), PIN_KEY_VECTOR);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const PIN_KEY_VECTOR: &str = "304346fdece1a73fc067c36125ff6eec55ab5745ed378e7cebba3cb3aa9485c5";

fn gated(limited: bool, c0: u32) -> (std::sync::MutexGuard<'static, ()>, Arc<Mutex<Model>>, [u8; 16]) {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    ecdsa::uninstall();
    let hash: [u8; 16] = unhex("03ac674216f3e15c761ee1a5e255f067");
    let sn = [0x01, 0x23, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xEE];
    let (c, m) = chip_pin(limited, c0, Some(auth::pin_key(&sn, &hash)));
    ecdsa::install(Box::leak(Box::new(c)));
    (g, m, hash)
}

#[test]
fn signing_is_gated_by_the_chip_pin() {
    let (_g, m, hash) = gated(false, 0);
    let mut rng = TestRng(ChaCha8Rng::seed_from_u64(5));
    // No PIN yet: the chip refuses to create a key (the adapter panics: a registration cannot proceed).
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| SeSecretKey::random(&mut rng))).is_err());

    // Wrong PIN: refused by the chip.
    let mut bad = hash;
    bad[0] ^= 1;
    assert_eq!(se::pin::verify(&bad), Err(Error::Status(1)));
    assert!(!m.lock().unwrap().authorized);

    // Right PIN: register and sign.
    se::pin::verify(&hash).expect("right PIN");
    let k = SeSecretKey::random(&mut rng);
    check_sig(&k, b"after PIN");
    let handle = k.export();

    // Lock (token expired / power-up): the chip refuses again, even with the handle in hand.
    se::pin::lock();
    let k2 = SeSecretKey::import(&handle).expect("public key needs no PIN");
    let der = k2.sign(b"locked").to_der();
    let sig = Signature::from_der(&der);
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    k2.public_key().to_coordinates(&mut x, &mut y);
    let mut sec1 = vec![4u8];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let vk = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    if let Ok(sig) = sig {
        assert!(vk.verify_prehash(&Sha256::digest(b"locked"), &sig).is_err());
    }
    // And with the PIN again it works.
    se::pin::verify(&hash).unwrap();
    check_sig(&k2, b"again");
    se::pin::lock();
}

#[test]
fn pin_attempts_and_authorised_signatures_spend_the_chip_budget() {
    // 12 units left. Every authorised session costs one CheckMac (right or wrong) on the PIN slot;
    // a signature also costs the Sign itself.
    let (_g, m, hash) = gated(true, COUNTER_MAX - 12);
    let mut rng = TestRng(ChaCha8Rng::seed_from_u64(6));
    let mut bad = hash;
    bad[3] ^= 0x80;
    assert_eq!(se::pin::verify(&bad), Err(Error::Status(1))); // -1
    se::pin::verify(&hash).unwrap(); // -1
    let k = SeSecretKey::random(&mut rng); // GenKey session: CheckMac -1 (GenKey itself: verify on hardware)
    assert_eq!(ecdsa::budget_left(), Some(9));
    check_sig(&k, b"a"); // CheckMac + Sign = -2
    assert_eq!(ecdsa::budget_left(), Some(7));
    for _ in 0..3 {
        check_sig(&k, b"b"); // -6
    }
    assert_eq!(ecdsa::budget_left(), Some(1));
    se::pin::verify(&hash).unwrap(); // -1 -> 0
    assert_eq!(ecdsa::budget_left(), Some(0));
    // Budget gone: neither PIN nor signature works any more.
    assert_eq!(se::pin::verify(&hash), Err(Error::Status(0x0F)));
    assert_eq!(m.lock().unwrap().counters[0], COUNTER_MAX);
    se::pin::lock();
}
