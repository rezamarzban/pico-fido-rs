//! Host tests of src/wrap.rs: the two-stage PIN wrapping (host PIN, IR PIN, SRAM-PUF secret ->
//! Argon2id -> AES-256-GCM), Argon2 bounds and the authenticated PUF-masked plain record.
//!
//! `wrap.rs` works in one static Argon2 buffer (one call at a time, as on the device), so the tests
//! take a lock: cargo runs them on several threads.
use guard_host_tests::store::Record;
use guard_host_tests::wrap::*;
use std::sync::Mutex;

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

const SEED: [u8; 32] = [0x5A; 32];
const KEY: [u8; 32] = [0x11; 32];
const HOST: [u8; 16] = [1; 16];
const IR: [u8; 32] = [2; 32];
const SALT: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn expect(rec: &Record, body: &str, gcm_tag: &str, verifier: &str) {
    assert_eq!(rec.body[..], hex(body)[..], "ciphertext");
    assert_eq!(rec.tag[..16], hex(gcm_tag)[..], "GCM tag");
    assert_eq!(rec.tag[16..], hex(verifier)[..], "host verifier");
}

/// Known answers from an independent implementation (Python `cryptography`: Argon2id, AES-GCM,
/// HMAC-SHA-256; see the format description at the top of src/wrap.rs).
#[test]
fn known_answer_ir_record_with_puf() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let rec = wrap_full(&SEED, &HOST, &IR, SALT, Some(&KEY)).unwrap();
    assert!(rec.wrapped && rec.puf && rec.ir);
    expect(
        &rec,
        "19b0e36a6fdd2ccd7b68f16595e4f376952ea4963f3aa37c1a4ded9a40d3d1d8",
        "2914c291853ee38b130c45bd120c608b",
        "5a7505d8ffc453c37533a53ba67253ea",
    );
}

#[test]
fn known_answer_host_only_record_with_puf() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let rec = wrap_host(&SEED, &HOST, SALT, Some(&KEY)).unwrap();
    assert!(rec.wrapped && rec.puf && !rec.ir);
    expect(
        &rec,
        "481dd6ac3a85eb92bdf8d8af3973acbd96947460b450f4893feea2d5737ef773",
        "ff73b4dcdb247a43c374d45fd19d0e6a",
        "40f896c190dd7bcb0d5e50b8975eee9d",
    );
}

#[test]
fn known_answer_ir_record_without_puf() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let rec = wrap_full(&SEED, &HOST, &IR, SALT, None).unwrap();
    assert!(rec.wrapped && !rec.puf && rec.ir);
    expect(
        &rec,
        "6f8468dab5e7ed0c3a35e083cd00b48c642e10526c83c623f35ff2fc113a9497",
        "6001481cf3464d2441d7e3a1779806f4",
        "c62ca8c1037e5c6f95579de3dd6f815e",
    );
}

#[test]
fn ir_record_two_stages_roundtrip() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let rec = wrap_full(&SEED, &HOST, &IR, SALT, Some(&KEY)).unwrap();
    // stage 1: the host PIN is recognised, but nothing is decrypted yet
    assert!(matches!(host_stage(&rec, &HOST, Some(&KEY)), Host::Verified));
    // a wrong host PIN is rejected at stage 1 (before the IR PIN is asked)
    assert!(matches!(host_stage(&rec, &[9; 16], Some(&KEY)), Host::Wrong));
    // stage 2: host PIN + IR PIN open the seed
    assert_eq!(*open_ir(&rec, &HOST, &IR, Some(&KEY)).unwrap(), SEED);
}

#[test]
fn ir_record_wrong_factor_wrong_puf_or_damage_never_opens() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let rec = wrap_full(&SEED, &HOST, &IR, SALT, Some(&KEY)).unwrap();
    assert!(open_ir(&rec, &HOST, &[3; 32], Some(&KEY)).is_none(), "wrong IR PIN");
    assert!(open_ir(&rec, &[9; 16], &IR, Some(&KEY)).is_none(), "wrong host PIN");
    assert!(open_ir(&rec, &HOST, &IR, Some(&[0x22; 32])).is_none(), "wrong PUF key");
    assert!(open_ir(&rec, &HOST, &IR, None).is_none(), "PUF presence must match the record");
    let mut d = wrap_full(&SEED, &HOST, &IR, SALT, Some(&KEY)).unwrap();
    d.body[0] ^= 1;
    assert!(open_ir(&d, &HOST, &IR, Some(&KEY)).is_none(), "damaged ciphertext");
    let mut d = wrap_full(&SEED, &HOST, &IR, SALT, Some(&KEY)).unwrap();
    d.tag[0] ^= 1;
    assert!(open_ir(&d, &HOST, &IR, Some(&KEY)).is_none(), "damaged GCM tag");
    // the associated data binds the parameters: a changed flag or salt must not open
    let mut d = wrap_full(&SEED, &HOST, &IR, SALT, Some(&KEY)).unwrap();
    d.salt[15] ^= 1;
    assert!(open_ir(&d, &HOST, &IR, Some(&KEY)).is_none(), "different salt");
}

#[test]
fn host_only_record_opens_at_stage_one() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let rec = wrap_host(&SEED, &HOST, SALT, Some(&KEY)).unwrap();
    match host_stage(&rec, &HOST, Some(&KEY)) {
        Host::Seed(s) => assert_eq!(*s, SEED),
        _ => panic!("a record without IR PIN must open with the host PIN"),
    }
    assert!(matches!(host_stage(&rec, &[9; 16], Some(&KEY)), Host::Wrong));
    // it is not an IR record: stage 2 does not apply
    assert!(open_ir(&rec, &HOST, &IR, Some(&KEY)).is_none());
}

#[test]
fn same_inputs_with_another_salt_give_another_key_and_ciphertext() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let a = wrap_full(&SEED, &HOST, &IR, SALT, Some(&KEY)).unwrap();
    let b = wrap_full(&SEED, &HOST, &IR, [7; 16], Some(&KEY)).unwrap();
    assert_ne!(a.body, b.body);
    assert_ne!(a.tag, b.tag);
}

#[test]
fn stored_time_cost_is_bounded() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let mut rec = wrap_full(&SEED, &HOST, &IR, SALT, Some(&KEY)).unwrap();
    rec.t_cost = MAX_T_COST + 1;
    assert!(matches!(host_stage(&rec, &HOST, Some(&KEY)), Host::Wrong), "t_cost above the limit must be refused");
    assert!(open_ir(&rec, &HOST, &IR, Some(&KEY)).is_none());
    rec.t_cost = 255;
    assert!(open_ir(&rec, &HOST, &IR, Some(&KEY)).is_none());
    rec.t_cost = 0;
    assert!(open_ir(&rec, &HOST, &IR, Some(&KEY)).is_none());
    rec.t_cost = T_COST;
    rec.m_kib = MAX_M_KIB + 4;
    assert!(open_ir(&rec, &HOST, &IR, Some(&KEY)).is_none(), "memory cost above the buffer must be refused");
}

#[test]
fn expand_gives_four_distinct_blocks() {
    let mut m = [0u8; 128];
    expand_into(&SEED, &mut m);
    for i in 0..4 {
        for j in i + 1..4 {
            assert_ne!(m[i * 32..(i + 1) * 32], m[j * 32..(j + 1) * 32]);
        }
    }
}

#[test]
fn puf_masked_plain_record_roundtrip() {
    let rec = plain_puf(&SEED, &KEY);
    assert!(rec.puf && !rec.wrapped && !rec.ir);
    assert_ne!(rec.body, SEED, "the seed must not be stored in the clear");
    assert!(!legacy_plain_puf(&rec));
    assert_eq!(*plain_seed(&rec, Some(&KEY)).unwrap(), SEED);
}

#[test]
fn puf_masked_plain_record_rejects_wrong_key_and_damage() {
    let rec = plain_puf(&SEED, &KEY);
    // a different PUF key (for example after re-enrolment) must not yield a wrong seed
    assert!(plain_seed(&rec, Some(&[0x22; 32])).is_none());
    let mut damaged = plain_puf(&SEED, &KEY);
    damaged.body[0] ^= 1;
    assert!(plain_seed(&damaged, Some(&KEY)).is_none());
    // key presence must match the record
    assert!(plain_seed(&rec, None).is_none());
}

#[test]
fn legacy_untagged_record_is_still_accepted() {
    let mut rec = plain_puf(&SEED, &KEY);
    rec.tag = [0; 32];
    assert!(legacy_plain_puf(&rec));
    assert_eq!(*plain_seed(&rec, Some(&KEY)).unwrap(), SEED);
}

#[test]
fn unbound_plain_record_needs_no_key() {
    let rec = Record::plain(SEED);
    assert_eq!(*plain_seed(&rec, None).unwrap(), SEED);
}
