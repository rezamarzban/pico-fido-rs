//! Host tests of src/wrap.rs: PIN wrapping bounds and the authenticated PUF-masked plain record.
use guard_host_tests::store::Record;
use guard_host_tests::wrap::*;

const SEED: [u8; 32] = [0x5A; 32];
const KEY: [u8; 32] = [0x11; 32];

#[test]
fn pin_wrap_roundtrip_and_wrong_pin() {
    let rec = wrap(&SEED, &[1; 16], [9; 16], None).unwrap();
    assert_eq!(*unwrap(&rec, &[1; 16], None).unwrap(), SEED);
    assert!(unwrap(&rec, &[2; 16], None).is_none());
}

#[test]
fn stored_time_cost_is_bounded() {
    let mut rec = wrap(&SEED, &[1; 16], [9; 16], None).unwrap();
    rec.t_cost = MAX_T_COST + 1;
    assert!(unwrap(&rec, &[1; 16], None).is_none(), "t_cost above the limit must be refused");
    rec.t_cost = 255;
    assert!(unwrap(&rec, &[1; 16], None).is_none());
    rec.t_cost = 0;
    assert!(unwrap(&rec, &[1; 16], None).is_none());
}

#[test]
fn puf_masked_plain_record_roundtrip() {
    let rec = plain_puf(&SEED, &KEY);
    assert!(rec.puf && !rec.wrapped);
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
