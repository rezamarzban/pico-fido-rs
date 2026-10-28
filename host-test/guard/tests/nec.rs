//! Host tests of src/nec.rs: NEC frame checks, timing classes and the PIN digest.
use guard_host_tests::nec::*;

#[test]
fn frame_check_bytes() {
    assert!(valid(0x00FF_45BA)); // the example from the reference script
    assert!(valid(0xFF00_FF00));
    assert!(!valid(0x00FF_45BB), "wrong inverted command");
    assert!(!valid(0x01FF_45BA), "wrong inverted address");
    assert!(!valid(0));
}

#[test]
fn timing_classes() {
    assert!(leader_mark_ok(9_000) && !leader_mark_ok(6_000) && !leader_mark_ok(12_000));
    assert_eq!(classify_space(4_500), Space::Frame);
    assert_eq!(classify_space(2_250), Space::Repeat);
    assert_eq!(classify_space(1_000), Space::Bad);
    assert_eq!(classify_space(7_000), Space::Bad);
    assert!(!bit(560) && bit(1_690));
}

#[test]
fn digest_depends_on_every_code_and_the_order() {
    let a = [0x00FF_45BAu32, 0x00FF_46B9, 0x00FF_47B8, 0x00FF_44BB, 0x00FF_40BF, 0x00FF_43BC, 0x00FF_07F8, 0x00FF_15EA];
    let d = digest(&a);
    assert_eq!(d, digest(&a), "deterministic");
    let mut b = a;
    b.swap(0, 1);
    assert_ne!(d, digest(&b), "order matters");
    let mut c = a;
    c[7] = 0x00FF_09F6;
    assert_ne!(d, digest(&c), "every code matters");
    assert_ne!(d, digest(&a[..7]), "the length matters");
    assert_eq!(pin_hash(&d)[..], d[..16]);
}

#[test]
fn magic_pin_hash_is_the_hash_of_ten_zeros() {
    use sha2::{Digest, Sha256};
    assert_eq!(MAGIC_PIN.len(), 10);
    assert_eq!(magic_hash()[..], Sha256::digest(b"0000000000")[..16]);
}
