use guard_host_tests::ram_guard::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn rng() -> ChaCha20Rng { ChaCha20Rng::from_seed([7; 32]) }
fn secret() -> [u8; 32] { let mut s = [0u8; 32]; for (i, b) in s.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(37).wrapping_add(11); } s }

fn roundtrip<const N: usize>() {
    let mut r = rng();
    let mut pool = Pool::new(&mut r);
    let s = secret();
    let m = Masked::<N>::new(&mut pool, &s, &mut r).unwrap();
    assert_eq!(*m.reveal(&pool), s);
    // slots: distinct and never adjacent
    let mut idx: Vec<i32> = m.slots().iter().map(|&i| i as i32).collect();
    idx.sort();
    for w in idx.windows(2) { assert!(w[1] - w[0] >= 2, "adjacent slots {:?}", idx); }
    for _ in 0..1000 { m.refresh(&mut pool, &mut r); }
    assert_eq!(*m.reveal(&pool), s);
}
#[test] fn n4() { roundtrip::<4>() }
#[test] fn n8() { roundtrip::<8>() }
#[test] fn n16() { roundtrip::<16>() }

#[test]
fn two_secrets_release_reuse_and_exhaustion() {
    let mut r = rng();
    let mut pool = Pool::new(&mut r);
    let a = secret(); let mut b = secret(); b[0] ^= 1;
    let ma = Masked::<8>::new(&mut pool, &a, &mut r).unwrap();
    let mb = Masked::<8>::new(&mut pool, &b, &mut r).unwrap();
    for &i in mb.slots() { assert!(!ma.slots().contains(&i)); assert!(!ma.slots().iter().any(|&j| (i as i32 - j as i32).abs() < 2)); }
    ma.refresh(&mut pool, &mut r); mb.refresh(&mut pool, &mut r);
    assert_eq!(*ma.reveal(&pool), a); assert_eq!(*mb.reveal(&pool), b);
    ma.release(&mut pool, &mut r);
    let mc = Masked::<8>::new(&mut pool, &a, &mut r).unwrap();
    assert_eq!(*mc.reveal(&pool), a);
    assert_eq!(*mb.reveal(&pool), b);
    // exhaustion returns None instead of looping or panicking
    let mut keep = vec![];
    loop { match Masked::<16>::new(&mut pool, &a, &mut r) { Some(m) => keep.push(m), None => break } }
    assert!(keep.len() <= 4);
}

#[test]
fn drbg_reseed_changes_stream_and_is_deterministic_given_inputs() {
    let mut a = Drbg::new(&[1; 32]); let mut b = Drbg::new(&[1; 32]);
    assert_eq!(a.next_u64(), b.next_u64());
    a.reseed(&[2; 32]); b.reseed(&[3; 32]);
    assert_ne!(a.next_u64(), b.next_u64());
    let mut c = Drbg::new(&[1; 32]); let mut d = Drbg::new(&[1; 32]);
    c.reseed(&[9; 32]); d.reseed(&[9; 32]);
    assert_eq!(c.next_u64(), d.next_u64());
}
