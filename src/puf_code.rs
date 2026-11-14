//! The arithmetic of the SRAM-PUF fuzzy extractor, without any hardware access (host-tested in
//! `host-test/se/tests/se.rs`, simulated in `host-test/puf_sim.py`; `puf.rs` reads the RAM).
//!
//! * The PUF region is `REGION_WORDS` words (4 KiB) of SRAM that nothing writes. Cell `j` and cell
//!   `j + PAIR_OFFSET` are combined by XOR: cells that are ones with probability `0.5 + d` give a pair
//!   that is a one with probability `0.5 - 2*d*d` (60 % ones -> 48 %, 70 % -> 42 %), which is what
//!   keeps the helper data from giving the secret away on a biased chip. This is the "pair stream" `R` of `CODE_BITS` bits.
//! * Code offset with a repetition code: the 256-bit secret `s` is repeated `REP` = 63 times
//!   (secret bit `i` -> codeword bit `k*256 + i`, i.e. row `k` is the eight little-endian words of
//!   `s`). Enrolment stores `W = R xor C(s)` (public). Later `R'` is decoded by majority vote of
//!   `R' xor W` (bit-sliced: a 6-bit counter per column, 63 rows, no per-bit loop).
//! * Strength, under the model "independent cells, known bias `p` of the pair stream" (host-test
//!   `puf_sim.py`): the helper data leaks the majority of each column, so the secret keeps about
//!   256 bits at p = 50 %, 244 at 52 %, 212 at 54 %, 167 at 56 %, 77 at 60 %. `plausible` therefore
//!   only accepts a RAM sample whose pair stream is within 46..54 % ones. The reliability at 10 %
//!   raw bit-error rate (18 % per pair) is a failure probability of ~1e-6 per boot.

/// SRAM words reserved for the PUF (must match build.rs).
pub const REGION_WORDS: usize = 1024;
pub const SEC_WORDS: usize = 8;
#[allow(dead_code)] // the host tests use it
pub const SEC_BITS: usize = SEC_WORDS * 32;
pub const REP: usize = 63;
pub const CODE_WORDS: usize = SEC_WORDS * REP;
pub const CODE_BITS: usize = CODE_WORDS * 32;
/// Distance in words between the two cells of a pair.
pub const PAIR_OFFSET: usize = 512;
const _: () = core::assert!(
    REP == 63,
    "the bit-sliced majority counts to 63 in six planes"
);
const _: () = core::assert!(PAIR_OFFSET >= CODE_WORDS && CODE_WORDS + PAIR_OFFSET <= REGION_WORDS);

/// The pair stream of a region: `out[w] = cell word w xor cell word w + PAIR_OFFSET`. `word(i)` reads
/// word `i` of the region; the number of ones in the raw cells used is added to `raw_ones`.
pub fn pair_stream(word: impl Fn(usize) -> u32, raw_ones: &mut u32) -> [u32; CODE_WORDS] {
    let mut out = [0u32; CODE_WORDS];
    for (w, o) in out.iter_mut().enumerate() {
        let (a, b) = (word(w), word(w + PAIR_OFFSET));
        *raw_ones += a.count_ones() + b.count_ones();
        *o = a ^ b;
    }
    out
}

/// Is this a real power-up pattern (not stuck or cleared) whose pair stream is balanced enough that
/// the helper data does not give the secret away (see the module documentation)?
pub fn plausible(raw_ones: u32, stream: &[u32; CODE_WORDS]) -> bool {
    let raw_bits = (2 * CODE_WORDS * 32) as u32;
    let raw_ok = (raw_bits / 4..=raw_bits / 4 * 3).contains(&raw_ones);
    let ones: u32 = stream.iter().map(|w| w.count_ones()).sum();
    let bits = CODE_BITS as u32;
    raw_ok && (bits * 46 / 100..=bits * 54 / 100).contains(&ones)
}

/// The codeword of the secret: every one of the `REP` rows is the secret.
pub fn encode(s: &[u32; SEC_WORDS]) -> [u32; CODE_WORDS] {
    let mut c = [0u32; CODE_WORDS];
    for k in 0..REP {
        c[k * SEC_WORDS..(k + 1) * SEC_WORDS].copy_from_slice(s);
    }
    c
}

/// Majority vote of every column of the `REP` rows of `x`.
pub fn decode(x: &[u32; CODE_WORDS]) -> [u32; SEC_WORDS] {
    let mut s = [0u32; SEC_WORDS];
    for j in 0..SEC_WORDS {
        // Six vertical counter planes: plane p holds bit p of the number of ones in each column.
        let mut plane = [0u32; 6];
        for k in 0..REP {
            let mut carry = x[k * SEC_WORDS + j];
            for p in plane.iter_mut() {
                let t = *p & carry;
                *p ^= carry;
                carry = t;
            }
        }
        // 63 rows: a column has a majority (>= 32 ones) exactly when bit 5 of its count is set.
        s[j] = plane[5];
    }
    s
}

/// How many bits of `x` differ from the codeword of `s` (the raw bit errors of this boot).
pub fn bit_errors(x: &[u32; CODE_WORDS], s: &[u32; SEC_WORDS]) -> u32 {
    let mut e = 0;
    for k in 0..REP {
        for j in 0..SEC_WORDS {
            e += (x[k * SEC_WORDS + j] ^ s[j]).count_ones();
        }
    }
    e
}

pub fn words_of(b: &[u8; 32]) -> [u32; SEC_WORDS] {
    let mut w = [0u32; SEC_WORDS];
    for (i, o) in w.iter_mut().enumerate() {
        *o = u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
    }
    w
}

pub fn bytes_of(w: &[u32; SEC_WORDS]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, v) in w.iter().enumerate() {
        b[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    b
}
