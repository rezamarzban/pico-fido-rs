//! RAM secret protection: a 32-byte secret is never stored as such. It lives as `N` XOR shares
//! (secret = share_0 ^ ... ^ share_{N-1}) in scattered slots of a static pool, and the shares are
//! re-randomised over and over, so a single RAM snapshot (cold boot, debug probe glitch, partial
//! read) is only useful if it covers all N shares of ONE refresh epoch.
//!
//! This file is pure logic (no hardware, no statics) so it can be unit-tested on the host. The
//! firmware singleton, entropy seeding and the 1 ms refresh task are in `guard.rs`.
//!
//! * `Masked<N>` holds only slot INDICES, never secret bytes; the shares live in the [`Pool`].
//! * `refresh` XORs a fresh mask into share 0 and share i, for every i >= 1: the secret is never
//!   reconstructed and nothing is decrypted.
//! * Unused pool slots are filled with random decoys, and the N slots of a secret are picked at
//!   boot at random with no two of them adjacent.
//! * Nothing here derives Debug / Display, and nothing logs.
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Number of 32-byte slots in the pool (2 KiB of RAM).
pub const SLOTS: usize = 64;
const _: () = core::assert!(SLOTS <= 64, "`used` is a u64 bit set");

/// Static-slot storage for the shares (and decoys).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Pool {
    slots: [[u8; 32]; SLOTS],
    used: u64,
}

impl Pool {
    /// A pool whose every slot holds random decoy bytes.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut p = Pool {
            slots: [[0; 32]; SLOTS],
            used: 0,
        };
        for s in p.slots.iter_mut() {
            rng.fill_bytes(s);
        }
        p
    }

    /// Picks `N` free slots at random, no two adjacent to each other or to a used slot.
    fn pick<const N: usize, R: RngCore>(&mut self, rng: &mut R) -> Option<[u8; N]> {
        let mut idx = [0u8; N];
        let mut blocked = self.used | (self.used << 1) | (self.used >> 1);
        let mut chosen = 0u64;
        for slot in idx.iter_mut() {
            let mut found = false;
            for _ in 0..512 {
                let c = (rng.next_u32() as usize) % SLOTS;
                let bit = 1u64 << c;
                if blocked & bit == 0 {
                    *slot = c as u8;
                    blocked |= bit | (bit << 1) | (bit >> 1);
                    chosen |= bit;
                    found = true;
                    break;
                }
            }
            if !found {
                return None;
            }
        }
        self.used |= chosen;
        Some(idx)
    }
}

/// `N` XOR shares of a 32-byte secret (4 <= N <= 16).
pub struct Masked<const N: usize> {
    idx: [u8; N],
}

impl<const N: usize> Masked<N> {
    const N_OK: () = core::assert!(N >= 4 && N <= 16, "Masked<N>: N must be in 4..=16");

    /// Splits `secret` into N shares. `None` if the pool has no room.
    pub fn new<R: RngCore + CryptoRng>(
        pool: &mut Pool,
        secret: &[u8; 32],
        rng: &mut R,
    ) -> Option<Self> {
        let () = Self::N_OK;
        let idx = pool.pick::<N, R>(rng)?;
        let mut acc = Zeroizing::new([0u8; 32]);
        for &i in &idx[..N - 1] {
            let s = &mut pool.slots[i as usize];
            rng.fill_bytes(s);
            for (a, b) in acc.iter_mut().zip(s.iter()) {
                *a ^= b;
            }
        }
        let last = &mut pool.slots[idx[N - 1] as usize];
        for ((l, s), a) in last.iter_mut().zip(secret).zip(acc.iter()) {
            *l = s ^ a;
        }
        Some(Masked { idx })
    }

    /// Re-randomises all shares without reconstructing the secret: for every i >= 1 a fresh mask
    /// is XORed into share 0 and into share i.
    pub fn refresh<R: RngCore + CryptoRng>(&self, pool: &mut Pool, rng: &mut R) {
        let mut r = Zeroizing::new([0u8; 32]);
        let s0 = self.idx[0] as usize;
        for &i in &self.idx[1..] {
            rng.fill_bytes(&mut r[..]);
            for (b, m) in pool.slots[s0].iter_mut().zip(r.iter()) {
                *b ^= m;
            }
            for (b, m) in pool.slots[i as usize].iter_mut().zip(r.iter()) {
                *b ^= m;
            }
        }
    }

    /// Reconstructs the secret into a caller-owned buffer (no by-value move, so no stray stack
    /// copy). The caller must keep `out` in a `Zeroizing` or wipe it.
    pub fn reveal_into(&self, pool: &Pool, out: &mut [u8; 32]) {
        out.fill(0);
        for &i in &self.idx {
            for (o, s) in out.iter_mut().zip(pool.slots[i as usize].iter()) {
                *o ^= s;
            }
        }
    }

    /// Convenience wrapper returning the secret in a `Zeroizing` (the return itself may be a
    /// memcpy; prefer `reveal_into` on hot paths).
    #[allow(dead_code)]
    pub fn reveal(&self, pool: &Pool) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        self.reveal_into(pool, &mut out);
        out
    }

    /// Destroys the shares (overwritten with random decoys) and frees the slots.
    pub fn release<R: RngCore>(self, pool: &mut Pool, rng: &mut R) {
        for &i in &self.idx {
            rng.fill_bytes(&mut pool.slots[i as usize]);
            pool.used &= !(1u64 << i);
        }
    }

    /// The slot indices (not secret). Used by tests.
    #[allow(dead_code)]
    pub fn slots(&self) -> &[u8; N] {
        &self.idx
    }
}

/// ChaCha20 DRBG for the refresh masks. Seeded once at boot from the conditioned entropy and
/// reseeded periodically; the raw TRNG is never used per refresh.
pub struct Drbg(ChaCha20Rng);

impl Drbg {
    pub fn new(seed: &[u8; 32]) -> Self {
        Drbg(ChaCha20Rng::from_seed(*seed))
    }

    /// New key = SHA-256(domain || 32 bytes of the old stream || fresh entropy): a reseed adds
    /// entropy and never replaces the state by something weaker.
    pub fn reseed(&mut self, fresh: &[u8; 32]) {
        let mut old = Zeroizing::new([0u8; 32]);
        self.0.fill_bytes(&mut old[..]);
        let mut k: [u8; 32] = Sha256::new()
            .chain_update(b"ram_guard/reseed/v1")
            .chain_update(&old[..])
            .chain_update(fresh)
            .finalize()
            .into();
        self.0 = ChaCha20Rng::from_seed(k);
        k.zeroize();
    }
}

impl RngCore for Drbg {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}
impl CryptoRng for Drbg {}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([9; 32])
    }

    #[test]
    fn refresh_rerandomises_every_share_and_keeps_the_secret() {
        let mut r = rng();
        let mut pool = Pool::new(&mut r);
        let secret = [0x42u8; 32];
        let m = Masked::<8>::new(&mut pool, &secret, &mut r).unwrap();
        let snap: Vec<[u8; 32]> = m.idx.iter().map(|&i| pool.slots[i as usize]).collect();
        // no single share is the secret
        assert!(snap.iter().all(|s| *s != secret));
        m.refresh(&mut pool, &mut r);
        for (k, &i) in m.idx.iter().enumerate() {
            assert_ne!(snap[k], pool.slots[i as usize], "share {k} unchanged by refresh");
        }
        assert_eq!(*m.reveal(&pool), secret);
    }

    #[test]
    fn release_destroys_shares_and_leaves_no_secret() {
        let mut r = rng();
        let mut pool = Pool::new(&mut r);
        let secret = [0x42u8; 32];
        let m = Masked::<4>::new(&mut pool, &secret, &mut r).unwrap();
        let idx = *m.slots();
        let before: Vec<[u8; 32]> = idx.iter().map(|&i| pool.slots[i as usize]).collect();
        m.release(&mut pool, &mut r);
        assert_eq!(pool.used, 0);
        for (k, &i) in idx.iter().enumerate() {
            assert_ne!(before[k], pool.slots[i as usize]);
        }
    }
}
