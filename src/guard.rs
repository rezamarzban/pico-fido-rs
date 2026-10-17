//! Firmware side of `ram_guard`: the one protected secret (the 32-byte master seed), boot-time
//! entropy seeding, and the 1 ms refresh task.
//!
//! The pool, the DRBG and the share table sit in one `static` behind a critical section, so the
//! refresh task (interrupt executor) and the main thread can both touch them safely. Critical
//! sections here are short: a refresh is ~7 ChaCha20 blocks plus 14 XORs of 32 bytes. Anything
//! heavy (HMAC expansion, Argon2) happens OUTSIDE the lock, on a `Zeroizing` copy.
use core::cell::RefCell;
use embassy_rp::clocks::RoscRng;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use embassy_time::{Duration, Instant, Ticker};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::keys::fill_random;
use crate::ram_guard::{Drbg, Masked, Pool};

/// Shares per secret (compile-time checked to 4..=16).
pub const SHARES: usize = 8;
/// Background refresh period.
const REFRESH_MS: u64 = 1;
/// The DRBG is reseeded from the conditioned ROSC pool every this many ticks (~1 s).
const RESEED_EVERY: u32 = 1000;

struct Guard {
    pool: Pool,
    drbg: Drbg,
    seed: Option<Masked<SHARES>>,
}

impl Guard {
    fn refresh(&mut self) {
        if let Some(m) = &self.seed {
            m.refresh(&mut self.pool, &mut self.drbg);
        }
    }
}

static GUARD: Mutex<CriticalSectionRawMutex, RefCell<Option<Guard>>> =
    Mutex::new(RefCell::new(None));

fn with<R>(f: impl FnOnce(&mut Guard) -> R) -> Option<R> {
    GUARD.lock(|g| g.borrow_mut().as_mut().map(f))
}

/// Seeds the DRBG once at boot and creates the pool. Mixed through SHA-256: ROSC bits, the flash
/// chip's unique ID (not secret, only domain separation between devices), ADC (temperature
/// sensor) noise, timer jitter, and the health-tested conditioned pool from `keys::fill_random`.
/// Call before anything is stored.
pub fn init(flash_uid: &[u8], mut adc_sample: impl FnMut() -> u16) {
    let mut h = Sha256::new();
    h.update(b"ram_guard/boot-seed/v1");
    h.update(flash_uid);
    for _ in 0..64 {
        h.update(adc_sample().to_le_bytes());
        let mut rosc = [0u8; 8];
        RoscRng.fill_bytes(&mut rosc);
        h.update(rosc);
        // Ticks between consecutive samples jitter with the ADC/ROSC timing.
        h.update(Instant::now().as_ticks().to_le_bytes());
    }
    let mut pooled = Zeroizing::new([0u8; 32]);
    fill_random(&mut pooled[..]);
    h.update(&pooled[..]);
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(h.finalize().into());
    let mut drbg = Drbg::new(&seed);
    let pool = Pool::new(&mut drbg);
    GUARD.lock(|g| {
        *g.borrow_mut() = Some(Guard {
            pool,
            drbg,
            seed: None,
        })
    });
}

/// Stores (or replaces) the protected seed. `false` if `init` was not called or the pool is full.
pub fn store_seed(secret: &[u8; 32]) -> bool {
    with(|g| {
        if let Some(old) = g.seed.take() {
            old.release(&mut g.pool, &mut g.drbg);
        }
        match Masked::<SHARES>::new(&mut g.pool, secret, &mut g.drbg) {
            Some(m) => {
                g.seed = Some(m);
                true
            }
            None => false,
        }
    })
    .unwrap_or(false)
}

/// Reconstructs the seed into `out`. Refreshes before AND right after the reveal, so a snapshot
/// of the shares taken during the reveal is already stale when it returns. `false` = no seed
/// (locked). `out` must be a `Zeroizing` owned by the caller.
pub fn reveal_seed_into(out: &mut Zeroizing<[u8; 32]>) -> bool {
    with(|g| {
        g.refresh();
        let ok = match &g.seed {
            Some(m) => {
                m.reveal_into(&g.pool, out);
                true
            }
            None => false,
        };
        g.refresh();
        ok
    })
    .unwrap_or(false)
}

/// Forgets the seed (shares overwritten with decoys). Safe from any context, including the USB
/// handler.
pub fn clear_seed() {
    with(|g| {
        if let Some(old) = g.seed.take() {
            old.release(&mut g.pool, &mut g.drbg);
        }
    });
}

pub fn has_seed() -> bool {
    with(|g| g.seed.is_some()).unwrap_or(false)
}

/// Refresh now (before / after a signing, PIN check or key derivation).
pub fn refresh_now() {
    with(|g| g.refresh());
}

fn reseed() {
    // Entropy is gathered outside the critical section (it takes about a millisecond).
    let mut fresh = Zeroizing::new([0u8; 32]);
    fill_random(&mut fresh[..]);
    with(|g| g.drbg.reseed(&fresh));
}

/// Periodic refresh on the interrupt executor: it keeps running while the main thread is busy
/// with a signature or waiting for the button.
#[embassy_executor::task]
pub async fn tick_task() {
    let mut t = Ticker::every(Duration::from_millis(REFRESH_MS));
    let mut n = 0u32;
    loop {
        t.next().await;
        refresh_now();
        n = n.wrapping_add(1);
        if n.is_multiple_of(RESEED_EVERY) {
            reseed();
        }
    }
}
