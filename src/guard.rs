//! Firmware side of `ram_guard`: the protected secrets (the 32-byte master seed and, between the two
//! PIN stages, the 16-byte host PIN hash and the IR PIN digest), boot-time entropy seeding, and the adaptive refresh task.
//!
//! The pool, the DRBG and the share table sit in one `static` behind a critical section, so the
//! refresh task (interrupt executor) and the main thread can both touch them safely. Critical
//! sections here are short: a refresh is split in 7 independent pair steps, each one ChaCha20
//! block plus two XORs of 32 bytes, each in its own critical section (interrupts, USB included,
//! are served between the steps). Anything heavy (HMAC expansion, Argon2) happens OUTSIDE the
//! lock, on a `Zeroizing` copy.
//!
//! Refresh scheduling (see `tick_task`): fast while the device is in use, slower when it is idle,
//! hardly at all while it is locked (no seed, nothing to protect), so the spare CPU time is spent
//! where it matters and the rest is left to sleep.
use core::cell::RefCell;
use embassy_rp::clocks::RoscRng;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use embassy_time::{Duration, Instant, Timer};
use portable_atomic::{AtomicBool, AtomicU32, Ordering};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::keys::fill_random;
use crate::ram_guard::{Drbg, Masked, Pool};

/// Shares per secret (compile-time checked to 4..=16).
pub const SHARES: usize = 8;
/// Shares of the host PIN hash (16 bytes, padded to a 32-byte secret): it only lives from the host PIN
/// check until the session ends, so fewer shares than the seed (and fewer pool slots) are used.
pub const HOST_SHARES: usize = 4;
/// Refresh period while the device is in use (a packet, a reveal or a seed store within the last
/// `ACTIVE_WINDOW_MS`), idle with a seed, and locked (no seed: the task only keeps a slow
/// heartbeat so a sleeping main thread is woken regularly).
const ACTIVE_US: u64 = 500;
const IDLE_US: u64 = 2_000;
const LOCKED_US: u64 = 50_000;
const ACTIVE_WINDOW_MS: u32 = 3_000;
/// The DRBG is reseeded from the conditioned ROSC pool about this often (only with a seed).
const RESEED_MS: u32 = 1_000;

// ---- scheduling state and statistics (relaxed atomics: nothing here is secret) ------------
static LAST_ACTIVITY_MS: AtomicU32 = AtomicU32::new(0);
static TICKING: AtomicBool = AtomicBool::new(false);
static REFRESHES: AtomicU32 = AtomicU32::new(0);
static BUSY_US: AtomicU32 = AtomicU32::new(0);
static MAX_CS_US: AtomicU32 = AtomicU32::new(0);
static MAX_LATE_US: AtomicU32 = AtomicU32::new(0);
static PERIOD_US: AtomicU32 = AtomicU32::new(0);

fn now_ms() -> u32 {
    Instant::now().as_millis() as u32
}

/// Marks "the device is in use": the refresh runs at the fast rate for the next few seconds.
pub fn touch() {
    LAST_ACTIVITY_MS.store(now_ms(), Ordering::Relaxed);
}

fn active() -> bool {
    now_ms().wrapping_sub(LAST_ACTIVITY_MS.load(Ordering::Relaxed)) < ACTIVE_WINDOW_MS
}

/// True once the refresh task runs; it keeps a timer interrupt pending at least every
/// `LOCKED_US`, which is what makes `wfi` sleeps of the main thread safe.
pub fn ticking() -> bool {
    TICKING.load(Ordering::Relaxed)
}

/// Counters for the status display and the stress test.
pub struct Snapshot {
    /// Full refreshes since boot (wrapping).
    pub refreshes: u32,
    /// Time spent refreshing since boot, microseconds (wrapping).
    pub busy_us: u32,
    /// Longest single critical section of a refresh step, microseconds.
    pub max_cs_us: u32,
    /// Latest a refresh tick ran after its due time, microseconds.
    pub max_late_us: u32,
    /// Current refresh period, microseconds.
    pub period_us: u32,
}

pub fn snapshot() -> Snapshot {
    Snapshot {
        refreshes: REFRESHES.load(Ordering::Relaxed),
        busy_us: BUSY_US.load(Ordering::Relaxed),
        max_cs_us: MAX_CS_US.load(Ordering::Relaxed),
        max_late_us: MAX_LATE_US.load(Ordering::Relaxed),
        period_us: PERIOD_US.load(Ordering::Relaxed),
    }
}

fn max_update(a: &AtomicU32, v: u32) {
    if v > a.load(Ordering::Relaxed) {
        a.store(v, Ordering::Relaxed);
    }
}

struct Guard {
    pool: Pool,
    drbg: Drbg,
    seed: Option<Masked<SHARES>>,
    /// Hash of the host PIN, kept after stage 1 of the PIN check until the IR PIN has been entered (and
    /// for the rest of the session, for a PIN change). Wiped by `clear_host` (USB reset, reset).
    host: Option<Masked<HOST_SHARES>>,
    /// Digest of the IR PIN: a candidate between the physical-button stage and the key use, or the proven
    /// IR PIN for the rest of the session (every later button confirmation compares against it).
    ir: Option<Masked<HOST_SHARES>>,
}

impl Guard {
    /// One step of a refresh (see `Masked::refresh_pair`).
    fn refresh_pair(&mut self, k: usize) {
        if let Some(m) = &self.seed {
            m.refresh_pair(&mut self.pool, &mut self.drbg, k);
        }
    }

    fn refresh_host_pair(&mut self, k: usize) {
        if let Some(m) = &self.host {
            m.refresh_pair(&mut self.pool, &mut self.drbg, k);
        }
        if let Some(m) = &self.ir {
            m.refresh_pair(&mut self.pool, &mut self.drbg, k);
        }
    }
}

/// A full refresh, as `Masked::PAIRS` separate short critical sections so that interrupts (USB)
/// are served in between. The secret stays valid after every single step.
fn refresh_once() {
    let mut busy = 0u32;
    for k in 0..Masked::<SHARES>::PAIRS {
        let t0 = Instant::now();
        with(|g| g.refresh_pair(k));
        let dt = Instant::now().as_micros().wrapping_sub(t0.as_micros()) as u32;
        busy = busy.wrapping_add(dt);
        max_update(&MAX_CS_US, dt);
    }
    if has_host() || has_ir() {
        for k in 0..Masked::<HOST_SHARES>::PAIRS {
            let t0 = Instant::now();
            with(|g| g.refresh_host_pair(k));
            let dt = Instant::now().as_micros().wrapping_sub(t0.as_micros()) as u32;
            busy = busy.wrapping_add(dt);
            max_update(&MAX_CS_US, dt);
        }
    }
    BUSY_US.fetch_add(busy, Ordering::Relaxed);
    REFRESHES.fetch_add(1, Ordering::Relaxed);
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
            host: None,
            ir: None,
        })
    });
}

/// Stores (or replaces) the protected seed. `false` if `init` was not called or the pool is full.
pub fn store_seed(secret: &[u8; 32]) -> bool {
    touch();
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
    touch();
    refresh_once();
    // The reveal itself is one short critical section; the caller owns (and wipes) `out`.
    let ok = with(|g| match &g.seed {
        Some(m) => {
            m.reveal_into(&g.pool, out);
            true
        }
        None => false,
    })
    .unwrap_or(false);
    refresh_once();
    ok
}

/// Just-in-time use of the seed: reveals it into a local `Zeroizing`, runs `f`, wipes it on every
/// exit path (return, `?`, unwinding is not used on this target). `None` = locked.
#[allow(dead_code)]
pub fn with_seed<R>(f: impl FnOnce(&[u8; 32]) -> R) -> Option<R> {
    let mut s = Zeroizing::new([0u8; 32]);
    if !reveal_seed_into(&mut s) {
        return None;
    }
    Some(f(&s))
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

/// Stores (or replaces) the hash of the host PIN (stage 1 of the PIN check, see `env/harden.rs`).
/// `false` if `init` was not called or the pool is full.
pub fn store_host(h: &[u8; 16]) -> bool {
    touch();
    let mut padded = Zeroizing::new([0u8; 32]);
    padded[..16].copy_from_slice(h);
    with(|g| {
        if let Some(old) = g.host.take() {
            old.release(&mut g.pool, &mut g.drbg);
        }
        match Masked::<HOST_SHARES>::new(&mut g.pool, &padded, &mut g.drbg) {
            Some(m) => {
                g.host = Some(m);
                true
            }
            None => false,
        }
    })
    .unwrap_or(false)
}

/// Reconstructs the host PIN hash into `out` (refreshed before and after, like the seed). `false` =
/// none stored.
pub fn reveal_host_into(out: &mut Zeroizing<[u8; 16]>) -> bool {
    touch();
    refresh_once();
    let mut full = Zeroizing::new([0u8; 32]);
    let ok = with(|g| match &g.host {
        Some(m) => {
            m.reveal_into(&g.pool, &mut full);
            true
        }
        None => false,
    })
    .unwrap_or(false);
    refresh_once();
    if ok {
        out.copy_from_slice(&full[..16]);
    }
    ok
}

/// Forgets the host PIN hash (shares overwritten with decoys). Safe from any context.
pub fn clear_host() {
    with(|g| {
        if let Some(old) = g.host.take() {
            old.release(&mut g.pool, &mut g.drbg);
        }
    });
}

pub fn has_host() -> bool {
    with(|g| g.host.is_some()).unwrap_or(false)
}

/// Stores (or replaces) the IR PIN digest (see `Guard::ir`). `false` if the pool is full.
pub fn store_ir(d: &[u8; 32]) -> bool {
    touch();
    with(|g| {
        if let Some(old) = g.ir.take() {
            old.release(&mut g.pool, &mut g.drbg);
        }
        match Masked::<HOST_SHARES>::new(&mut g.pool, d, &mut g.drbg) {
            Some(m) => {
                g.ir = Some(m);
                true
            }
            None => false,
        }
    })
    .unwrap_or(false)
}

/// Reconstructs the IR PIN digest into `out` (refreshed before and after). `false` = none stored.
pub fn reveal_ir_into(out: &mut Zeroizing<[u8; 32]>) -> bool {
    touch();
    refresh_once();
    let ok = with(|g| match &g.ir {
        Some(m) => {
            m.reveal_into(&g.pool, out);
            true
        }
        None => false,
    })
    .unwrap_or(false);
    refresh_once();
    ok
}

/// Forgets the IR PIN digest. Safe from any context.
pub fn clear_ir() {
    with(|g| {
        if let Some(old) = g.ir.take() {
            old.release(&mut g.pool, &mut g.drbg);
        }
    });
}

pub fn has_ir() -> bool {
    with(|g| g.ir.is_some()).unwrap_or(false)
}

/// Refresh now (before / after a signing, PIN check or key derivation).
pub fn refresh_now() {
    refresh_once();
}

fn reseed() {
    // Entropy is gathered outside the critical section (it takes about a millisecond).
    let mut fresh = Zeroizing::new([0u8; 32]);
    fill_random(&mut fresh[..]);
    with(|g| g.drbg.reseed(&fresh));
}

/// Periodic refresh on the interrupt executor: it keeps running while the main thread is busy
/// with a signature or waiting for the button. The period adapts: `ACTIVE_US` while in use,
/// `IDLE_US` with a seed but no recent activity, `LOCKED_US` without a seed (nothing to refresh).
#[embassy_executor::task]
pub async fn tick_task() {
    TICKING.store(true, Ordering::Relaxed);
    let mut last_reseed = now_ms();
    #[cfg(feature = "guard_log")]
    let mut last_log = now_ms();
    loop {
        let seed = has_seed() || has_host() || has_ir();
        let period = if !seed {
            LOCKED_US
        } else if active() {
            ACTIVE_US
        } else {
            IDLE_US
        };
        PERIOD_US.store(period as u32, Ordering::Relaxed);
        let due = Instant::now() + Duration::from_micros(period);
        Timer::at(due).await;
        let late = Instant::now().as_micros().saturating_sub(due.as_micros()) as u32;
        max_update(&MAX_LATE_US, late);
        if seed {
            refresh_once();
            if now_ms().wrapping_sub(last_reseed) >= RESEED_MS {
                last_reseed = now_ms();
                reseed();
            }
        }
        #[cfg(feature = "guard_log")]
        {
            let t = now_ms();
            if t.wrapping_sub(last_log) >= 5_000 {
                last_log = t;
                let s = snapshot();
                defmt::info!(
                    "guard: {} refreshes, period {} us, longest critical section {} us, latest tick {} us late",
                    s.refreshes, s.period_us, s.max_cs_us, s.max_late_us
                );
            }
        }
    }
}
