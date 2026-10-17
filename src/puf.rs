//! SRAM PUF: a device-bound key from the power-up state of 496 bytes of RAM that nothing writes.
//!
//! * `build.rs` carves `REGION_BYTES` at 0x2000_0000 out of the linker's RAM, so no startup code,
//!   `.bss`, `.data`, heap or stack ever touches it; this module only READS it.
//! * Fuzzy extractor (code offset, repetition code, interleaved): the 128-bit secret `s` is
//!   repeated `REP` = 31 times (secret bit `i` -> codeword bits `k*128 + i`). Enrolment stores the
//!   public helper `W = R xor C(s)` plus an 8-byte check in one flash sector. Later `R'` is
//!   decoded by majority vote of `R' xor W`; the check tells a good decode from a bad one.
//!   Up to 15 of 31 votes per bit may be wrong; the measured raw bit-error count is logged on
//!   every boot (`puf: ... bit errors`): use it to judge your chip (see SECURITY.md).
//! * Key = HMAC-SHA-256(s, "sram-puf-key-v1"). It is derived on demand and never kept in RAM.
//! * Enrolment only happens on a power-on reset (`CHIP_RESET.HAD_POR`), because after a warm
//!   reset the RAM may hold something else than a fresh power-up pattern. Decoding is attempted
//!   on every boot: after a warm reset the sample is usually still intact and the check decides.
//!
//! What it buys, honestly: a copy of the FLASH alone (dump, backup, desoldered chip read in a
//! programmer) no longer contains enough to attack the PIN or recover the seed. It does NOT stop
//! anyone who can run code on the device (BOOTSEL / SWD): they can read the same RAM at power-up.
use core::cell::RefCell;
use defmt::{info, warn};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use portable_atomic::{AtomicBool, Ordering};
use zeroize::{Zeroize, Zeroizing};

use crate::keys::{fill_random, Fl};
use crate::{FLASH_SIZE, PUF_BYTES, VAULT_BYTES};

/// RAM bytes reserved at the start of SRAM (must match build.rs).
pub const REGION_BYTES: usize = 512;
const REGION_ADDR: usize = 0x2000_0000;

const SEC_BITS: usize = 128;
const REP: usize = 31;
const CODE_BITS: usize = SEC_BITS * REP; // 3968
const CODE_BYTES: usize = CODE_BITS / 8; // 496
const _: () = core::assert!(
    CODE_BITS.is_multiple_of(8) && CODE_BYTES <= REGION_BYTES && CODE_BYTES.is_multiple_of(4)
);

/// Flash sector holding the helper data (just below the vault; carved from the key-value store).
const OFFSET: u32 = (FLASH_SIZE - VAULT_BYTES - PUF_BYTES) as u32;
const MAGIC: [u8; 4] = *b"PUF1";
const CHECK_LEN: usize = 8;
const HASH_LEN: usize = 16;
const IMG_LEN: usize = 4 + CHECK_LEN + CODE_BYTES + HASH_LEN;
const _: () = core::assert!(IMG_LEN <= PUF_BYTES);

/// CHIP_RESET register (VREG_AND_CHIP_RESET + 0x08), bit 8 = HAD_POR.
const CHIP_RESET: *const u32 = 0x4006_4008 as *const u32;
const HAD_POR: u32 = 1 << 8;

/// Set whenever the PUF is required (`sram_puf`) but its key is not available, or a record that
/// depends on it cannot be used. The LED blinker shows it (3 short blinks, pause) until the
/// condition is cleared by a boot / reset that has a working key.
static FAULT: AtomicBool = AtomicBool::new(false);

pub fn set_fault(on: bool) {
    FAULT.store(on, Ordering::Relaxed);
}

pub fn fault() -> bool {
    FAULT.load(Ordering::Relaxed)
}

/// Any other locked state (damaged / unknown vault, failed migration, ...). Shown by the LED like
/// `fault()` but kept apart: `HardenPersist::init` only postpones a pending reset for `fault()`
/// (PUF key unavailable), never for this one.
static SEC_FAULT: AtomicBool = AtomicBool::new(false);

pub fn set_sec_fault(on: bool) {
    SEC_FAULT.store(on, Ordering::Relaxed);
}

/// What the LED shows: either condition.
pub fn led_fault() -> bool {
    fault() || SEC_FAULT.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum Status {
    /// Built without `sram_puf`.
    Disabled,
    /// Sector is erased: nothing enrolled yet.
    Blank,
    /// Sector holds something that is not a valid enrolment.
    Damaged,
    /// Valid enrolment, but this boot's RAM sample does not decode (check failed).
    Noisy,
    Ready,
}

pub struct Puf {
    flash: &'static RefCell<Fl>,
    status: Status,
    por: bool,
    check: [u8; CHECK_LEN],
    helper: [u8; CODE_BYTES],
}

fn bit(buf: &[u8], i: usize) -> u8 {
    (buf[i >> 3] >> (i & 7)) & 1
}

fn mac(s: &[u8; 16], label: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(s).unwrap();
    m.update(label);
    m.finalize().into_bytes().into()
}

fn read_sample(out: &mut [u8; CODE_BYTES]) {
    for i in (0..CODE_BYTES).step_by(4) {
        // SAFETY: the region is reserved in memory.x, mapped SRAM, 4-byte aligned, read-only here.
        let w = unsafe { ((REGION_ADDR + i) as *const u32).read_volatile() };
        out[i..i + 4].copy_from_slice(&w.to_le_bytes());
    }
}

fn encode(s: &[u8; 16]) -> [u8; CODE_BYTES] {
    let mut c = [0u8; CODE_BYTES];
    for k in 0..REP {
        for i in 0..SEC_BITS {
            if bit(s, i) == 1 {
                let b = k * SEC_BITS + i;
                c[b >> 3] |= 1 << (b & 7);
            }
        }
    }
    c
}

/// Majority decode of `x`; also returns how many bits disagreed with the decoded word.
fn decode(x: &[u8; CODE_BYTES]) -> ([u8; 16], u32) {
    let mut s = [0u8; 16];
    let mut errors = 0u32;
    for i in 0..SEC_BITS {
        let mut ones = 0usize;
        for k in 0..REP {
            ones += bit(x, k * SEC_BITS + i) as usize;
        }
        if ones > REP / 2 {
            s[i >> 3] |= 1 << (i & 7);
            errors += (REP - ones) as u32;
        } else {
            errors += ones as u32;
        }
    }
    (s, errors)
}

impl Puf {
    /// Reads the helper sector and tries to decode this boot's RAM sample.
    pub fn open(flash: &'static RefCell<Fl>) -> Puf {
        let mut p = Puf {
            flash,
            status: Status::Disabled,
            // SAFETY: fixed, always-readable chip register.
            por: unsafe { CHIP_RESET.read_volatile() } & HAD_POR != 0,
            check: [0; CHECK_LEN],
            helper: [0; CODE_BYTES],
        };
        if !cfg!(feature = "sram_puf") {
            return p;
        }
        let mut img = [0u8; IMG_LEN];
        if flash.borrow_mut().blocking_read(OFFSET, &mut img).is_err() {
            warn!("puf: helper sector unreadable");
            p.status = Status::Damaged;
            return p;
        }
        if img.iter().all(|&b| b == 0xFF) {
            p.status = Status::Blank;
        } else if img[..4] == MAGIC
            && Sha256::digest(&img[..IMG_LEN - HASH_LEN])[..HASH_LEN] == img[IMG_LEN - HASH_LEN..]
        {
            p.check.copy_from_slice(&img[4..4 + CHECK_LEN]);
            p.helper.copy_from_slice(&img[4 + CHECK_LEN..4 + CHECK_LEN + CODE_BYTES]);
            p.status = if p.try_decode().is_some() {
                Status::Ready
            } else {
                Status::Noisy
            };
        } else {
            p.status = Status::Damaged;
        }
        info!(
            "puf: status {}, power-on reset {}",
            p.status, p.por
        );
        p
    }

    pub fn status(&self) -> Status {
        self.status
    }

    /// True when built with `sram_puf`: then no seed record may exist without PUF binding.
    pub fn required(&self) -> bool {
        self.status != Status::Disabled
    }

    /// The secret, if this boot's sample decodes. The secret is returned in a `Zeroizing`
    /// wrapper, so callers that only test `is_some()` still wipe it when the value is dropped.
    fn try_decode(&self) -> Option<Zeroizing<[u8; 16]>> {
        let mut r = Zeroizing::new([0u8; CODE_BYTES]);
        read_sample(&mut r);
        for (x, w) in r.iter_mut().zip(&self.helper) {
            *x ^= w;
        }
        let (s, errors) = decode(&r);
        let s = Zeroizing::new(s);
        let chk = Zeroizing::new(mac(&s, b"sram-puf-check-v1"));
        let ok = bool::from(chk[..CHECK_LEN].ct_eq(&self.check));
        info!(
            "puf: {} bit errors of {} ({} per mille), check {}",
            errors,
            CODE_BITS,
            errors * 1000 / CODE_BITS as u32,
            ok
        );
        if ok {
            Some(s)
        } else {
            None
        }
    }

    /// The device-bound key, derived now (not stored). `None` unless the helper is valid and
    /// this boot's RAM sample decodes.
    pub fn key(&self) -> Option<Zeroizing<[u8; 32]>> {
        if !matches!(self.status, Status::Ready | Status::Noisy) {
            return None;
        }
        let s = self.try_decode()?;
        Some(Zeroizing::new(mac(&s, b"sram-puf-key-v1")))
    }

    /// Enrols (or re-enrols, destroying the old helper) from the current RAM sample. Only on a
    /// power-on reset and only if the sample looks like a real power-up pattern.
    pub fn enroll(&mut self) -> bool {
        if !cfg!(feature = "sram_puf") {
            return false;
        }
        if !self.por {
            warn!("puf: not a power-on reset, cannot enrol; unplug for 10 s and retry");
            return false;
        }
        let mut r = [0u8; CODE_BYTES];
        read_sample(&mut r);
        let ones: u32 = r.iter().map(|b| b.count_ones()).sum();
        // A real power-up pattern is roughly balanced; stuck / cleared RAM is not.
        if !(CODE_BITS as u32 * 25 / 100..=CODE_BITS as u32 * 75 / 100).contains(&ones) {
            warn!("puf: RAM sample is not usable ({} ones of {})", ones, CODE_BITS);
            r.zeroize();
            return false;
        }
        let mut s = [0u8; 16];
        fill_random(&mut s);
        let c = Zeroizing::new(encode(&s));
        let mut img = [0u8; IMG_LEN];
        img[..4].copy_from_slice(&MAGIC);
        let chk = mac(&s, b"sram-puf-check-v1");
        img[4..4 + CHECK_LEN].copy_from_slice(&chk[..CHECK_LEN]);
        for (i, o) in img[4 + CHECK_LEN..4 + CHECK_LEN + CODE_BYTES].iter_mut().enumerate() {
            *o = r[i] ^ c[i];
        }
        let h = Sha256::digest(&img[..IMG_LEN - HASH_LEN]);
        img[IMG_LEN - HASH_LEN..].copy_from_slice(&h[..HASH_LEN]);
        r.zeroize();
        s.zeroize();

        let ok = {
            let mut f = self.flash.borrow_mut();
            let mut back = [0u8; IMG_LEN];
            f.blocking_erase(OFFSET, OFFSET + PUF_BYTES as u32).is_ok()
                && f.blocking_write(OFFSET, &img).is_ok()
                && f.blocking_read(OFFSET, &mut back).is_ok()
                && back == img
        };
        if !ok {
            warn!("puf: could not write the helper sector");
            self.status = Status::Damaged;
            return false;
        }
        self.check.copy_from_slice(&img[4..4 + CHECK_LEN]);
        self.helper
            .copy_from_slice(&img[4 + CHECK_LEN..4 + CHECK_LEN + CODE_BYTES]);
        self.status = if self.try_decode().is_some() {
            Status::Ready
        } else {
            Status::Noisy
        };
        if self.status == Status::Ready {
            info!("puf: enrolled, status {}", self.status);
            true
        } else {
            // The helper data was written, but this very sample does not decode: no usable key.
            warn!("puf: helper written but the key cannot be reconstructed, status {}", self.status);
            false
        }
    }
}
