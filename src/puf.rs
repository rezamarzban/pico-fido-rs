//! SRAM PUF: the root of the flash encryption keys, from the power-up state of 1 KiB of RAM that
//! nothing writes. Adapted from the `openSK-based-se5` branch (same fuzzy extractor), with a
//! 256-bit secret and a single helper sector.
//!
//! * `build.rs` carves `REGION_BYTES` at 0x2000_0000 out of the linker's RAM, so no startup code,
//!   `.bss`, `.data`, heap or stack ever touches it; this module only READS it. (It is therefore
//!   still intact after a warm reset.)
//! * Fuzzy extractor (code offset, repetition code, interleaved): the 256-bit secret `s` is repeated
//!   `REP` = 31 times (secret bit `i` -> codeword bit `k*256 + i`). Enrolment stores the public
//!   helper `W = R xor C(s)` and an 8-byte check in one flash sector. Later `R'` is decoded by
//!   majority vote of `R' xor W`; the check tells a good decode from a bad one. Up to 15 of 31
//!   votes per bit may be wrong: a raw bit-error rate up to ~10 % decodes with a failure
//!   probability below 2e-6 per boot (host simulation, see `host-test/puf_sim.py`). The measured
//!   error count is logged on every boot (`puf: ... bit errors`).
//! * Root key = HMAC-SHA-256(s, "sram-puf-key-v1"). It is derived on demand and never kept in RAM
//!   (`key()` returns a `Zeroizing` value); `seal::Sealer` derives the AES-256-GCM keys from it.
//! * Enrolment only happens on a power-on reset (`CHIP_RESET.HAD_POR`): after a warm reset the RAM
//!   still holds the first sample, but enrolling on anything but a fresh power-up pattern would
//!   bind the key to a pattern that is not the chip's own.
//!
//! What it buys, honestly: a copy of the FLASH alone (dump, backup, desoldered chip read in a
//! programmer) contains only ciphertext. It does NOT stop anyone who can run code on the device
//! (BOOTSEL / SWD): they can read the same RAM at power-up. The 256 bits are an upper bound: the
//! real strength is limited by the min-entropy of this chip's SRAM pattern.

use core::cell::{Cell, RefCell};
use critical_section::Mutex;
use defmt::{info, warn};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::keys::Fl;
use crate::layout::PUF_START;
use crate::seal::{Domain, Sealer};

/// RAM bytes reserved at the start of SRAM (must match build.rs).
pub const REGION_BYTES: usize = 1024;
const REGION_ADDR: usize = 0x2000_0000;

const SEC_BITS: usize = 256;
const SEC_BYTES: usize = SEC_BITS / 8;
const REP: usize = 31;
const CODE_BITS: usize = SEC_BITS * REP; // 7936
const CODE_BYTES: usize = CODE_BITS / 8; // 992
const _: () = core::assert!(CODE_BITS % 8 == 0 && CODE_BYTES <= REGION_BYTES && CODE_BYTES % 4 == 0);

const MAGIC: [u8; 4] = *b"PUF2";
const CHECK_LEN: usize = 8;
const HASH_LEN: usize = 16;
const IMG_LEN: usize = 4 + CHECK_LEN + CODE_BYTES + HASH_LEN;
const _: () = core::assert!(IMG_LEN <= 4096);

/// CHIP_RESET register (VREG_AND_CHIP_RESET + 0x08), bit 8 = HAD_POR.
const CHIP_RESET: *const u32 = 0x4006_4008 as *const u32;
const HAD_POR: u32 = 1 << 8;

#[derive(Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum Status {
    /// The helper sector is erased: nothing enrolled yet (new device, or first start of this firmware).
    Blank,
    /// The helper sector holds something that is not a valid enrolment (or could not be read).
    Damaged,
    /// Valid enrolment, but this boot's RAM sample does not decode (check failed).
    Noisy,
    Ready,
}

/// Public helper data of the enrolment.
struct Slot {
    check: [u8; CHECK_LEN],
    helper: [u8; CODE_BYTES],
}

pub struct Puf {
    status: Status,
    por: bool,
    slot: Option<Slot>,
}

fn bit(buf: &[u8], i: usize) -> u8 {
    (buf[i >> 3] >> (i & 7)) & 1
}

fn mac(s: &[u8; SEC_BYTES], label: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(s).expect("HMAC takes any key length");
    m.update(label);
    m.finalize().into_bytes().into()
}

fn read_sample(out: &mut [u8; CODE_BYTES]) {
    for i in (0..CODE_BYTES).step_by(4) {
        // SAFETY: the region is reserved in memory.x (build.rs), mapped SRAM, 4-byte aligned and
        // only read here.
        let w = unsafe { ((REGION_ADDR + i) as *const u32).read_volatile() };
        out[i..i + 4].copy_from_slice(&w.to_le_bytes());
    }
}

fn encode(s: &[u8; SEC_BYTES]) -> [u8; CODE_BYTES] {
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
fn decode(x: &[u8; CODE_BYTES]) -> ([u8; SEC_BYTES], u32) {
    let mut s = [0u8; SEC_BYTES];
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

/// Does the RAM sample look like a real power-up pattern (roughly balanced, not stuck / cleared)?
fn sample_plausible(r: &[u8; CODE_BYTES]) -> bool {
    let ones: u32 = r.iter().map(|b| b.count_ones()).sum();
    (CODE_BITS as u32 * 25 / 100..=CODE_BITS as u32 * 75 / 100).contains(&ones)
}

enum Parsed {
    Blank,
    Valid(Slot),
    Damaged,
}

fn parse(img: &[u8; IMG_LEN]) -> Parsed {
    if img.iter().all(|&b| b == 0xFF) {
        return Parsed::Blank;
    }
    if img[..4] == MAGIC
        && Sha256::digest(&img[..IMG_LEN - HASH_LEN])[..HASH_LEN] == img[IMG_LEN - HASH_LEN..]
    {
        let mut s = Slot {
            check: [0; CHECK_LEN],
            helper: [0; CODE_BYTES],
        };
        s.check.copy_from_slice(&img[4..4 + CHECK_LEN]);
        s.helper
            .copy_from_slice(&img[4 + CHECK_LEN..4 + CHECK_LEN + CODE_BYTES]);
        return Parsed::Valid(s);
    }
    Parsed::Damaged
}

impl Puf {
    /// Reads the helper sector and, if it holds an enrolment, tries to decode this boot's RAM sample.
    /// A read error is never taken for a blank sector.
    pub fn open(flash: &RefCell<Fl>) -> Puf {
        let mut p = Puf {
            status: Status::Damaged,
            // SAFETY: fixed, always-readable chip register.
            por: unsafe { CHIP_RESET.read_volatile() } & HAD_POR != 0,
            slot: None,
        };
        let mut img = [0u8; IMG_LEN];
        if flash
            .borrow_mut()
            .blocking_read(PUF_START as u32, &mut img)
            .is_err()
        {
            warn!("puf: helper sector unreadable");
        } else {
            match parse(&img) {
                Parsed::Blank => p.status = Status::Blank,
                Parsed::Damaged => {}
                Parsed::Valid(s) => {
                    p.slot = Some(s);
                    p.status = if p.try_decode(true).is_some() {
                        Status::Ready
                    } else {
                        Status::Noisy
                    };
                }
            }
        }
        info!("puf: status {}, power-on reset {}", p.status, p.por);
        p
    }

    pub fn status(&self) -> Status {
        self.status
    }

    /// Can a first enrolment happen now? Needs an erased helper sector, a power-on reset and a RAM
    /// sample that looks like a real power-up pattern.
    pub fn can_enroll(&self) -> bool {
        if self.status != Status::Blank {
            return false;
        }
        if !self.por {
            warn!("puf: not a power-on reset, cannot enrol; unplug for 10 s and retry");
            return false;
        }
        let mut r = Zeroizing::new([0u8; CODE_BYTES]);
        read_sample(&mut r);
        let ok = sample_plausible(&r);
        if !ok {
            warn!("puf: the RAM sample is not usable (stuck or cleared RAM)");
        }
        ok
    }

    /// Enrols from the current RAM sample: writes the helper sector (the commit of the first start,
    /// call it only after every flash area that depends on the key was wiped, see main.rs).
    /// `secret` is 32 fresh random bytes. True if the sector was written and this very sample decodes.
    pub fn enroll(&mut self, flash: &RefCell<Fl>, secret: &[u8; SEC_BYTES]) -> bool {
        if !self.can_enroll() {
            return false;
        }
        let mut r = Zeroizing::new([0u8; CODE_BYTES]);
        read_sample(&mut r);
        let c = Zeroizing::new(encode(secret));
        let mut img = [0u8; IMG_LEN];
        img[..4].copy_from_slice(&MAGIC);
        let chk = Zeroizing::new(mac(secret, b"sram-puf-check-v1"));
        img[4..4 + CHECK_LEN].copy_from_slice(&chk[..CHECK_LEN]);
        for (i, o) in img[4 + CHECK_LEN..4 + CHECK_LEN + CODE_BYTES]
            .iter_mut()
            .enumerate()
        {
            *o = r[i] ^ c[i];
        }
        let h = Sha256::digest(&img[..IMG_LEN - HASH_LEN]);
        img[IMG_LEN - HASH_LEN..].copy_from_slice(&h[..HASH_LEN]);

        let ok = {
            let mut f = flash.borrow_mut();
            let mut back = [0u8; IMG_LEN];
            f.blocking_erase(PUF_START as u32, (PUF_START + crate::layout::PAGE) as u32)
                .is_ok()
                && f.blocking_write(PUF_START as u32, &img).is_ok()
                && f.blocking_read(PUF_START as u32, &mut back).is_ok()
                && back == img
        };
        if !ok {
            warn!("puf: could not write the helper sector");
            return false;
        }
        match parse(&img) {
            Parsed::Valid(s) => self.slot = Some(s),
            _ => return false,
        }
        self.status = if self.try_decode(true).is_some() {
            Status::Ready
        } else {
            Status::Noisy
        };
        if self.status == Status::Ready {
            info!("puf: enrolled");
            true
        } else {
            warn!("puf: helper written but this sample does not decode");
            false
        }
    }

    /// The secret, if this boot's sample decodes with the helper data.
    fn try_decode(&self, log: bool) -> Option<Zeroizing<[u8; SEC_BYTES]>> {
        let slot = self.slot.as_ref()?;
        let mut r = Zeroizing::new([0u8; CODE_BYTES]);
        read_sample(&mut r);
        for (x, w) in r.iter_mut().zip(&slot.helper) {
            *x ^= w;
        }
        let (s, errors) = decode(&r);
        let s = Zeroizing::new(s);
        let chk = Zeroizing::new(mac(&s, b"sram-puf-check-v1"));
        let ok = bool::from(chk[..CHECK_LEN].ct_eq(&slot.check));
        if log {
            info!(
                "puf: {} bit errors of {} ({} per mille), check {}",
                errors,
                CODE_BITS,
                errors * 1000 / CODE_BITS as u32,
                ok
            );
        }
        if ok {
            Some(s)
        } else {
            None
        }
    }

    /// The device-bound root key, derived now (not stored). `None` unless this boot's RAM sample
    /// decodes. Quiet: it runs for every flash operation.
    pub fn key(&self) -> Option<Zeroizing<[u8; 32]>> {
        if self.status != Status::Ready {
            return None;
        }
        let s = self.try_decode(false)?;
        Some(Zeroizing::new(mac(&s, b"sram-puf-key-v1")))
    }
}

// ---- the installed PUF: what the flash drivers use ----------------------------------------------

static INSTALLED: Mutex<Cell<Option<&'static Puf>>> = Mutex::new(Cell::new(None));

/// Makes `puf` (status `Ready`) the key source of `try_sealer` / `sealer`. Call once at start-up.
pub fn install(puf: &'static Puf) {
    critical_section::with(|cs| INSTALLED.borrow(cs).set(Some(puf)));
}

/// The keys of `domain`, or `None` if no PUF is installed or its key cannot be rebuilt right now.
pub fn try_sealer(domain: Domain) -> Option<Sealer> {
    let puf = critical_section::with(|cs| INSTALLED.borrow(cs).get())?;
    let root = puf.key()?;
    Some(Sealer::new(&root, domain))
}

/// Like `try_sealer`, but a missing key halts the firmware: the RAM sample was fine at start-up, so
/// it can only have been overwritten (a stack overflow into the reserved region, a fault). Nothing
/// is ever read or written without the key.
pub fn sealer(domain: Domain) -> Sealer {
    match try_sealer(domain) {
        Some(s) => s,
        None => defmt::panic!("puf: the flash key cannot be rebuilt - the reserved RAM changed"),
    }
}
