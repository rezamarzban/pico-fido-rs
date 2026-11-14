//! SRAM PUF: the root of the flash encryption keys, from the power-up state of 4 KiB of RAM that
//! nothing writes. The arithmetic (pair-XOR debiasing, repetition code, bit-sliced majority vote) is in
//! `puf_code.rs`, which is host-tested; this module reads the RAM and the helper sector.
//!
//! * `build.rs` keeps `REGION_BYTES` at `REGION_ADDR` (the top of the striped SRAM, 0x2003_F000) out
//!   of the linker's RAM, so no startup code, `.bss`, `.data`, heap or stack ever touches it; this module
//!   only READS it. (It is therefore still intact after a warm reset.) It is at the TOP so that the
//!   stack, which flip-link places at the BOTTOM of RAM, still runs into unmapped memory (a fault) on
//!   overflow instead of silently into the PUF.
//! * Fuzzy extractor: see `puf_code.rs`. Enrolment stores the public helper `W = R xor C(s)` and an
//!   8-byte check in one flash sector. Later the sample is decoded by majority vote of `R' xor W`; the
//!   check tells a good decode from a bad one. A raw bit-error rate of 10 % decodes with a failure
//!   probability of about 1e-6 per boot (`host-test/puf_sim.py`). The measured error count and the
//!   bias of the sample are logged on every boot (`puf: ...`).
//! * Enrolment is refused when the pair stream is not balanced (46..54 % ones): on a heavily biased
//!   chip the helper data would give a secret that is much weaker than 256 bits (`puf_code.rs`).
//! * Root key = HMAC-SHA-256(s, "sram-puf-key-v1"). It is derived on demand and never kept in RAM
//!   (`key()` returns a `Zeroizing` value); `seal::Sealer` derives the AES-256-GCM keys from it.
//! * Enrolment only happens on a power-on reset (`CHIP_RESET.HAD_POR`): after a warm reset the RAM
//!   still holds the first sample, but enrolling on anything but a fresh power-up pattern would
//!   bind the key to a pattern that is not the chip's own.
//!
//! * Backup (`puf_backup.rs`, policy in `main.rs`): while the PUF works, its secret is also kept in the
//!   backup sector sealed with each connected chip's slot-0 public key. If a later boot cannot read
//!   the PUF (noisy sample, damaged or lost helper sector), `restore` takes the secret from there and
//!   writes a new helper sector from the current power-up pattern when that is possible (power-on
//!   reset, plausible sample); otherwise the secret is kept in RAM until the next power cycle.
//!
//! What it buys, honestly: a copy of the FLASH alone (dump, backup, desoldered chip read in a
//! programmer) contains only ciphertext. It does NOT stop anyone who has the device: BOOTSEL and
//! picotool (or SWD) can very likely read the same RAM at power-up, with no code of their own. The 256
//! bits are an upper bound: the real strength is limited by the min-entropy of this chip's SRAM.

use core::cell::{Cell, RefCell};
use critical_section::Mutex;
use defmt::{info, warn};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::puf_code::{self as code, CODE_BITS, CODE_WORDS, SEC_WORDS};

use crate::keys::Fl;
use crate::layout::PUF_START;
use crate::seal::{Domain, Sealer};

/// RAM bytes reserved for the PUF (must match build.rs).
pub const REGION_BYTES: usize = code::REGION_WORDS * 4;
/// Top of the striped SRAM (SRAM0-3, 0x2000_0000..0x2004_0000), 4 KiB below it.
pub const REGION_ADDR: usize = 0x2003_F000;

const _: () = core::assert!(
    REGION_ADDR + REGION_BYTES == 0x2004_0000,
    "the PUF region ends at the top of SRAM0-3"
);

const SEC_BYTES: usize = SEC_WORDS * 4;
const CODE_BYTES: usize = CODE_WORDS * 4; // 2016

const MAGIC: [u8; 4] = *b"PUF3";
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
    helper: [u32; CODE_WORDS],
}

/// Where this boot's key comes from, for the display.
#[derive(Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum Restored {
    /// Rebuilt from the RAM sample.
    No,
    /// From the backup, kept in RAM (the sample could not be used for a new helper sector).
    Ram,
    /// From the backup, and the helper sector was rewritten from this boot's sample.
    Healed,
}

/// Quality of this boot's RAM sample.
#[derive(Clone, Copy, Default)]
pub struct Stats {
    /// Bits of the pair stream that differ from the decoded codeword (out of `CODE_BITS`).
    pub errors: u32,
    /// Share of ones, per mille, in the raw cells and in the pair stream.
    pub raw_pm: u32,
    pub pair_pm: u32,
}

pub struct Puf {
    status: Status,
    por: bool,
    slot: Option<Slot>,
    /// The secret, when it came from the backup and no helper sector could be written (kept only for
    /// this power cycle).
    ram: Option<Zeroizing<[u8; SEC_BYTES]>>,
    restored: Restored,
    stats: Stats,
}

fn mac(s: &[u8; SEC_BYTES], label: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(s).expect("HMAC takes any key length");
    m.update(label);
    m.finalize().into_bytes().into()
}

/// The pair stream of this boot's RAM sample, and how many raw cells were ones.
fn read_sample() -> (Zeroizing<[u32; CODE_WORDS]>, u32) {
    let mut raw_ones = 0;
    let r = code::pair_stream(
        // SAFETY: the region is reserved in memory.x (build.rs), mapped SRAM, 4-byte aligned and
        // only read here.
        |i| unsafe { ((REGION_ADDR + 4 * i) as *const u32).read_volatile() },
        &mut raw_ones,
    );
    (Zeroizing::new(r), raw_ones)
}

#[allow(clippy::large_enum_variant)] // short-lived, on the stack of `open`
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
            helper: [0; CODE_WORDS],
        };
        s.check.copy_from_slice(&img[4..4 + CHECK_LEN]);
        for (i, h) in s.helper.iter_mut().enumerate() {
            let o = 4 + CHECK_LEN + 4 * i;
            *h = u32::from_le_bytes([img[o], img[o + 1], img[o + 2], img[o + 3]]);
        }
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
            ram: None,
            restored: Restored::No,
            stats: Stats::default(),
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
                    let ok = p.try_decode(true).is_some();
                    p.stats = p.decode().1;
                    p.status = if ok { Status::Ready } else { Status::Noisy };
                }
            }
        }
        info!("puf: status {}, power-on reset {}", p.status, p.por);
        p
    }

    pub fn status(&self) -> Status {
        self.status
    }

    pub fn por(&self) -> bool {
        self.por
    }

    pub fn restored(&self) -> Restored {
        self.restored
    }

    /// Quality of this boot's sample (all zero when there was no helper sector to compare with).
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Can a first enrolment happen now? Needs an erased helper sector and a sample that can be used
    /// (see `can_write_helper`).
    pub fn can_enroll(&self) -> bool {
        self.status == Status::Blank && self.can_write_helper()
    }

    /// Can a helper sector be written from the current RAM sample? Needs a power-on reset (the
    /// sample must be the chip's own power-up pattern) and a sample that looks real and balanced.
    pub fn can_write_helper(&self) -> bool {
        if !self.por {
            warn!("puf: not a power-on reset, cannot write a helper sector; unplug for 10 s and retry");
            return false;
        }
        let (r, raw_ones) = read_sample();
        let ok = code::plausible(raw_ones, &r);
        if !ok {
            warn!(
                "puf: the RAM sample is not usable (stuck, cleared or too biased): raw {} per mille ones",
                raw_ones as usize * 1000 / (2 * CODE_BITS)
            );
        }
        ok
    }

    /// Enrols from the current RAM sample: writes the helper sector (the commit of the first start,
    /// call it only after every flash area that depends on the key was wiped, see main.rs).
    /// `secret` is 32 fresh random bytes. True if the sector was written and this very sample decodes.
    pub fn enroll(&mut self, flash: &RefCell<Fl>, secret: &[u8; SEC_BYTES]) -> bool {
        if self.status != Status::Blank || !self.can_write_helper() {
            return false;
        }
        self.write_helper(flash, secret)
    }

    /// Takes `secret` (from the backup) when this boot's sample cannot give it, i.e. status `Noisy`,
    /// `Damaged`, or `Blank` with a backup of this chip (the helper sector was lost). A valid helper
    /// sector must belong to this secret. Then, if the sample allows it, a new helper sector is
    /// written from this power-up pattern (the next boots use the PUF again); otherwise the secret
    /// stays in RAM for this power cycle. True if the key is available now.
    pub fn restore(&mut self, flash: &RefCell<Fl>, secret: Zeroizing<[u8; SEC_BYTES]>) -> bool {
        if self.status == Status::Ready {
            return true;
        }
        if let Some(slot) = &self.slot {
            let chk = Zeroizing::new(mac(&secret, b"sram-puf-check-v1"));
            if !bool::from(chk[..CHECK_LEN].ct_eq(&slot.check)) {
                warn!("puf: the backup is not the secret of this enrolment");
                return false;
            }
        }
        if self.can_write_helper() && self.write_helper(flash, &secret) {
            self.restored = Restored::Healed;
            warn!("puf: key restored from the backup, new helper sector written");
            return true;
        }
        self.ram = Some(secret);
        self.status = Status::Ready;
        self.restored = Restored::Ram;
        warn!("puf: key restored from the backup, kept in RAM until the next power cycle");
        true
    }

    fn write_helper(&mut self, flash: &RefCell<Fl>, secret: &[u8; SEC_BYTES]) -> bool {
        let (r, _) = read_sample();
        let c = Zeroizing::new(code::encode(&code::words_of(secret)));
        let mut img = [0u8; IMG_LEN];
        img[..4].copy_from_slice(&MAGIC);
        let chk = Zeroizing::new(mac(secret, b"sram-puf-check-v1"));
        img[4..4 + CHECK_LEN].copy_from_slice(&chk[..CHECK_LEN]);
        for i in 0..CODE_WORDS {
            let o = 4 + CHECK_LEN + 4 * i;
            img[o..o + 4].copy_from_slice(&(r[i] ^ c[i]).to_le_bytes());
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
        self.ram = None;
        let (secret_back, stats) = self.decode();
        self.stats = stats;
        self.status = if secret_back.is_some() {
            Status::Ready
        } else {
            Status::Noisy
        };
        if self.status == Status::Ready {
            info!("puf: helper sector written");
            true
        } else {
            warn!("puf: helper written but this sample does not decode");
            false
        }
    }

    /// Decodes this boot's sample with the helper data: the secret if the check agrees, and the
    /// quality figures of the sample (also when it does not decode).
    fn decode(&self) -> (Option<Zeroizing<[u8; SEC_BYTES]>>, Stats) {
        let Some(slot) = self.slot.as_ref() else {
            return (None, Stats::default());
        };
        let (mut x, raw_ones) = read_sample();
        let ones: u32 = x.iter().map(|w| w.count_ones()).sum();
        for (v, w) in x.iter_mut().zip(&slot.helper) {
            *v ^= w;
        }
        let sw = Zeroizing::new(code::decode(&x));
        let s = Zeroizing::new(code::bytes_of(&sw));
        let chk = Zeroizing::new(mac(&s, b"sram-puf-check-v1"));
        let ok = bool::from(chk[..CHECK_LEN].ct_eq(&slot.check));
        let stats = Stats {
            errors: code::bit_errors(&x, &sw),
            raw_pm: (raw_ones as usize * 1000 / (2 * CODE_BITS)) as u32,
            pair_pm: (ones as usize * 1000 / CODE_BITS) as u32,
        };
        (if ok { Some(s) } else { None }, stats)
    }

    /// The secret, if this boot's sample decodes with the helper data. `log`: report the quality
    /// of the sample (once at start-up; the key is rebuilt for every flash operation, quietly).
    fn try_decode(&self, log: bool) -> Option<Zeroizing<[u8; SEC_BYTES]>> {
        let (s, stats) = self.decode();
        if log && self.slot.is_some() {
            info!(
                "puf: {} bit errors of {} ({} per mille), check {}; ones: raw {} per mille, pairs {} per mille",
                stats.errors,
                CODE_BITS,
                stats.errors as usize * 1000 / CODE_BITS,
                s.is_some(),
                stats.raw_pm,
                stats.pair_pm
            );
        }
        s
    }

    /// The PUF secret (for the backup): from the backup (RAM) if that is where it came from,
    /// otherwise decoded from this boot's sample. `None` unless the status is `Ready`.
    pub fn secret(&self) -> Option<Zeroizing<[u8; SEC_BYTES]>> {
        if self.status != Status::Ready {
            return None;
        }
        match &self.ram {
            Some(s) => Some(s.clone()),
            None => self.try_decode(false),
        }
    }

    /// The device-bound root key, derived now (not stored). `None` unless this boot's RAM sample
    /// decodes. Quiet: it runs for every flash operation.
    pub fn key(&self) -> Option<Zeroizing<[u8; 32]>> {
        if self.status != Status::Ready {
            return None;
        }
        let s = self.secret()?;
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
