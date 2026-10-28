//! PIN entry with the IR remote (feature `ir`).
//!
//! The host types the magic PIN `0000000000` (ten zeros) in its normal PIN dialog; the PIN hooks in
//! `env/harden.rs` (`set_pin`, `unlock_with_pin`) see its hash and call `collect` instead. The
//! real PIN is then the sequence of remote keys:
//!
//! * the OLED shows the entry screen (key count and one `*` per key, never the codes);
//! * every key press adds its full 32-bit NEC code (`nec.rs`);
//! * a short press of BOOTSEL confirms (at least `MIN_PRESSES` keys), a press of 1.5 s cancels;
//!   the physical button means nobody can finish an entry with an IR blaster from across the room;
//! * when SETTING a PIN the sequence is entered twice and must match, otherwise it starts over;
//! * while waiting, CTAPHID keepalives tell the host the key is waiting for the user;
//! * 60 s without any key or button, a USB reset or a cancel end the entry.
//!
//! PIN hash = first 16 bytes of `SHA-256("pico-fido-ir-pin-v1" || count || codes)`. A cancelled or
//! timed-out entry is NOT refunded: `incr_pin_fails` has already counted the attempt (a refund
//! would forgive earlier failures).
use embassy_rp::peripherals::BOOTSEL;
use embassy_time::{block_for, Duration, Instant};
use portable_atomic::Ordering;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::nec;
use crate::status as st;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Set,
    Enter,
}

pub enum Outcome {
    /// PIN hash and the PIN length to record (2 per key).
    Pin(Zeroizing<[u8; 16]>, u8),
    Cancelled,
    TimedOut,
}

const POLL: Duration = Duration::from_millis(5);
const KEEPALIVE_MS: u32 = 100;
const TIMEOUT_MS: u32 = 60_000;
const LONG_PRESS_MS: u32 = 1_500;
const DEBOUNCE_MS: u32 = 30;
const MSG_MS: u32 = 2_000;
/// CTAPHID_KEEPALIVE status: waiting for the user.
const KEEPALIVE_UPNEEDED: u8 = 2;

/// Is this the PIN hash of the magic PIN?
pub fn is_magic(pin_hash: &[u8; 16]) -> bool {
    bool::from(pin_hash.ct_eq(&nec::magic_hash()))
}

fn ms() -> u32 {
    Instant::now().as_millis() as u32
}

fn show(msg: u8) {
    st::ENTRY_MSG.store(msg, Ordering::Relaxed);
    st::REDRAW.store(true, Ordering::Relaxed);
}

/// One sequence of keys, ended by a short BOOTSEL press.
fn read_entry(step: u8) -> Result<(Zeroizing<[u8; 32]>, usize), Outcome> {
    let mut codes = Zeroizing::new([0u32; nec::MAX_PRESSES]);
    let mut n = 0usize;
    // SAFETY: BOOTSEL is only read here and by the user-presence code, never at the same time
    // (user presence is not polled while a PIN command is processed).
    let mut button = unsafe { BOOTSEL::steal() };
    let mut armed = false; // the button has been seen released: a held button is not a press
    let mut down_since: Option<u32> = None;
    let mut last_activity = ms();
    let mut last_keepalive = last_activity.wrapping_sub(KEEPALIVE_MS);
    let mut msg_until = if st::ENTRY_MSG.load(Ordering::Relaxed) != 0 {
        Some(last_activity.wrapping_add(MSG_MS))
    } else {
        None
    };
    st::ENTRY_STEP.store(step, Ordering::Relaxed);
    st::ENTRY_COUNT.store(0, Ordering::Relaxed);
    st::REDRAW.store(true, Ordering::Relaxed);

    loop {
        crate::wdog::feed();
        let now = ms();
        if crate::env::hid::op_cancelled() {
            return Err(Outcome::Cancelled);
        }
        if now.wrapping_sub(last_activity) > TIMEOUT_MS {
            return Err(Outcome::TimedOut);
        }
        if now.wrapping_sub(last_keepalive) >= KEEPALIVE_MS {
            last_keepalive = now;
            crate::env::hid::keepalive(KEEPALIVE_UPNEEDED);
        }

        // Key presses from the receiver task.
        while let Ok(code) = crate::ir::FRAMES.try_receive() {
            if n < nec::MAX_PRESSES {
                codes[n] = code;
                n += 1;
                st::ENTRY_COUNT.store(n as u8, Ordering::Relaxed);
                st::REDRAW.store(true, Ordering::Relaxed);
            }
            last_activity = now;
        }

        // BOOTSEL: short press = confirm, long press = cancel.
        let pressed = button.is_pressed();
        if !pressed {
            armed = true;
        }
        match (pressed, down_since) {
            (true, None) if armed => down_since = Some(now),
            (true, Some(t)) if now.wrapping_sub(t) >= LONG_PRESS_MS => {
                return Err(Outcome::Cancelled);
            }
            (false, Some(t)) => {
                down_since = None;
                last_activity = now;
                if now.wrapping_sub(t) >= DEBOUNCE_MS {
                    if n >= nec::MIN_PRESSES {
                        return Ok((Zeroizing::new(nec::digest(&codes[..n])), n));
                    }
                    show(1); // NEED 8 KEYS
                    msg_until = Some(now.wrapping_add(MSG_MS));
                }
            }
            _ => {}
        }

        if let Some(until) = msg_until {
            if now.wrapping_sub(until) < u32::MAX / 2 {
                msg_until = None;
                show(0);
            }
        }

        #[cfg(feature = "oled")]
        crate::oled::poll();
        block_for(POLL);
    }
}

fn pin_from(digest: &[u8; 32], keys: usize) -> Outcome {
    Outcome::Pin(Zeroizing::new(nec::pin_hash(digest)), (keys * 2).min(63) as u8)
}

fn run(purpose: Purpose) -> Outcome {
    let mut first: Option<Zeroizing<[u8; 32]>> = None;
    loop {
        let step = if purpose == Purpose::Set && first.is_some() { 2 } else { 1 };
        let (digest, keys) = match read_entry(step) {
            Ok(v) => v,
            Err(o) => return o,
        };
        if purpose == Purpose::Enter {
            return pin_from(&digest, keys);
        }
        match first.take() {
            None => first = Some(digest), // now repeat it
            Some(f) => {
                if bool::from(f[..].ct_eq(&digest[..])) {
                    return pin_from(&digest, keys);
                }
                show(2); // MISMATCH: start over
            }
        }
    }
}

/// Collects a PIN from the remote. Blocks the main thread (the interrupt tasks, USB included, keep
/// running) until BOOTSEL confirms, the entry is cancelled, it times out or USB is reset.
pub fn collect(purpose: Purpose) -> Outcome {
    crate::ir::arm();
    st::ENTRY_MSG.store(0, Ordering::Relaxed);
    st::ENTRY_KIND.store(if purpose == Purpose::Set { 1 } else { 2 }, Ordering::Relaxed);
    let out = run(purpose);
    st::ENTRY_KIND.store(0, Ordering::Relaxed);
    st::ENTRY_MSG.store(0, Ordering::Relaxed);
    st::REDRAW.store(true, Ordering::Relaxed);
    crate::ir::disarm();
    out
}
