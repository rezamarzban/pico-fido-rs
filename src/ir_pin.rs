//! IR PIN entry (feature `ir`): the second PIN, entered with the remote while the device waits for the
//! physical button.
//!
//! The IR PIN is separate from the PIN typed in the host dialog. The host PIN is checked at once, in the
//! host's own dialog (stage 1, `env/harden.rs`). The IR PIN is asked later, in the first command that needs
//! the key (stage 2), at the moment the device waits for the physical button:
//!
//! * every key press of the remote adds its full 32-bit NEC code (`nec.rs`) and flashes the LED once
//!   (`ir.rs`); the OLED, if there is one, shows the key count and one `*` per key, never the codes;
//! * a short press of the button (BOOTSEL **or** the external key on GP14, `button.rs`) confirms, at least
//!   `MIN_PRESSES` keys; a press of 1.5 s cancels. The physical button means nobody can finish an
//!   entry with an IR blaster from across the room;
//! * the confirming press also counts as user presence of the command (`user_presence::grant_credit`);
//! * when ENROLLING the IR PIN (first use after the host PIN was set) the sequence is entered twice and
//!   must match, otherwise it starts over; a PIN change (`Purpose::Change`) asks for a new IR PIN the same
//!   way, but the button alone (no key) keeps the current one;
//! * while waiting, CTAPHID keepalives tell the host the key is waiting for the user, and a CTAPHID_CANCEL
//!   from the host ends the entry;
//! * 60 s without any key or button, a USB reset or a cancel end the entry.
//!
//! The result is `SHA-256("pico-fido-ir-pin-v2" || key count || the 32-bit codes)`, one of the inputs of the
//! Argon2id key derivation (`wrap.rs`). Nothing in this file needs a display: the LED shows what happens
//! (`LedState::IrEntry`, `LedFlash`).
use embassy_rp::peripherals::BOOTSEL;
use embassy_time::{Duration, Instant};
use portable_atomic::Ordering;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::nec;
use crate::status as st;
use crate::{button, LedFlash, LedState, LED_FLASH, LED_SIGNAL};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// The first IR PIN of a PIN record: entered twice.
    Enroll,
    /// The IR PIN of an IR record: entered once.
    Verify,
    /// During a PIN change: a new IR PIN (entered twice), or the button alone to keep the current one.
    Change,
}

pub enum Outcome {
    /// Digest of the key sequence (the IR PIN input of the key derivation) and the number of keys.
    Pin(Zeroizing<[u8; 32]>, usize),
    /// `Purpose::Change` only: confirmed without a key, the current IR PIN stays.
    Keep,
    Cancelled,
    TimedOut,
}

const POLL: Duration = Duration::from_millis(5);
const KEEPALIVE_MS: u32 = 100;
const TIMEOUT_MS: u32 = 60_000;
const LONG_PRESS_MS: u32 = 1_500;
const DEBOUNCE_MS: u32 = 30;
const MSG_MS: u32 = 2_000;
/// How often the queue is checked for a CTAPHID_CANCEL of the host.
const CANCEL_CHECK_MS: u32 = 50;
/// CTAPHID_KEEPALIVE status: waiting for the user.
const KEEPALIVE_UPNEEDED: u8 = 2;

fn ms() -> u32 {
    Instant::now().as_millis() as u32
}

fn show(msg: u8) {
    st::ENTRY_MSG.store(msg, Ordering::Relaxed);
    st::REDRAW.store(true, Ordering::Relaxed);
}

/// One sequence of keys, ended by a short press of the button. `Ok(None)`: confirmed with no key at
/// all (only when `allow_empty`).
fn read_entry(step: u8, allow_empty: bool) -> Result<Option<(Zeroizing<[u8; 32]>, usize)>, Outcome> {
    let mut codes = Zeroizing::new([0u32; nec::MAX_PRESSES]);
    let mut n = 0usize;
    // SAFETY: BOOTSEL is only read here and by the user-presence code, never at the same time
    // (user presence is not polled while a command is blocked in this entry).
    let mut bootsel = unsafe { BOOTSEL::steal() };
    let mut armed = false; // the button has been seen released: a held button is not a press
    let mut down_since: Option<u32> = None;
    let mut last_activity = ms();
    let mut last_keepalive = last_activity.wrapping_sub(KEEPALIVE_MS);
    let mut last_cancel_check = last_activity;
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
        if now.wrapping_sub(last_cancel_check) >= CANCEL_CHECK_MS {
            last_cancel_check = now;
            if crate::env::hid::cancel_requested() {
                return Err(Outcome::Cancelled);
            }
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

        // Button: short press = confirm, long press = cancel.
        let pressed = button::pressed(&mut bootsel);
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
                    if n == 0 && allow_empty {
                        return Ok(None);
                    }
                    if n >= nec::MIN_PRESSES {
                        return Ok(Some((Zeroizing::new(nec::digest(&codes[..n])), n)));
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

        // Feeds the watchdog, gives the OLED (if any) its turn and sleeps until the next interrupt.
        crate::wdog::poll_wait(POLL);
    }
}

fn run(purpose: Purpose) -> Outcome {
    let mut first: Option<Zeroizing<[u8; 32]>> = None;
    loop {
        // Verify: one entry. Enroll / Change: enter, then repeat.
        let step = if purpose != Purpose::Verify && first.is_some() { 2 } else { 1 };
        let allow_empty = purpose == Purpose::Change && first.is_none();
        let (digest, keys) = match read_entry(step, allow_empty) {
            Ok(Some(v)) => v,
            Ok(None) => return Outcome::Keep,
            Err(o) => return o,
        };
        if purpose == Purpose::Verify {
            return Outcome::Pin(digest, keys);
        }
        match first.take() {
            None => first = Some(digest), // now repeat it
            Some(f) => {
                if bool::from(f[..].ct_eq(&digest[..])) {
                    return Outcome::Pin(digest, keys);
                }
                show(2); // MISMATCH: start over
            }
        }
    }
}

/// Collects an IR PIN from the remote. Blocks the main thread (the interrupt tasks, USB included, keep
/// running) until the button confirms, the entry is cancelled, it times out or USB is reset.
pub fn collect(purpose: Purpose) -> Outcome {
    crate::ir::arm();
    st::ENTRY_MSG.store(0, Ordering::Relaxed);
    st::ENTRY_KIND.store(
        match purpose {
            Purpose::Enroll => 1,
            Purpose::Verify => 2,
            Purpose::Change => 3,
        },
        Ordering::Relaxed,
    );
    LED_SIGNAL.signal(LedState::IrEntry);
    let out = run(purpose);
    st::ENTRY_KIND.store(0, Ordering::Relaxed);
    st::ENTRY_MSG.store(0, Ordering::Relaxed);
    st::REDRAW.store(true, Ordering::Relaxed);
    crate::ir::disarm();
    if matches!(out, Outcome::Cancelled | Outcome::TimedOut) {
        LED_FLASH.signal(LedFlash::Bad);
    }
    LED_SIGNAL.signal(LedState::Processing);
    out
}
