//! User presence = a FRESH press of the button: BOOTSEL or the external key on GP14 (`src/button.rs`),
//! both do the same.
//!
//! "Fresh": the button must be seen released after the check started and pressed afterwards, so a
//! button that is already held down when a request arrives does not count.
//!
//! With an IR PIN (feature `ir`, a PIN is set) the IR PIN is a part of the button step: the user types the
//! IR PIN on the remote and CONFIRMS WITH THE BUTTON, and that press is the user presence. A press
//! without the right IR PIN is no user presence. See `ir_confirm`. When the IR PIN already had to be
//! entered earlier in the same command (the key was needed before the button step), the press that
//! confirmed it ("credit", see `grant_credit`) is the user presence, so the user presses once.
use defmt::info;
use embassy_rp::peripherals::BOOTSEL;
use portable_atomic::{AtomicU32, Ordering};
use embassy_time::{Duration, Instant};
use opensk::api::connection::{RecvStatus, UsbEndpoint};
use opensk::api::user_presence::{UserPresence, UserPresenceError, UserPresenceWaitResult};

use super::hid::{op_cancelled, op_serial, IN_CH};
use crate::{button, LedState, LED_SIGNAL};

const POLL: Duration = Duration::from_millis(5);

/// Serial (`hid::op_serial`) of the operation whose IR PIN entry was confirmed with a physical button
/// press, 0 = none. Valid for that operation only: the next operation has another serial.
static CREDIT: AtomicU32 = AtomicU32::new(0);

/// The button press that confirmed an IR PIN entry counts as user presence for the running operation.
#[cfg(feature = "ir")]
pub fn grant_credit() {
    CREDIT.store(op_serial(), Ordering::Release);
}

/// Consumes the credit if it belongs to operation `serial`.
fn take_credit(serial: u32) -> bool {
    serial != 0
        && CREDIT
            .compare_exchange(serial, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
}

pub struct PicoUserPresence {
    button: BOOTSEL,
    /// The button has been seen released since the current check was armed.
    released: bool,
}

impl PicoUserPresence {
    pub fn new(button: BOOTSEL) -> Self {
        PicoUserPresence {
            button,
            released: false,
        }
    }

    /// Starts requiring a new press (also used for U2F, which has no begin/end calls).
    pub fn arm(&mut self) {
        self.released = false;
    }

    /// Polls the button; true once on a fresh press.
    pub fn poll_fresh_press(&mut self) -> bool {
        if button::pressed(&mut self.button) {
            let fresh = self.released;
            self.released = false;
            fresh
        } else {
            self.released = true;
            false
        }
    }
}

/// Result of one button confirmation as the physical-button stage of a U2F request sees it.
#[allow(dead_code)]
pub enum U2fPress {
    /// Not (yet) confirmed.
    Waiting,
    Granted,
    /// The IR PIN entry was cancelled, timed out or was wrong.
    Denied,
}

#[cfg(feature = "ir")]
impl PicoUserPresence {
    /// The IR PIN as part of the button step. `None`: no IR PIN is involved now (no PIN, the host PIN
    /// was not checked in this session, or the feature is off): the plain button press decides.
    ///
    /// * Open session: the IR PIN is entered and confirmed with the button, and must equal the proven
    ///   one (three wrong ones in a row lock the session).
    /// * IR PIN still to be proven (first command of the session) or to be enrolled: the entry is kept
    ///   until the key is used, which then evaluates it with a counted attempt; the press is the user
    ///   presence of this command.
    fn ir_confirm(&mut self) -> Option<UserPresenceWaitResult> {
        use super::harden::{self as hd, IrMode};
        use crate::ir_pin::{collect, Outcome, Purpose};
        let mode = hd::ir_mode();
        if mode == IrMode::None || !crate::guard::has_host() {
            return None;
        }
        let purpose = if mode == IrMode::Enroll { Purpose::Enroll } else { Purpose::Verify };
        self.released = false;
        Some(match collect(purpose) {
            Outcome::Pin(d, _) => {
                if mode == IrMode::Session {
                    if hd::session_matches(&d) {
                        hd::session_ok();
                        Ok((Ok(()), RecvStatus::Timeout))
                    } else {
                        crate::LED_FLASH.signal(crate::LedFlash::Bad);
                        hd::session_fail();
                        Ok((Err(UserPresenceError::Canceled), RecvStatus::Timeout))
                    }
                } else if hd::store_candidate(&d) {
                    Ok((Ok(()), RecvStatus::Timeout))
                } else {
                    Ok((Err(UserPresenceError::Canceled), RecvStatus::Timeout))
                }
            }
            Outcome::TimedOut => Ok((Err(UserPresenceError::Timeout), RecvStatus::Timeout)),
            Outcome::Cancelled | Outcome::Keep => Ok((Err(UserPresenceError::Canceled), RecvStatus::Timeout)),
        })
    }

    /// U2F has no begin/end calls: the main loop asks this while a U2F request waits for the button.
    pub fn u2f_press(&mut self) -> U2fPress {
        match self.ir_confirm() {
            Some(Ok((Ok(()), _))) => U2fPress::Granted,
            Some(_) => U2fPress::Denied,
            None => {
                if self.poll_fresh_press() {
                    U2fPress::Granted
                } else {
                    U2fPress::Waiting
                }
            }
        }
    }
}

impl UserPresence for PicoUserPresence {
    fn check_init(&mut self) {
        self.arm();
        LED_SIGNAL.signal(LedState::Confirm);
    }

    fn wait_with_timeout(
        &mut self,
        packet: &mut [u8; 64],
        timeout_ms: usize,
    ) -> UserPresenceWaitResult {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        if !op_cancelled() && take_credit(op_serial()) {
            info!("user presence: the button press of the IR PIN entry");
            return Ok((Ok(()), RecvStatus::Timeout));
        }
        #[cfg(feature = "ir")]
        {
            if let Some(result) = self.ir_confirm() {
                return result;
            }
        }
        loop {
            // Reset / suspend / unplug: give up at once. Checked BEFORE the button and the queue,
            // so a press or a packet of the new session can never complete the old operation.
            if op_cancelled() {
                self.released = false;
                return Ok((Err(UserPresenceError::Canceled), RecvStatus::Timeout));
            }
            if self.poll_fresh_press() {
                info!("user presence: button pressed");
                return Ok((Ok(()), RecvStatus::Timeout));
            }
            // OpenSK wants packets that arrive during the wait (e.g. CTAPHID_CANCEL, a new INIT).
            if let Ok(received) = IN_CH.try_receive() {
                // A reset between the check at the top and this dequeue: old-session packet.
                if op_cancelled() {
                    self.released = false;
                    return Ok((Err(UserPresenceError::Canceled), RecvStatus::Timeout));
                }
                *packet = received;
                return Ok((
                    Err(UserPresenceError::Timeout),
                    RecvStatus::Received(UsbEndpoint::MainHid),
                ));
            }
            if Instant::now() >= deadline {
                return Ok((Err(UserPresenceError::Timeout), RecvStatus::Timeout));
            }
            crate::wdog::poll_wait(POLL);
        }
    }

    fn check_complete(&mut self) {
        self.released = false;
        LED_SIGNAL.signal(LedState::Processing);
    }
}
