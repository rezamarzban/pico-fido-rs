//! User presence = a FRESH press of the BOOTSEL button (the Pico has no other button).
//!
//! "Fresh": the button must be seen released after the check started and pressed afterwards, so a
//! button that is already held down when a request arrives does not count.
use defmt::info;
use embassy_rp::peripherals::BOOTSEL;
use embassy_time::{block_for, Duration, Instant};
use opensk::api::connection::{RecvStatus, UsbEndpoint};
use opensk::api::user_presence::{UserPresence, UserPresenceError, UserPresenceWaitResult};

use super::hid::{op_cancelled, IN_CH};
use crate::{LedState, LED_SIGNAL};

const POLL: Duration = Duration::from_millis(5);

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
        if self.button.is_pressed() {
            let fresh = self.released;
            self.released = false;
            fresh
        } else {
            self.released = true;
            false
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
                *packet = received;
                return Ok((
                    Err(UserPresenceError::Timeout),
                    RecvStatus::Received(UsbEndpoint::MainHid),
                ));
            }
            if Instant::now() >= deadline {
                return Ok((Err(UserPresenceError::Timeout), RecvStatus::Timeout));
            }
            block_for(POLL);
        }
    }

    fn check_complete(&mut self) {
        self.released = false;
        LED_SIGNAL.signal(LedState::Processing);
    }
}
