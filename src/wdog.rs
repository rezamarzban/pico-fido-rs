//! Optional hardware watchdog (feature `watchdog`, off by default).
//!
//! Only the MAIN thread feeds it: from the polling waits of the HID bridge and of the user-presence
//! wait (`poll_wait`, every ~0.3 ms while it waits) and from the top of the main loop. The USB /
//! LED / guard tasks of the interrupt executor never feed it, so a hung or crashed main thread (a
//! stack-overflow HardFault, a deadlock in a blocking call) is reset after `TIMEOUT_MS` instead of
//! leaving the token dead until it is unplugged.
//!
//! Why it is not on by default: any single blocking step longer than the timeout without feeding
//! (the Argon2 PIN derivation, a P-256 signature, a flash-store compaction that erases many
//! sectors) would reset the device in the middle of a command. Measure the longest such step on
//! hardware first (`stack_probe`-style logging of command times) and keep a wide margin.
//!
//! A watchdog reset is a warm reset: the SRAM PUF still decodes (nothing writes the reserved bytes),
//! only a (re-)enrolment needs a real power-on reset.

use embassy_time::{block_for, Duration};

/// The RP2040 watchdog counts at most ~8.3 s.
#[cfg(feature = "watchdog")]
const TIMEOUT_MS: u64 = 8000;

#[cfg(feature = "watchdog")]
mod imp {
    use core::cell::RefCell;

    use embassy_rp::watchdog::Watchdog;
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::blocking_mutex::Mutex;
    use embassy_time::Duration;

    static WD: Mutex<CriticalSectionRawMutex, RefCell<Option<Watchdog>>> =
        Mutex::new(RefCell::new(None));

    pub fn start(mut wd: Watchdog) {
        wd.pause_on_debug(true);
        wd.start(Duration::from_millis(super::TIMEOUT_MS));
        WD.lock(|c| *c.borrow_mut() = Some(wd));
    }

    pub fn feed() {
        WD.lock(|c| {
            if let Some(wd) = c.borrow_mut().as_mut() {
                wd.feed();
            }
        });
    }
}

#[cfg(feature = "watchdog")]
pub use imp::{feed, start};

/// No-op without the `watchdog` feature.
#[cfg(not(feature = "watchdog"))]
pub fn feed() {}

/// One step of a polling wait on the main thread: feed, then busy-wait `d`.
pub fn poll_wait(d: Duration) {
    feed();
    block_for(d);
}
