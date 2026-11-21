//! Polling wait of the main thread.

use embassy_time::{block_for, Duration, Instant};
use portable_atomic::Ordering;

/// One step of a polling wait on the main thread: give the status display a turn, then wait.
///
/// With the guard task running (`guard::ticking`) the core sleeps in `wfi` until the next
/// interrupt: the refresh task keeps a timer interrupt due at least every 50 ms (every 0.5 to
/// 2 ms while a seed is held), and USB interrupts wake it at once, so a wait is never longer than
/// that and the idle main thread burns no power spinning. Before the task runs, `d` is
/// busy-waited as before. The time slept is booked as idle time for the CPU-load display.
pub fn poll_wait(d: Duration) {
    #[cfg(feature = "oled")]
    crate::oled::poll();
    if crate::guard::ticking() {
        let t0 = Instant::now();
        cortex_m::asm::wfi();
        let dt = Instant::now().as_micros().wrapping_sub(t0.as_micros()) as u32;
        crate::status::IDLE_US.fetch_add(dt, Ordering::Relaxed);
    } else {
        block_for(d);
    }
}
