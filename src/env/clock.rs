//! Clock adapter for OpenSK using Embassy time.

use embassy_time::{Duration, Instant};
use opensk::api::clock::Clock;

#[derive(Default)]
pub struct PicoTimer {
    end: Option<Instant>,
}

pub struct PicoClock;

impl PicoClock {
    pub fn new() -> Self {
        Self
    }
}

impl Clock for PicoClock {
    type Timer = PicoTimer;

    fn make_timer(&mut self, milliseconds: usize) -> Self::Timer {
        PicoTimer {
            end: Some(Instant::now() + Duration::from_millis(milliseconds as u64)),
        }
    }

    fn is_elapsed(&mut self, timer: &Self::Timer) -> bool {
        match timer.end {
            None => true, // Default timer is already elapsed (per OpenSK contract).
            Some(end) => Instant::now() >= end,
        }
    }
}
