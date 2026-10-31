//! VS1838B / NEC infrared receiver (feature `ir`): OUT on GP15 (idle high, pulses low), 3.3 V.
//!
//! A port of the MicroPython `nec_decode` (same timings and checks) as an async task on the
//! interrupt executor: it sleeps until the pin changes, so a blocked main thread or a 12 ms OLED
//! page push cannot make it lose a frame, and it costs nothing while no key is pressed. Decoded
//! 32-bit codes are queued ONLY while a PIN entry is armed (`arm`); everything else is dropped, so
//! stray IR traffic is never buffered. Level waits are used (not edge waits) so an edge that
//! happens between two awaits cannot be missed.
//!
//! Every valid key press received while an entry is armed also flashes the LED once (`LedFlash::Key`),
//! so the user sees that the device heard the remote even without a display.
use embassy_rp::gpio::Input;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{with_timeout, Duration, Instant};
use portable_atomic::{AtomicBool, Ordering};

use crate::nec;

/// Decoded codes waiting for the PIN entry.
pub static FRAMES: Channel<CriticalSectionRawMutex, u32, 16> = Channel::new();
static ARMED: AtomicBool = AtomicBool::new(false);

fn drain() {
    while FRAMES.try_receive().is_ok() {}
}

/// Starts accepting key presses (the queue is emptied first).
pub fn arm() {
    drain();
    ARMED.store(true, Ordering::Relaxed);
}

/// Stops accepting key presses and forgets the queued ones.
pub fn disarm() {
    ARMED.store(false, Ordering::Relaxed);
    drain();
}

async fn frame(pin: &mut Input<'static>) -> Option<u32> {
    // Leader mark: the line is low for ~9 ms.
    let t = Instant::now();
    with_timeout(Duration::from_millis(15), pin.wait_for_high()).await.ok()?;
    if !nec::leader_mark_ok(t.elapsed().as_micros() as u32) {
        return None;
    }
    // Leader space: ~4.5 ms high (a repeat code has ~2.25 ms and is ignored).
    let t = Instant::now();
    with_timeout(Duration::from_millis(6), pin.wait_for_low()).await.ok()?;
    if nec::classify_space(t.elapsed().as_micros() as u32) != nec::Space::Frame {
        return None;
    }
    // 32 bits, MSB first: ~560 us mark, then a space whose length is the bit.
    let mut bits = 0u32;
    for _ in 0..32 {
        with_timeout(Duration::from_micros(1_500), pin.wait_for_high()).await.ok()?;
        let t = Instant::now();
        // After the last bit this ends at the stop mark.
        with_timeout(Duration::from_micros(2_500), pin.wait_for_low()).await.ok()?;
        bits = (bits << 1) | nec::bit(t.elapsed().as_micros() as u32) as u32;
    }
    nec::valid(bits).then_some(bits)
}

#[embassy_executor::task]
pub async fn ir_task(mut pin: Input<'static>) {
    loop {
        pin.wait_for_low().await;
        if let Some(code) = frame(&mut pin).await {
            if ARMED.load(Ordering::Relaxed) {
                let _ = FRAMES.try_send(code);
                crate::LED_FLASH.signal(crate::LedFlash::Key);
            }
        }
        // Resynchronise: a pause of 6 ms with the line high is longer than anything inside a
        // frame (the longest space is 4.5 ms), so it is the gap between frames.
        loop {
            match with_timeout(Duration::from_millis(6), pin.wait_for_low()).await {
                Err(_) => break,
                Ok(()) => pin.wait_for_high().await,
            }
        }
    }
}
