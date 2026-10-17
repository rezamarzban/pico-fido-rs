//! USB HID <-> OpenSK packet pump.
//!
//! Runs on the high-priority (interrupt) executor, so USB keeps being serviced while OpenSK, which
//! runs blocking in thread mode, waits for the button or computes a signature. Packets travel
//! through the two queues in `env::hid`.
use defmt::warn;
use embassy_futures::select::{select, select3, Either, Either3};
use embassy_time::Timer;
use embassy_rp::peripherals::USB;
use embassy_rp::usb::Driver;
use embassy_usb::class::hid::{HidReader, HidWriter};

use crate::env::hid::{epoch, IN_CH, OUT_CH, RESET_SIG};

pub type Reader = HidReader<'static, Driver<'static, USB>, 64>;
pub type Writer = HidWriter<'static, Driver<'static, USB>, 64>;

/// Standard FIDO HID report descriptor: usage page 0xF1D0, 64-byte IN + 64-byte OUT.
pub const FIDO_REPORT_DESC: &[u8] = &[
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xC0,
];

#[embassy_executor::task]
pub async fn usb_io(mut rd: Reader, mut wr: Writer) {
    let mut buf = [0u8; 64];
    loop {
        // A read that was started before a reset must never deliver its packet afterwards:
        // `cancel_all` raises RESET_SIG (the read is dropped and restarted, which also makes the
        // first packet of the new session acceptable) and the epoch is compared once more when the
        // read completes. The signal arm is polled first, so a reset wins over a ready read.
        let e = epoch();
        RESET_SIG.reset();
        let ev = {
            let read = async {
                rd.ready().await;
                rd.read(&mut buf).await
            };
            select3(RESET_SIG.wait(), read, OUT_CH.receive()).await
        };
        match ev {
            Either3::First(()) => {
                // Reset, suspend or deconfigure: whatever the endpoint still holds belongs to the
                // old session. Read and discard it until nothing arrives for a moment (a host
                // needs far longer than this before its first packet of the new session).
                for _ in 0..8 {
                    let again = select(
                        async {
                            rd.ready().await;
                            rd.read(&mut buf).await
                        },
                        Timer::after_millis(2),
                    )
                    .await;
                    if matches!(again, Either::Second(_)) {
                        break;
                    }
                }
                buf = [0u8; 64];
            }
            Either3::Second(Ok(64)) => {
                if epoch() != e {
                    warn!("USB: packet read across a reset dropped");
                } else if IN_CH.try_send(buf).is_err() {
                    // A full queue means OpenSK is not consuming (busy or stuck): drop the
                    // packet, the host retries or times out. Waiting here could deadlock
                    // against a blocked `send`.
                    warn!("USB: incoming queue full, packet dropped");
                }
            }
            Either3::Second(_) => {}
            Either3::Third(packet) => {
                if wr.write(&packet).await.is_err() {
                    warn!("USB: write failed");
                }
            }
        }
    }
}
