use alloc::vec;
use alloc::vec::Vec;
use embassy_futures::select::{select, Either};
use embassy_rp::peripherals::{BOOTSEL, USB};
use embassy_rp::usb::Driver;
use embassy_time::Timer;
use embassy_usb::class::hid::{HidReader, HidWriter};

use crate::ctap::{err, Ctap, Resp};
use crate::ctaphid::{self, Hid, Rx};
use crate::{LedState, LED_SIGNAL};

pub type Reader = HidReader<'static, Driver<'static, USB>, 64>;
pub type Writer = HidWriter<'static, Driver<'static, USB>, 64>;

/// Standard FIDO HID report descriptor: usage page 0xF1D0, 64-byte IN + 64-byte OUT.
pub const FIDO_REPORT_DESC: &[u8] = &[
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xC0,
];

async fn send(w: &mut Writer, cid: u32, cmd: u8, data: &[u8]) {
    for p in ctaphid::frames(cid, cmd, data) {
        if w.write(&p).await.is_err() {
            break;
        }
    }
}

/// Wait up to 30 s for the BOOTSEL button, sending keepalives. Err = CTAP status code.
async fn wait_touch(
    cid: u32,
    rd: &mut Reader,
    wr: &mut Writer,
    hid: &mut Hid,
    button: &mut BOOTSEL,
) -> Result<(), u8> {
    let mut buf = [0u8; 64];
    for tick in 0..600u32 {
        if button.is_pressed() {
            return Ok(());
        }
        if tick % 2 == 0 {
            send(wr, cid, ctaphid::KEEPALIVE, &[2]).await; // 2 = UP needed
        }
        if let Either::Second(Ok(64)) = select(Timer::after_millis(50), rd.read(&mut buf)).await {
            match hid.rx(&buf) {
                Rx::Cancel => return Err(err::KEEPALIVE_CANCEL),
                Rx::Reply(c, cmd, d) => send(wr, c, cmd, &d).await,
                _ => {}
            }
        }
    }
    Err(err::USER_ACTION_TIMEOUT)
}

#[embassy_executor::task]
pub async fn ctap_task(
    mut rd: Reader,
    mut wr: Writer,
    mut ctap: Ctap,
    mut button: BOOTSEL,
) {
    let mut hid = Hid::new();
    let mut buf = [0u8; 64];
    LED_SIGNAL.signal(LedState::Active);
    loop {
        rd.ready().await;
        if !matches!(rd.read(&mut buf).await, Ok(64)) {
            continue;
        }
        match hid.rx(&buf) {
            Rx::None | Rx::Cancel => {}
            Rx::Reply(cid, cmd, d) => send(&mut wr, cid, cmd, &d).await,
            Rx::Cbor(cid, req) => {
                LED_SIGNAL.signal(LedState::Processing);
                let mut r = ctap.handle(&req, false).await;
                if let Resp::NeedUp = r {
                    LED_SIGNAL.signal(LedState::Confirm);
                    r = match wait_touch(cid, &mut rd, &mut wr, &mut hid, &mut button).await {
                        Ok(()) => {
                            LED_SIGNAL.signal(LedState::Processing);
                            send(&mut wr, cid, ctaphid::KEEPALIVE, &[1]).await; // 1 = processing
                            ctap.handle(&req, true).await
                        }
                        Err(code) => Resp::Err(code),
                    };
                }
                let out: Vec<u8> = match r {
                    Resp::Ok(v) => v,
                    Resp::Err(c) => vec![c],
                    Resp::NeedUp => vec![err::OTHER],
                };
                send(&mut wr, cid, ctaphid::CBOR, &out).await;
                hid.end();
                LED_SIGNAL.signal(LedState::Active);
            }
        }
    }
}
