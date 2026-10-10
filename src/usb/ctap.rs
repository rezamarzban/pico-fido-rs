use alloc::vec;
use alloc::vec::Vec;
use defmt::info;
use embassy_futures::select::{select, Either};
use embassy_rp::peripherals::{BOOTSEL, USB};
use embassy_rp::usb::Driver;
use embassy_time::{Duration, Instant, Timer};
use embassy_usb::class::hid::{HidReader, HidWriter};

use crate::ctap::{err, Ctap, Resp};
use crate::ctaphid::{self, Hid, Rx};
use crate::keys::{self, Fl};
use crate::store::Pos;
use crate::{LedState, LED_SIGNAL};

pub type Reader = HidReader<'static, Driver<'static, USB>, 64>;
pub type Writer = HidWriter<'static, Driver<'static, USB>, 64>;

/// Standard FIDO HID report descriptor: usage page 0xF1D0, 64-byte IN + 64-byte OUT.
pub const FIDO_REPORT_DESC: &[u8] = &[
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xC0,
];

const TOUCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Button must be held this long (debounce).
const DEBOUNCE: Duration = Duration::from_millis(30);

fn now_ms() -> u64 {
    Instant::now().as_millis()
}

async fn send(w: &mut Writer, cid: u32, cmd: u8, data: &[u8]) {
    for p in ctaphid::frames(cid, cmd, data) {
        if w.write(&p).await.is_err() {
            break;
        }
    }
}

enum Wait {
    Touch,
    Fail(u8),
    /// Host re-initialised the channel: drop the request, send nothing for it.
    Aborted,
}

/// Wait for a *fresh* press of BOOTSEL. A button that is already held when the request
/// arrives does not count: it must be released first, then pressed (and held ~30 ms).
async fn wait_touch(
    cid: u32,
    rd: &mut Reader,
    wr: &mut Writer,
    hid: &mut Hid,
    button: &mut BOOTSEL,
) -> Wait {
    let mut buf = [0u8; 64];
    let deadline = Instant::now() + TOUCH_TIMEOUT;
    let mut next_keepalive = Instant::now();
    let mut armed = false; // seen the button released since the request arrived
    let mut pressed_since: Option<Instant> = None;
    while Instant::now() < deadline {
        if button.is_pressed() {
            if armed {
                let t = *pressed_since.get_or_insert(Instant::now());
                if t.elapsed() >= DEBOUNCE {
                    return Wait::Touch;
                }
            }
        } else {
            armed = true;
            pressed_since = None;
        }
        if Instant::now() >= next_keepalive {
            send(wr, cid, ctaphid::KEEPALIVE, &[2]).await; // 2 = user presence needed
            next_keepalive += Duration::from_millis(100);
        }
        if let Either::Second(Ok(64)) = select(Timer::after_millis(10), rd.read(&mut buf)).await {
            match hid.rx(&buf, now_ms()) {
                Rx::Cancel => return Wait::Fail(err::KEEPALIVE_CANCEL),
                Rx::Reply(c, cmd, d) => {
                    send(wr, c, cmd, &d).await;
                    if hid.take_abort() {
                        return Wait::Aborted;
                    }
                }
                _ => {}
            }
        }
    }
    Wait::Fail(err::USER_ACTION_TIMEOUT)
}

#[embassy_executor::task]
pub async fn ctap_task(
    mut rd: Reader,
    mut wr: Writer,
    mut ctap: Ctap,
    mut button: BOOTSEL,
    mut flash: Fl,
    mut pos: Option<Pos>,
) {
    let mut hid = Hid::new();
    let mut buf = [0u8; 64];
    let mut rng = |b: &mut [u8]| keys::fill_random(b);
    LED_SIGNAL.signal(LedState::Active);
    loop {
        rd.ready().await;
        if !matches!(rd.read(&mut buf).await, Ok(64)) {
            continue;
        }
        match hid.rx(&buf, now_ms()) {
            Rx::None | Rx::Cancel => {}
            Rx::Reply(cid, cmd, d) => send(&mut wr, cid, cmd, &d).await,
            Rx::Cbor(cid, req) => {
                LED_SIGNAL.signal(LedState::Processing);
                let mut r = ctap.handle(&req, false, now_ms(), &mut rng);
                if let Resp::NeedUp = r {
                    LED_SIGNAL.signal(LedState::Confirm);
                    match wait_touch(cid, &mut rd, &mut wr, &mut hid, &mut button).await {
                        Wait::Touch => {
                            LED_SIGNAL.signal(LedState::Processing);
                            send(&mut wr, cid, ctaphid::KEEPALIVE, &[1]).await; // 1 = processing
                            let t = Instant::now();
                            r = ctap.handle(&req, true, now_ms(), &mut rng);
                            // P-256 runs without yielding; this shows how long the host waits.
                            info!("crypto took {} ms", t.elapsed().as_millis());
                        }
                        Wait::Fail(code) => r = Resp::Err(code),
                        Wait::Aborted => {
                            LED_SIGNAL.signal(LedState::Active);
                            continue;
                        }
                    }
                }
                let out: Vec<u8> = match r {
                    Resp::Ok(v) => v,
                    Resp::Err(c) => vec![c],
                    Resp::NeedUp => vec![err::OTHER],
                    Resp::Reset(key) => match keys::replace(&mut flash, &key, pos) {
                        Ok(p) => {
                            pos = Some(p);
                            ctap.install_key(key);
                            vec![0]
                        }
                        Err(()) => vec![err::OTHER],
                    },
                };
                send(&mut wr, cid, ctaphid::CBOR, &out).await;
                hid.end();
                LED_SIGNAL.signal(LedState::Active);
            }
        }
    }
}
