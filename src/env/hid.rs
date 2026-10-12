//! Bridge between the USB task (asynchronous, interrupt executor) and OpenSK (blocking, thread
//! mode). Two small queues carry the 64-byte HID packets; every OpenSK call that waits for the
//! host simply polls them, while USB keeps being serviced by the higher-priority executor.
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{block_for, Duration, Instant};
use opensk::api::connection::{HidConnection, RecvStatus, UsbEndpoint};
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};

pub type HidPacket = [u8; 64];

const QUEUE: usize = 8;
/// How long `send` waits for space in the outgoing queue before it reports a hardware failure.
const SEND_TIMEOUT_MS: u64 = 1000;
/// Polling interval of the blocking waits.
const POLL: Duration = Duration::from_micros(300);

/// Host -> device (filled by the USB task, drained by OpenSK).
pub static IN_CH: Channel<CriticalSectionRawMutex, HidPacket, QUEUE> = Channel::new();
/// Device -> host (filled by OpenSK, drained by the USB task).
pub static OUT_CH: Channel<CriticalSectionRawMutex, HidPacket, QUEUE> = Channel::new();

/// Drops everything that is queued (USB reset / suspend: the host will start with a new INIT).
pub fn flush() {
    while IN_CH.try_receive().is_ok() {}
    while OUT_CH.try_receive().is_ok() {}
}

/// Waits for a packet from the host. `None` waits forever. Returns whether a packet arrived.
pub fn recv_packet(buf: &mut HidPacket, timeout_ms: Option<usize>) -> bool {
    let deadline = timeout_ms.map(|t| Instant::now() + Duration::from_millis(t as u64));
    loop {
        if let Ok(packet) = IN_CH.try_receive() {
            *buf = packet;
            return true;
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return false;
        }
        block_for(POLL);
    }
}

pub struct PicoHidConnection;

impl HidConnection for PicoHidConnection {
    fn send(&mut self, buf: &[u8; 64], endpoint: UsbEndpoint) -> CtapResult<()> {
        let UsbEndpoint::MainHid = endpoint;
        let deadline = Instant::now() + Duration::from_millis(SEND_TIMEOUT_MS);
        loop {
            if OUT_CH.try_send(*buf).is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE);
            }
            block_for(POLL);
        }
    }

    fn recv(&mut self, buf: &mut [u8; 64], timeout_ms: usize) -> CtapResult<RecvStatus> {
        Ok(if recv_packet(buf, Some(timeout_ms)) {
            RecvStatus::Received(UsbEndpoint::MainHid)
        } else {
            RecvStatus::Timeout
        })
    }
}
