//! Bridge between the USB task (asynchronous, interrupt executor) and OpenSK (blocking, thread
//! mode). Two small queues carry the 64-byte HID packets; every OpenSK call that waits for the
//! host simply polls them, while USB keeps being serviced by the higher-priority executor.
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{block_for, Duration, Instant};
use opensk::api::connection::{HidConnection, RecvStatus, UsbEndpoint};
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};
use portable_atomic::{AtomicU32, Ordering};

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

// ---- cancellation -----------------------------------------------------------------------------
//
// USB reset / suspend / disable / deconfigure bump CANCEL_EPOCH (`cancel_all`). The main loop
// stamps every CTAP operation with the epoch it started in (`begin_op`). Anything that blocks
// (user-presence wait, packet waits, sends) compares the two and gives up at once, and `send`
// silently drops every packet of a cancelled operation, so nothing stale reaches the next host
// session. A signature that is already being computed cannot be interrupted, but its response is
// dropped the same way.

static CANCEL_EPOCH: AtomicU32 = AtomicU32::new(0);
static OP_EPOCH: AtomicU32 = AtomicU32::new(0);

/// Current cancellation epoch.
pub fn epoch() -> u32 {
    CANCEL_EPOCH.load(Ordering::Acquire)
}

/// Marks the start of a CTAP operation; returns its epoch.
pub fn begin_op() -> u32 {
    let e = epoch();
    OP_EPOCH.store(e, Ordering::Release);
    e
}

/// True once the operation started by the last `begin_op` has been cancelled.
pub fn op_cancelled() -> bool {
    epoch() != OP_EPOCH.load(Ordering::Acquire)
}

/// Cancels everything in flight and drops the queues. Callable from the USB handler.
pub fn cancel_all() {
    CANCEL_EPOCH.fetch_add(1, Ordering::AcqRel);
    // Forget the seed now (with a PIN set), not at the next main-loop turn.
    super::harden::lock_now();
    flush();
}

/// Drops everything that is queued (the host will start with a new INIT).
pub fn flush() {
    while IN_CH.try_receive().is_ok() {}
    while OUT_CH.try_receive().is_ok() {}
}

/// Waits for a packet from the host. `None` waits forever. Returns whether a packet arrived;
/// false also when the operation was cancelled meanwhile.
pub fn recv_packet(buf: &mut HidPacket, timeout_ms: Option<usize>) -> bool {
    let deadline = timeout_ms.map(|t| Instant::now() + Duration::from_millis(t as u64));
    loop {
        if op_cancelled() {
            return false;
        }
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

/// The main loop's idle wait: like `recv_packet` but ends as soon as the epoch differs from
/// `seen` (so a reset is noticed even when no packet ever arrives).
pub fn wait_packet(buf: &mut HidPacket, timeout_ms: Option<usize>, seen: u32) -> bool {
    let deadline = timeout_ms.map(|t| Instant::now() + Duration::from_millis(t as u64));
    loop {
        if epoch() != seen {
            return false;
        }
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
        if op_cancelled() {
            return Ok(()); // stale response / keepalive of a cancelled operation: drop it
        }
        let deadline = Instant::now() + Duration::from_millis(SEND_TIMEOUT_MS);
        loop {
            if OUT_CH.try_send(*buf).is_ok() {
                return Ok(());
            }
            if op_cancelled() {
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
