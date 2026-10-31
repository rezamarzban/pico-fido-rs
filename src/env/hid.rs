//! Bridge between the USB task (asynchronous, interrupt executor) and OpenSK (blocking, thread
//! mode). Two small queues carry the 64-byte HID packets; every OpenSK call that waits for the
//! host simply polls them, while USB keeps being serviced by the higher-priority executor.
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant};
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

/// Makes "not cancelled? then enqueue the response" one step with respect to `cancel_all`, which
/// runs in the USB interrupt executor: otherwise a reset could flush the queue between the check
/// and the enqueue and the stale response would be sent afterwards.
static SEND_LOCK: Mutex<CriticalSectionRawMutex, ()> = Mutex::new(());

// ---- cancellation -----------------------------------------------------------------------------
//
// USB reset / suspend / disable / deconfigure bump CANCEL_EPOCH (`cancel_all`). The main loop
// stamps every CTAP operation with the epoch it started in (`begin_op_at`). Anything that blocks
// (user-presence wait, packet waits, sends) compares the two and gives up at once, and `send`
// silently drops every packet of a cancelled operation, so nothing stale reaches the next host
// session. A signature that is already being computed cannot be interrupted, but its response is
// dropped the same way.

static CANCEL_EPOCH: AtomicU32 = AtomicU32::new(0);
static OP_EPOCH: AtomicU32 = AtomicU32::new(0);
/// Counts the operations started by `begin_op_at` (0 = none yet). Lets code tell "the same operation"
/// from a later one: the button press that confirms an IR PIN entry counts as user presence for the
/// operation it happened in, and for no other.
static OP_SERIAL: AtomicU32 = AtomicU32::new(0);

/// Current cancellation epoch.
pub fn epoch() -> u32 {
    CANCEL_EPOCH.load(Ordering::Acquire)
}

/// Marks the start of a CTAP operation that belongs to epoch `e` (the epoch under which its
/// packet was dequeued). If a reset advanced the epoch meanwhile, the operation is cancelled from
/// its first instruction on (`op_cancelled` is true at once) instead of silently adopting the
/// new epoch.
pub fn begin_op_at(e: u32) -> u32 {
    OP_EPOCH.store(e, Ordering::Release);
    // Never 0: 0 means "no operation".
    let n = OP_SERIAL.load(Ordering::Relaxed).wrapping_add(1);
    OP_SERIAL.store(if n == 0 { 1 } else { n }, Ordering::Release);
    e
}

/// Milliseconds since boot (wrapping), for the main loop's short timers.
pub fn epoch_ms() -> u32 {
    Instant::now().as_millis() as u32
}

/// Serial number of the operation being processed (see `OP_SERIAL`).
pub fn op_serial() -> u32 {
    OP_SERIAL.load(Ordering::Acquire)
}

/// True once the operation started by the last `begin_op_at` has been cancelled.
pub fn op_cancelled() -> bool {
    epoch() != OP_EPOCH.load(Ordering::Acquire)
}

/// Cancels everything in flight and drops the queues. Callable from the USB handler.
pub fn cancel_all() {
    CANCEL_EPOCH.fetch_add(1, Ordering::AcqRel);
    // Forget the seed now (with a PIN set), not at the next main-loop turn.
    super::harden::lock_now();
    flush();
    // Tell the USB task to abandon the read it has in flight (see `usb::ctap::usb_io`).
    RESET_SIG.signal(());
}

/// Raised by `cancel_all`; `usb_io` restarts its pending endpoint read when it fires.
pub static RESET_SIG: Signal<CriticalSectionRawMutex, ()> = Signal::new();

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
            // Cancelled between the check above and the dequeue: the packet is from the old
            // session, drop it.
            if op_cancelled() {
                return false;
            }
            *buf = packet;
            return true;
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return false;
        }
        crate::wdog::poll_wait(POLL);
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
            // A reset may have landed between the check above and the dequeue: such a packet
            // belongs to the old session and must not be processed.
            if epoch() != seen {
                return false;
            }
            *buf = packet;
            return true;
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return false;
        }
        crate::wdog::poll_wait(POLL);
    }
}

/// Channel of the request being processed (first 4 bytes of its packets); 0 = none yet.
static CUR_CID: AtomicU32 = AtomicU32::new(0);

/// Remembers the channel of a received packet (for `keepalive`).
pub fn note_cid(packet: &[u8; 64]) {
    CUR_CID.store(u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]), Ordering::Relaxed);
}

/// Sends a CTAPHID_KEEPALIVE on the current channel (status 1 = processing, 2 = user needed), so
/// that the host keeps waiting while a command takes long (the IR PIN entry). Dropped if the
/// operation was cancelled.
pub fn keepalive(status: u8) {
    let cid = CUR_CID.load(Ordering::Relaxed);
    if cid == 0 {
        return;
    }
    let mut b = [0u8; 64];
    b[..4].copy_from_slice(&cid.to_be_bytes());
    b[4] = 0xBB; // CTAPHID_KEEPALIVE
    b[6] = 1; // payload length 1
    b[7] = status;
    let _ = PicoHidConnection.send(&b, UsbEndpoint::MainHid);
}

/// Has the host sent CTAPHID_CANCEL on the current channel? Used by the blocking IR PIN entry, which
/// runs inside a CTAP command and so cannot hand packets to OpenSK (the user-presence wait can).
///
/// The queue is drained into a local buffer, the cancel packet is dropped and every other packet is put
/// back in its original order, all with interrupts off (a few microseconds), so the USB task cannot
/// interleave a packet and reorder them.
pub fn cancel_requested() -> bool {
    let cid = CUR_CID.load(Ordering::Relaxed);
    cortex_m::interrupt::free(|_| {
        let mut keep: heapless::Vec<HidPacket, QUEUE> = heapless::Vec::new();
        let mut cancel = false;
        while let Ok(p) = IN_CH.try_receive() {
            let is_cancel = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) == cid && p[4] == 0x91; // CTAPHID_CANCEL
            if is_cancel {
                cancel = true;
            } else {
                let _ = keep.push(p);
            }
        }
        for p in keep {
            let _ = IN_CH.try_send(p);
        }
        cancel
    })
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
            // Ok = queued, or dropped because the operation was cancelled meanwhile.
            let queued = SEND_LOCK.lock(|_| {
                if op_cancelled() {
                    Ok(())
                } else {
                    OUT_CH.try_send(*buf).map_err(|_| ())
                }
            });
            if queued.is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE);
            }
            crate::wdog::poll_wait(POLL);
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
