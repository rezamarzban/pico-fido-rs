#![no_std]
#![no_main]
// Nightly-only feature: the firmware must be built with the nightly toolchain pinned by
// rust-toolchain.toml (CI does the same). Host tests (host-test/) build on stable.
#![feature(impl_trait_in_assoc_type)]

#[global_allocator]
static HEAP: Heap = Heap::empty();
extern crate alloc;

use core::mem::MaybeUninit;
use cortex_m_rt::entry;
use defmt::*;
use embassy_executor::{InterruptExecutor, Spawner};
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::gpio::{Level, Output};
use embassy_rp::interrupt;
use embassy_rp::interrupt::{InterruptExt, Priority};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Timer};
use embedded_alloc::Heap;
use {defmt_rtt as _, panic_probe as _};

mod env;
mod keys;
mod layout;
#[cfg(feature = "oled")]
mod oled;
mod puf;
mod se;
mod seal;
mod sealed_log;
mod status;
mod usb;

use core::cell::RefCell;
use env::{FlashDir, FlashTally, PicoEnv, PicoPersist, PicoUserPresence};
use opensk::api::connection::{HidConnection as _, UsbEndpoint};
use opensk::env::Env as _;
use opensk::{Ctap, Transport};
use static_cell::StaticCell;

// Flash size is a deliberate board setting: enable exactly one `flash_*` Cargo feature.
// build.rs derives the linker script (memory.x) from the same feature.
const FLASH_MB: usize = (cfg!(feature = "flash_2m") as usize) * 2
    + (cfg!(feature = "flash_4m") as usize) * 4
    + (cfg!(feature = "flash_8m") as usize) * 8
    + (cfg!(feature = "flash_16m") as usize) * 16;
const _: () = core::assert!(
    matches!(FLASH_MB, 2 | 4 | 8 | 16),
    "enable exactly one of the flash_2m / flash_4m / flash_8m / flash_16m features"
);
pub const FLASH_SIZE: usize = FLASH_MB * 1024 * 1024;

/// Pages of 4 KiB at the end of flash for OpenSK's key-value store (72 KiB). build.rs keeps the
/// same area out of the linker's FLASH region: change them together.
pub const STORE_PAGES: usize = 18;
// Below the store: site directory sectors A and B (8 KiB each, src/env/dir_flash.rs), the signature
// counter (12 KiB, src/env/tally_flash.rs) and the SRAM-PUF helper sector (4 KiB, src/puf.rs): 104 KiB
// in all, see src/layout.rs. Everything but the helper sector is sealed with AES-256-GCM.

// Heap for OpenSK (alloc): credentials, CBOR, the P-256 software crypto, message buffers.
const HEAP_SIZE: usize = 128 * 1024;
static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

/// USB, the LED and the packet pump run on this executor, which is driven by a software interrupt
/// with higher priority than the main thread: OpenSK blocks in thread mode (waiting for the
/// button, computing signatures) and USB must keep running meanwhile.
static EXECUTOR_HIGH: InterruptExecutor = InterruptExecutor::new();

#[interrupt]
unsafe fn SWI_IRQ_1() {
    EXECUTOR_HIGH.on_interrupt()
}

/// Moves non-`Send` values into a task of the interrupt executor.
/// SAFETY: there is a single core, the values are only ever touched by tasks of that one executor
/// after the move, and the main thread keeps no reference to them.
struct AssertSend<T>(T);
unsafe impl<T> Send for AssertSend<T> {}

struct UsbParts {
    device: usb::Device,
    reader: usb::CtapReader,
    writer: usb::CtapWriter,
    led: Output<'static>,
}

/// Runs on the interrupt executor and starts the (non-`Send`) USB tasks on it.
#[embassy_executor::task]
async fn usb_executor_init(parts: AssertSend<UsbParts>) {
    let spawner = Spawner::for_current_executor().await;
    let UsbParts {
        device,
        reader,
        writer,
        led,
    } = parts.0;
    spawner.spawn(usb::run_usb(device)).unwrap();
    spawner.spawn(usb::usb_io(reader, writer)).unwrap();
    spawner.spawn(blinker(led)).unwrap();
}

/// Blinks 3 short flashes and a pause forever: the flash key is not available (see SECURITY.md).
/// USB is not running: nothing is served, nothing is read from or written to flash.
fn halt_with_fault(led: &mut Output<'static>) -> ! {
    loop {
        for _ in 0..3 {
            led.set_high();
            embassy_time::block_for(Duration::from_millis(120));
            led.set_low();
            embassy_time::block_for(Duration::from_millis(180));
        }
        embassy_time::block_for(Duration::from_millis(1200));
    }
}

/// Starts the SRAM PUF and installs it as the source of the flash encryption keys.
///
/// * helper sector valid and this boot's RAM sample decodes: go on.
/// * helper sector erased (new device, or the first start of this firmware over an older one): wipe
///   every area that is protected by the key (an older firmware left PLAINTEXT there), THEN write the
///   helper sector. The helper sector is the commit: a power cut before it repeats the wipe, so the
///   flash never holds plaintext secrets next to an enrolled key. Needs a power-on reset (unplug and
///   replug after flashing the firmware).
/// * anything else (damaged helper, sample does not decode, no power-on reset when one is needed):
///   halt with the fault blink; nothing is read or written. A re-plug fixes a noisy sample.
fn init_flash_key(flash: &'static RefCell<keys::Fl>, led: &mut Output<'static>) {
    let mut puf = puf::Puf::open(flash);
    if puf.status() == puf::Status::Blank {
        if !puf.can_enroll() {
            error!("puf: cannot enrol now - unplug the key for 10 s and plug it in again");
            halt_with_fault(led);
        }
        let secret = match se::ecdsa::chip_random() {
            Ok(r) => zeroize::Zeroizing::new(r),
            Err(_) => defmt::panic!("puf: the secure element gave no random bytes for the enrolment"),
        };
        warn!("first start with flash encryption: erasing the store, directory and counter");
        let wiped = flash
            .borrow_mut()
            .blocking_erase(
                (layout::PUF_START + layout::PAGE) as u32,
                FLASH_SIZE as u32,
            )
            .is_ok();
        if !wiped || !puf.enroll(flash, &secret) {
            error!("puf: enrolment failed");
            halt_with_fault(led);
        }
    }
    if puf.status() != puf::Status::Ready {
        error!("puf: no usable key (status {}) - halting", puf.status());
        halt_with_fault(led);
    }
    static PUF: StaticCell<puf::Puf> = StaticCell::new();
    puf::install(PUF.init(puf));
}

/// Publishes which chip slots hold a key and how many belong to a site (for the status display;
/// reads the flash directory, no chip access).
fn refresh_slot_status() {
    use portable_atomic::Ordering::Relaxed;
    if let Some(r) = se::ecdsa::slot_report() {
        status::SE_REGS.store(r.keys() as u32, Relaxed);
        status::SE_SITES.store(r.sites() as u32, Relaxed);
    }
}

/// Heap in use, bytes (for the status display).
pub fn heap_used() -> usize {
    HEAP.used()
}

#[entry]
fn main() -> ! {
    unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    info!("Starting (OpenSK)");

    let p = embassy_rp::init(Default::default());
    #[cfg(feature = "oled")]
    oled::init(p.I2C0, p.PIN_17, p.PIN_16);
    // ATECC608A: credential and attestation keys, signing and the RNG seed.
    se::i2c::init(p.I2C1, p.PIN_15, p.PIN_14);
    static FLASH: StaticCell<RefCell<keys::Fl>> = StaticCell::new();
    let flash: &'static RefCell<keys::Fl> = &*FLASH.init(RefCell::new(
        Flash::<_, Blocking, FLASH_SIZE>::new_blocking(p.FLASH),
    ));

    let mut led = {
        #[cfg(feature = "rp2040_board")]
        Output::new(p.PIN_25, Level::Low)
    };

    // Flash encryption key from the SRAM PUF. Must come before anything touches the store, the
    // directory or the counter; halts with a blink pattern if the key is not available.
    init_flash_key(flash, &mut led);

    // Persistent serial number (privacy trade-off): build without `usb_serial` to omit it.
    let serial = if cfg!(feature = "usb_serial") {
        keys::serial(&mut flash.borrow_mut())
    } else {
        None
    };

    // USB + LED on the high-priority executor.
    let (device, reader, writer) = usb::create_usb(p.USB, serial);
    interrupt::SWI_IRQ_1.set_priority(Priority::P2);
    let spawner = EXECUTOR_HIGH.start(interrupt::SWI_IRQ_1);
    spawner
        .spawn(usb_executor_init(AssertSend(UsbParts {
            device,
            reader,
            writer,
            led,
        })))
        .unwrap();

    // OpenSK in thread mode. The flash moves into the key-value store, BOOTSEL into user presence.
    // The site directory (which site owns which chip key slot) is in the Pico's flash, not in the chip.
    static DIR: StaticCell<FlashDir> = StaticCell::new();
    se::ecdsa::install_dir(DIR.init(FlashDir::new(flash)));
    // The lifetime signature count is in the Pico's flash too (the chip counts nothing).
    static TALLY: StaticCell<FlashTally> = StaticCell::new();
    se::ecdsa::install_tally(TALLY.init(FlashTally::new(flash)));
    refresh_slot_status();
    let env = PicoEnv::new(PicoPersist::new(flash), PicoUserPresence::new(p.BOOTSEL));
    let mut ctap = Ctap::new(env);
    info!("OpenSK initialised");
    opensk_loop(&mut ctap)
}

/// Same structure as OpenSK's reference main loop (src/lib.rs of the OpenSK repository): feed HID
/// packets to `process_hid_packet`, send the answers, and drive WINK and the U2F touch.
fn opensk_loop(ctap: &mut Ctap<PicoEnv>) -> ! {
    let mut winking = false;
    let mut u2f_armed = false;
    let mut seen = env::hid::epoch();
    #[cfg(feature = "oled")]
    let mut last_store_ms = 0u32;
    LED_SIGNAL.signal(LedState::Active);
    loop {
        // Key-value store figures for the display (reads the store: every 15 s at most).
        #[cfg(feature = "oled")]
        {
            let t = embassy_time::Instant::now().as_millis() as u32;
            if t.wrapping_sub(last_store_ms) >= 15_000 || last_store_ms == 0 {
                last_store_ms = t.max(1);
                if let Some((u, tot, lu, lt)) = ctap.env().persist().stats() {
                    status::set_store(u, tot, lu, lt);
                }
                refresh_slot_status();
            }
        }
        let wink = ctap.should_wink();
        if wink != winking {
            winking = wink;
            LED_SIGNAL.signal(if wink {
                LedState::Processing
            } else {
                LedState::Active
            });
        }

        // Block for a packet; wake up regularly while something needs polling.
        let timeout = if u2f_armed {
            Some(10)
        } else if winking {
            Some(100)
        } else {
            None
        };
        let mut packet = [0u8; 64];
        let mut received = env::hid::wait_packet(&mut packet, timeout, seen);

        // USB reset / suspend / unplug: the wait above ends at once. Drop a packet that was
        // dequeued just before the reset (it belongs to the old session) and stop polling for
        // the button; the host starts over with a new CTAPHID_INIT.
        let now = env::hid::epoch();
        if now != seen {
            seen = now;
            received = false;
            status::BUSY.store(false, portable_atomic::Ordering::Relaxed);
            u2f_armed = false;
            winking = false;
            LED_SIGNAL.signal(LedState::Active);
        }

        // U2F has no begin/end calls: the loop polls the button while a U2F request waits for it.
        if u2f_armed && ctap.env().user_presence().poll_fresh_press() {
            u2f_armed = false;
            ctap.u2f_grant_user_presence();
            LED_SIGNAL.signal(LedState::Processing);
        }

        if received {
            status::PKTS.fetch_add(1, portable_atomic::Ordering::Relaxed);
            status::BUSY.store(true, portable_atomic::Ordering::Relaxed);
            // Stamp the operation: everything blocking inside it (user presence, sends) stops
            // as soon as a reset / suspend / unplug bumps the epoch.
            let op = env::hid::begin_op_at(seen);
            for out in ctap.process_hid_packet(&packet, Transport::MainHid) {
                // A cancelled operation never answers (stale responses must not leak into the
                // next host session).
                if env::hid::epoch() != op {
                    break;
                }
                if ctap
                    .env()
                    .hid_connection()
                    .send(&out, UsbEndpoint::MainHid)
                    .is_err()
                {
                    warn!("USB: could not send a response packet");
                    break;
                }
            }
            status::BUSY.store(false, portable_atomic::Ordering::Relaxed);
            // A registration may have taken a slot: update the key-slot page of the display.
            refresh_slot_status();
            if !u2f_armed && !winking {
                LED_SIGNAL.signal(LedState::Active);
            }
        }

        let needs_touch = ctap.u2f_needs_user_presence();
        if needs_touch && !u2f_armed {
            u2f_armed = true;
            ctap.env().user_presence().arm();
            LED_SIGNAL.signal(LedState::Confirm);
        } else if !needs_touch && u2f_armed {
            u2f_armed = false;
            LED_SIGNAL.signal(LedState::Active);
        }
    }
}

pub static LED_SIGNAL: Signal<CriticalSectionRawMutex, LedState> = Signal::new();

#[derive(Debug, Default, Format)]
pub enum LedState {
    Confirm, // Waiting for user to confirm
    #[default]
    Idle,
    Active,
    Processing,
}

#[embassy_executor::task]
pub async fn blinker(mut led: Output<'static>) {
    let mut signal = LedState::default();

    loop {
        if let Some(new_signal) = LED_SIGNAL.try_take() {
            info!("Got new signal: {}", new_signal);
            signal = new_signal;
        }

        let (on_time, off_time) = match signal {
            LedState::Confirm => (Duration::from_secs(1), Duration::from_millis(100)),
            LedState::Idle => (Duration::from_millis(500), Duration::from_secs(1)),
            LedState::Active => (Duration::from_millis(200), Duration::from_millis(200)),
            LedState::Processing => (Duration::from_millis(50), Duration::from_millis(50)),
        };

        led.set_high();
        Timer::after(on_time).await;
        led.set_low();
        Timer::after(off_time).await;
    }
}
