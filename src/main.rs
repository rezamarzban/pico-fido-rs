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
mod health;
mod keys;
mod usb;

use env::{PicoEnv, PicoPersist, PicoUserPresence};
use opensk::api::connection::{HidConnection as _, UsbEndpoint};
use opensk::env::Env as _;
use opensk::{Ctap, Transport};

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

/// Pages of 4 KiB at the end of flash for OpenSK's key-value store. build.rs keeps the same
/// amount (80 KiB) out of the linker's FLASH region: change both together.
pub const STORE_PAGES: usize = 20;

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

#[entry]
fn main() -> ! {
    unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    info!("Starting (OpenSK)");

    let p = embassy_rp::init(Default::default());
    let mut flash = Flash::<_, Blocking, FLASH_SIZE>::new_blocking(p.FLASH);

    // Persistent serial number (privacy trade-off): build without `usb_serial` to omit it.
    let serial = if cfg!(feature = "usb_serial") {
        keys::serial(&mut flash)
    } else {
        None
    };

    let led = {
        #[cfg(feature = "rp2040_board")]
        Output::new(p.PIN_25, Level::Low)
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
    LED_SIGNAL.signal(LedState::Active);
    loop {
        let wink = ctap.should_wink();
        if wink != winking {
            winking = wink;
            LED_SIGNAL.signal(if wink { LedState::Processing } else { LedState::Active });
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
        let received = env::hid::recv_packet(&mut packet, timeout);

        // U2F has no begin/end calls: the loop polls the button while a U2F request waits for it.
        if u2f_armed && ctap.env().user_presence().poll_fresh_press() {
            u2f_armed = false;
            ctap.u2f_grant_user_presence();
            LED_SIGNAL.signal(LedState::Processing);
        }

        if received {
            for out in ctap.process_hid_packet(&packet, Transport::MainHid) {
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
