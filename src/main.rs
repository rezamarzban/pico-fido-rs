#![no_std]
#![no_main]
// Nightly-only feature: the firmware must be built with the nightly toolchain pinned by
// rust-toolchain.toml (CI does the same). Host tests (host-test/) build on stable.
#![feature(impl_trait_in_assoc_type)]

#[global_allocator]
static HEAP: Heap = Heap::empty();
extern crate alloc;

use core::mem::MaybeUninit;
use defmt::*;
use embassy_executor::Spawner;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::gpio::{Level, Output};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Timer};
use embedded_alloc::Heap;
use {defmt_rtt as _, panic_probe as _};

mod cbor;
mod ctap;
mod ctaphid;
mod health;
mod keys;
mod pin;
mod store;
mod usb;
mod wrap;
use ctap::Ctap;
use usb::{create_usb_tasks, ctap_task};

// Three 4K sectors at the end of the flash hold the key slots and the PIN retry counter (store.rs). The flash size is a
// deliberate board setting: enable exactly one `flash_*` Cargo feature. build.rs derives the
// linker script (memory.x) from the same feature, so code and linker layout always agree.
const FLASH_MB: usize = (cfg!(feature = "flash_2m") as usize) * 2
    + (cfg!(feature = "flash_4m") as usize) * 4
    + (cfg!(feature = "flash_8m") as usize) * 8
    + (cfg!(feature = "flash_16m") as usize) * 16;
const _: () = assert!(
    matches!(FLASH_MB, 2 | 4 | 8 | 16),
    "enable exactly one of the flash_2m / flash_4m / flash_8m / flash_16m features"
);
pub const FLASH_SIZE: usize = FLASH_MB * 1024 * 1024;

// 160 KiB: Argon2 (wrap.rs) allocates up to MAX_M_KIB (128 KiB) while a PIN is being checked.
const HEAP_SIZE: usize = 160 * 1024;
static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    info!("Starting");
    let p = embassy_rp::init(Default::default());

    let mut flash = Flash::<_, Blocking, FLASH_SIZE>::new_blocking(p.FLASH);
    let rec = keys::load(&mut flash);
    let ctap = Ctap::new(rec);
    // A persistent serial number lets hosts recognise this exact device across connections
    // (privacy trade-off): build without the `usb_serial` feature to omit it.
    let serial = if cfg!(feature = "usb_serial") {
        keys::serial(&mut flash)
    } else {
        None
    };

    // Get board specific pin
    let led_pin = {
        #[cfg(feature = "rp2040_board")]
        Output::new(p.PIN_25, Level::Low)
    };

    let (usb_task, ctap_rd, ctap_wr) = create_usb_tasks(p.USB, serial);

    spawner.spawn(blinker(led_pin)).unwrap();
    spawner.spawn(usb_task).unwrap();
    spawner
        .spawn(ctap_task(ctap_rd, ctap_wr, ctap, p.BOOTSEL, flash))
        .unwrap();
}

pub static LED_SIGNAL: Signal<CriticalSectionRawMutex, LedState> = Signal::new();

#[derive(Debug, Default, Format)]
pub enum LedState {
    Confirm, // Waiting for user to confirm
    #[default]
    Idle, // Pico goes to sleep
    Active, // Awake and waiting for a command
    Processing, // Busy and cannot receive new commands
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
