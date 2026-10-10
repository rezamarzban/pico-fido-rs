#![no_std]
#![no_main]
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
mod keys;
mod store;
mod usb;
use ctap::Ctap;
use usb::{create_usb_tasks, ctap_task};

// Two 4K sectors at the end of this much flash hold the master key (see memory.x, store.rs).
pub const FLASH_SIZE: usize = 2 * 1024 * 1024;

const HEAP_SIZE: usize = 32 * 1024;
static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    info!("Starting");
    let p = embassy_rp::init(Default::default());

    let mut flash = Flash::<_, Blocking, FLASH_SIZE>::new_blocking(p.FLASH);
    let (master, pos) = keys::load(&mut flash);
    let ctap = Ctap::new(master);
    let serial = keys::serial(&mut flash);

    // Get board specific pin
    let led_pin = {
        #[cfg(feature = "rp2040_board")]
        Output::new(p.PIN_25, Level::Low)
    };

    let (usb_task, ctap_rd, ctap_wr) = create_usb_tasks(p.USB, serial);

    spawner.spawn(blinker(led_pin)).unwrap();
    spawner.spawn(usb_task).unwrap();
    spawner
        .spawn(ctap_task(ctap_rd, ctap_wr, ctap, p.BOOTSEL, flash, pos))
        .unwrap();
}

pub static LED_SIGNAL: Signal<CriticalSectionRawMutex, LedState> = Signal::new();

#[derive(Debug, Default, Format)]
pub enum LedState {
    Confirm, // Waiting for user to confirm
    #[default]
    Idle, // Pico goes to sleep
    Active,  // Awake and waiting for a command
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
