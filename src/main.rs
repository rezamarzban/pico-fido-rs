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
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Timer};
use embedded_alloc::Heap;
use static_cell::StaticCell;
use usbd_hid::descriptor::KeyboardUsage;
use {defmt_rtt as _, panic_probe as _};

mod cbor;
mod ctap;
mod ctaphid;
mod keys;
mod usb;
use ctap::Ctap;
use usb::{create_usb_tasks, ctap_task, HID_CHANNEL_LEN};

// The master key lives in the last 4K sector of this much flash (see memory.x).
pub const FLASH_SIZE: usize = 2 * 1024 * 1024;

const HEAP_SIZE: usize = 32 * 1024;
static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    info!("Starting");
    let p = embassy_rp::init(Default::default());

    let mut flash = Flash::<_, Blocking, FLASH_SIZE>::new_blocking(p.FLASH);
    let ctap = Ctap::new(keys::load_or_create(&mut flash));

    // Get board specific pin
    let led_pin = {
        #[cfg(feature = "rp2040_board")]
        Output::new(p.PIN_25, Level::Low)
    };

    static HID_KEYBOARD_CHANNEL: StaticCell<Channel<NoopRawMutex, KeyboardUsage, HID_CHANNEL_LEN>> =
        StaticCell::new();
    let keyboard_ch =
        HID_KEYBOARD_CHANNEL.init(Channel::<NoopRawMutex, KeyboardUsage, HID_CHANNEL_LEN>::new());
    let (usb_task, hid_writer, hid_reader, ctap_rd, ctap_wr) =
        create_usb_tasks(p.USB, keyboard_ch.receiver());

    spawner.spawn(blinker(led_pin)).unwrap();
    spawner.spawn(usb_task).unwrap();
    spawner.spawn(hid_writer).unwrap();
    spawner.spawn(hid_reader).unwrap();
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
