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
use embassy_rp::gpio::{Input, Level, Output, Pull};
use embassy_rp::interrupt;
use embassy_rp::interrupt::{InterruptExt, Priority};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{with_timeout, Duration, Timer};
use embedded_alloc::Heap;
use {defmt_rtt as _, panic_probe as _};

mod button;
mod env;
mod guard;
mod health;
mod keys;
mod puf;
mod ram_guard;
#[cfg(feature = "ir")]
mod ir;
#[cfg(feature = "ir")]
mod ir_pin;
#[cfg(feature = "ir")]
mod nec;
#[cfg(feature = "oled")]
mod oled;
mod scrub;
#[cfg(feature = "stack_probe")]
mod stack_probe;
mod status;
mod wdog;
mod store;
mod usb;
mod vault;
mod wrap;

use core::cell::RefCell;
use embassy_rp::adc::{Adc, Channel as AdcChannel, Config as AdcConfig};
use env::{HardenPersist, PicoEnv, PicoPersist, PicoUserPresence};
use static_cell::StaticCell;
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

/// Pages of 4 KiB at the end of flash for OpenSK's key-value store. build.rs keeps the store
/// (72 KiB), the two PUF sectors and the vault (92 KiB in total) out of the linker's FLASH region:
/// change them together.
pub const STORE_PAGES: usize = 18;

/// The last 12 KiB of flash hold the vault: [PIN retry counter][seed slot 0][seed slot 1].
/// build.rs keeps them (and the store above) out of the linker's FLASH region.
pub const VAULT_BYTES: usize = 3 * 4096;

/// Two sectors just below the vault hold the SRAM-PUF helper data (src/puf.rs, two slots): 72 KiB
/// store + 8 KiB PUF + 12 KiB vault = the same 92 KiB build.rs keeps out of the FLASH region.
pub const PUF_BYTES: usize = 2 * 4096;

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
    /// VS1838B IR receiver (GP15).
    #[cfg(feature = "ir")]
    ir: Input<'static>,
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
        #[cfg(feature = "ir")]
        ir,
    } = parts.0;
    spawner.spawn(usb::run_usb(device)).unwrap();
    spawner.spawn(usb::usb_io(reader, writer)).unwrap();
    spawner.spawn(blinker(led)).unwrap();
    #[cfg(feature = "ir")]
    spawner.spawn(ir::ir_task(ir)).unwrap();
    // Adaptive share refresh (src/guard.rs), also while the main thread signs or waits for the button.
    spawner.spawn(guard::tick_task()).unwrap();
}

/// Heap in use, bytes (for the status display).
pub fn heap_used() -> usize {
    HEAP.used()
}

#[entry]
fn main() -> ! {
    unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    // A warm reset (watchdog, panic) keeps RAM: overwrite what the previous run left on the stack.
    scrub::stack_boot();
    #[cfg(feature = "stack_probe")]
    stack_probe::paint();
    info!("Starting (OpenSK)");

    let p = embassy_rp::init(Default::default());
    #[cfg(feature = "watchdog")]
    wdog::start(embassy_rp::watchdog::Watchdog::new(p.WATCHDOG));
    #[cfg(feature = "oled")]
    oled::init(p.I2C0, p.PIN_17, p.PIN_16);
    let mut flash = Flash::<_, Blocking, FLASH_SIZE>::new_blocking(p.FLASH);
    // External confirmation key on GP14 (to GND, internal pull-up): does the same as BOOTSEL.
    button::init_ext(Input::new(p.PIN_14, Pull::Up));

    // RAM guard: seed the mask DRBG once, before any secret is stored (ROSC, flash unique ID,
    // ADC noise, timer jitter -> SHA-256).
    {
        let mut uid = [0u8; 8];
        let _ = flash.blocking_unique_id(&mut uid); // not secret; a failed read only drops that input
        let mut adc = Adc::new_blocking(p.ADC, AdcConfig::default());
        let mut sensor = AdcChannel::new_temp_sensor(p.ADC_TEMP_SENSOR);
        guard::init(&uid, || adc.blocking_read(&mut sensor).unwrap_or(0));
    }

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
            #[cfg(feature = "ir")]
            ir: Input::new(p.PIN_15, Pull::Up),
        })))
        .unwrap();

    // OpenSK in thread mode. The flash moves into the key-value store, BOOTSEL into user presence.
    static FLASH: StaticCell<RefCell<keys::Fl>> = StaticCell::new();
    let flash: &'static RefCell<keys::Fl> = &*FLASH.init(RefCell::new(flash));
    let puf = puf::Puf::open(flash);
    let (vault, rec, blank) = vault::open(flash, !puf.required());
    let persist = HardenPersist::new(PicoPersist::new(flash), vault, rec, blank, puf);
    let env = PicoEnv::new(persist, PicoUserPresence::new(p.BOOTSEL));
    let mut ctap = Ctap::new(env);
    info!("OpenSK initialised");
    opensk_loop(&mut ctap)
}

/// Same structure as OpenSK's reference main loop (src/lib.rs of the OpenSK repository): feed HID
/// packets to `process_hid_packet`, send the answers, and drive WINK and the U2F touch.
fn opensk_loop(ctap: &mut Ctap<PicoEnv>) -> ! {
    let mut winking = false;
    let mut u2f_armed = false;
    // After a denied U2F confirmation no new touch is armed until this time (ms).
    let mut u2f_block_until = 0u32;
    let mut seen = env::hid::epoch();
    #[cfg(feature = "oled")]
    let mut last_store_ms = 0u32;
    LED_SIGNAL.signal(LedState::Active);
    loop {
        wdog::feed();
        // Key-value store figures for the display (reads the store: every 15 s at most).
        #[cfg(feature = "oled")]
        {
            let t = embassy_time::Instant::now().as_millis() as u32;
            if t.wrapping_sub(last_store_ms) >= 15_000 || last_store_ms == 0 {
                last_store_ms = t.max(1);
                if let Some((u, tot, lu, lt)) = ctap.env().persist().store_stats() {
                    status::set_store(u, tot, lu, lt);
                }
            }
        }
        #[cfg(feature = "stack_probe")]
        stack_probe::report();
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
        let mut received = env::hid::wait_packet(&mut packet, timeout, seen);

        // USB reset / suspend / unplug: the wait above ends at once. Forget the master key (the
        // next use needs the PIN again) and every in-flight operation: HID reassembly, pending
        // U2F touch, PIN tokens, stateful commands.
        let now = env::hid::epoch();
        if now != seen {
            seen = now;
            // A packet dequeued just before the reset belongs to the old session: drop it.
            received = false;
            ctap.env().persist().lock();
            ctap.cancel_in_flight();
            status::BUSY.store(false, portable_atomic::Ordering::Relaxed);
            scrub::stack();
            u2f_armed = false;
            winking = false;
            LED_SIGNAL.signal(LedState::Active);
        }

        // U2F has no begin/end calls: the loop polls the button while a U2F request waits for it. With an
        // IR PIN the button step includes the IR PIN entry (see `PicoUserPresence::u2f_press`).
        if u2f_armed {
            #[cfg(feature = "ir")]
            let press = ctap.env().user_presence().u2f_press();
            #[cfg(not(feature = "ir"))]
            let press = if ctap.env().user_presence().poll_fresh_press() {
                env::U2fPress::Granted
            } else {
                env::U2fPress::Waiting
            };
            match press {
                env::U2fPress::Granted => {
                    u2f_armed = false;
                    ctap.u2f_grant_user_presence();
                    LED_SIGNAL.signal(LedState::Processing);
                }
                env::U2fPress::Denied => {
                    // Cancelled / wrong IR PIN: forget the pending touch and do not ask again at once.
                    u2f_armed = false;
                    ctap.cancel_in_flight();
                    u2f_block_until = env::hid::epoch_ms().wrapping_add(5_000);
                    LED_SIGNAL.signal(LedState::Active);
                }
                env::U2fPress::Waiting => {}
            }
        }

        if received {
            guard::touch();
            env::hid::note_cid(&packet);
            status::PKTS.fetch_add(1, portable_atomic::Ordering::Relaxed);
            status::BUSY.store(true, portable_atomic::Ordering::Relaxed);
            // Stamp the operation: everything blocking inside it (user presence, sends) stops
            // as soon as a reset / suspend / unplug bumps the epoch.
            let op = env::hid::begin_op_at(seen);
            guard::refresh_now();
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
            guard::refresh_now();
            status::BUSY.store(false, portable_atomic::Ordering::Relaxed);
            // Dead stack frames of the command (moved keys, hash/HMAC state) may still hold
            // secret bytes: overwrite them now.
            scrub::stack();
            if !u2f_armed && !winking {
                LED_SIGNAL.signal(LedState::Active);
            }
        }

        let needs_touch = ctap.u2f_needs_user_presence();
        let u2f_blocked = env::hid::epoch_ms().wrapping_sub(u2f_block_until) >= u32::MAX / 2;
        if needs_touch && !u2f_armed && !u2f_blocked {
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

/// One-shot LED feedback of the IR PIN entry, shown on top of the steady pattern.
pub static LED_FLASH: Signal<CriticalSectionRawMutex, LedFlash> = Signal::new();

#[derive(Debug, Default, Format)]
pub enum LedState {
    Confirm, // Waiting for user to confirm
    #[default]
    Idle,
    Active,
    Processing,
    /// Waiting for the IR PIN on the remote (and the button): dark, a short blip about once a second;
    /// every key received from the remote answers with `LedFlash::Key`.
    IrEntry,
}

#[derive(Debug, Format, Clone, Copy)]
pub enum LedFlash {
    /// The remote's key press was received: one flash.
    Key,
    /// Wrong IR PIN, cancelled or timed out: two long flashes.
    Bad,
}

async fn flash(led: &mut Output<'static>, f: LedFlash) {
    match f {
        LedFlash::Key => {
            led.set_high();
            Timer::after(Duration::from_millis(120)).await;
            led.set_low();
            Timer::after(Duration::from_millis(60)).await;
        }
        LedFlash::Bad => {
            for _ in 0..2 {
                led.set_high();
                Timer::after(Duration::from_millis(300)).await;
                led.set_low();
                Timer::after(Duration::from_millis(150)).await;
            }
        }
    }
}

#[embassy_executor::task]
pub async fn blinker(mut led: Output<'static>) {
    let mut signal = LedState::default();
    let mut ticks: u32 = 0;

    loop {
        if let Some(new_signal) = LED_SIGNAL.try_take() {
            info!("Got new signal: {}", new_signal);
            signal = new_signal;
        }

        // SRAM PUF fault (key required but unavailable): 3 short blinks, then a pause. Takes
        // precedence over every other state until a boot / reset with a working key clears it.
        if puf::led_fault() {
            for _ in 0..3 {
                led.set_high();
                Timer::after(Duration::from_millis(80)).await;
                led.set_low();
                Timer::after(Duration::from_millis(120)).await;
            }
            Timer::after(Duration::from_millis(900)).await;
            continue;
        }

        // IR PIN feedback (a key of the remote was heard / the entry failed) comes first.
        if let Some(f) = LED_FLASH.try_take() {
            flash(&mut led, f).await;
            continue;
        }

        let (on_time, off_time) = match signal {
            LedState::Confirm => (Duration::from_secs(1), Duration::from_millis(100)),
            LedState::Idle => (Duration::from_millis(500), Duration::from_secs(1)),
            LedState::Active => (Duration::from_millis(200), Duration::from_millis(200)),
            LedState::Processing => (Duration::from_millis(50), Duration::from_millis(50)),
            LedState::IrEntry => {
                // Dark between keys; a short blip every ~1 s shows that the device waits for the remote.
                led.set_low();
                ticks = ticks.wrapping_add(1);
                if ticks % 20 == 0 {
                    led.set_high();
                    Timer::after(Duration::from_millis(40)).await;
                    led.set_low();
                }
                // Wake early for a key flash; the 50 ms also bound the reaction to a state change.
                if let Ok(f) = with_timeout(Duration::from_millis(50), LED_FLASH.wait()).await {
                    flash(&mut led, f).await;
                }
                continue;
            }
        };

        led.set_high();
        Timer::after(on_time).await;
        led.set_low();
        Timer::after(off_time).await;
    }
}
