use embassy_executor::SpawnToken;
use embassy_rp::peripherals::USB;
use embassy_rp::usb::Driver;
use embassy_rp::{bind_interrupts, usb::InterruptHandler};
use embassy_usb::class::hid::{HidReaderWriter, State};
use embassy_usb::{Builder, Config, Handler, UsbDevice};

use core::sync::atomic::{AtomicBool, Ordering};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use defmt::*;
use static_cell::StaticCell;

pub mod ctap;

/// Raised on USB reset / suspend / disable: the CTAP task then ends the PIN session and wipes the
/// unwrapped master key from RAM.
pub static WIPE: Signal<CriticalSectionRawMutex, ()> = Signal::new();
pub use ctap::{ctap_task, Reader as CtapReader, Writer as CtapWriter, FIDO_REPORT_DESC};

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
});

#[embassy_executor::task]
async fn run_usb(mut usb: UsbDevice<'static, Driver<'static, USB>>) {
    usb.run().await;
}

/// PROTOTYPE USB identifiers. They are not assigned to this project and must be replaced before
/// the device is distributed (open-source projects can request a PID under VID 0x1209 from
/// pid.codes; commercial products need their own VID). The strings are placeholders as well.
pub const USB_VID: u16 = 0xc0de;
pub const USB_PID: u16 = 0xcafe;
pub const USB_MANUFACTURER: &str = "LegtCamper";
pub const USB_PRODUCT: &str = "Pico Fido";

/// `serial = None` presents no serial number (see keys::serial and the `usb_serial` feature).
pub fn create_usb_tasks(
    usb: USB,
    serial: Option<&'static str>,
) -> (SpawnToken<impl Sized>, CtapReader, CtapWriter) {
    let driver = Driver::new(usb, Irqs);

    // These are what is reconized by ctap apps like yubikey
    // and may need to be changed to be reconized
    // Create embassy-usb Config - VID, PID
    let mut config = Config::new(USB_VID, USB_PID);
    config.manufacturer = Some(USB_MANUFACTURER);
    config.product = Some(USB_PRODUCT);
    config.serial_number = serial;
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    // Create embassy-usb DeviceBuilder using the driver and config.
    // It needs some buffers for building the descriptors.
    static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    // You can also add a Microsoft OS descriptor.
    static MSOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();

    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESCRIPTOR.init([0; 256]),
        BOS_DESCRIPTOR.init([0; 256]),
        MSOS_DESCRIPTOR.init([0; 256]),
        CONTROL_BUF.init([0; 64]),
    );

    static DEVICE_HANDLER: StaticCell<UsbHandler> = StaticCell::new();
    builder.handler(DEVICE_HANDLER.init(UsbHandler::new()));

    // Create the usb classes

    let (ctap_receiver, ctap_sender) = {
        let config = embassy_usb::class::hid::Config {
            report_descriptor: FIDO_REPORT_DESC,
            request_handler: None,
            poll_ms: 5,
            max_packet_size: 64,
        };
        static STATE: StaticCell<State> = StaticCell::new();
        HidReaderWriter::<_, 64, 64>::new(&mut builder, STATE.init(State::new()), config)
    }
    .split();

    // Build the builder.
    let usb = builder.build();

    // return usb tasks
    (run_usb(usb), ctap_receiver, ctap_sender)
}

struct UsbHandler {
    configured: AtomicBool,
}

impl UsbHandler {
    fn new() -> Self {
        UsbHandler {
            configured: AtomicBool::new(false),
        }
    }
}

impl Handler for UsbHandler {
    fn enabled(&mut self, enabled: bool) {
        self.configured.store(false, Ordering::Relaxed);
        if !enabled {
            WIPE.signal(());
        }
        if enabled {
            info!("Device enabled");
        } else {
            info!("Device disabled");
        }
    }

    fn reset(&mut self) {
        self.configured.store(false, Ordering::Relaxed);
        WIPE.signal(());
        info!("Bus reset, the Vbus current limit is 100mA");
    }

    fn suspended(&mut self, suspended: bool) {
        if suspended {
            WIPE.signal(());
        }
    }

    fn addressed(&mut self, addr: u8) {
        self.configured.store(false, Ordering::Relaxed);
        info!("USB address set to: {}", addr);
    }

    fn configured(&mut self, configured: bool) {
        self.configured.store(configured, Ordering::Relaxed);
        if configured {
            info!(
                "Device configured, it may now draw up to the configured current limit from Vbus."
            )
        } else {
            info!("Device is no longer configured, the Vbus current limit is 100mA.");
        }
    }
}
