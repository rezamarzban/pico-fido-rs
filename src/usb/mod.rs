use embassy_rp::peripherals::USB;
use embassy_rp::usb::Driver;
use embassy_rp::{bind_interrupts, usb::InterruptHandler};
use embassy_usb::class::hid::{HidReaderWriter, State};
use embassy_usb::{Builder, Config, Handler, UsbDevice};

use core::sync::atomic::{AtomicBool, Ordering};
use defmt::*;
use static_cell::StaticCell;

pub mod ctap;

pub use ctap::{usb_io, Reader as CtapReader, Writer as CtapWriter, FIDO_REPORT_DESC};

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
});

#[embassy_executor::task]
pub async fn run_usb(mut usb: UsbDevice<'static, Driver<'static, USB>>) {
    usb.run().await;
}

/// PROTOTYPE USB identifiers. Replace before distribution.
pub const USB_VID: u16 = 0xc0de;
pub const USB_PID: u16 = 0xcafe;
pub const USB_MANUFACTURER: &str = "LegtCamper";
pub const USB_PRODUCT: &str = "Pico Fido";

pub type Device = UsbDevice<'static, Driver<'static, USB>>;

/// Builds the USB device with its FIDO HID interface. Spawn `run_usb(device)` and
/// `usb_io(reader, writer)` on the USB executor.
/// `serial = None` presents no serial number.
pub fn create_usb(usb: USB, serial: Option<&'static str>) -> (Device, CtapReader, CtapWriter) {
    let driver = Driver::new(usb, Irqs);

    let mut config = Config::new(USB_VID, USB_PID);
    config.manufacturer = Some(USB_MANUFACTURER);
    config.product = Some(USB_PRODUCT);
    config.serial_number = serial;
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
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

    let (ctap_receiver, ctap_sender) = {
        let config = embassy_usb::class::hid::Config {
            report_descriptor: FIDO_REPORT_DESC,
            request_handler: None,
            poll_ms: 5,
            max_packet_size: 64,
        };
        static STATE: StaticCell<State> = StaticCell::new();
        HidReaderWriter::<_, 64, 64>::new(&mut builder, STATE.init(State::new()), config).split()
    };

    (builder.build(), ctap_receiver, ctap_sender)
}

struct UsbHandler {
    configured: AtomicBool,
}

impl UsbHandler {
    fn new() -> Self {
        Self {
            configured: AtomicBool::new(false),
        }
    }
}

impl Handler for UsbHandler {
    fn enabled(&mut self, enabled: bool) {
        self.configured.store(false, Ordering::Relaxed);
        if enabled {
            info!("USB enabled");
        } else {
            info!("USB disabled");
            crate::env::hid::flush();
        }
    }

    fn reset(&mut self) {
        self.configured.store(false, Ordering::Relaxed);
        info!("USB reset");
        // The host starts over with a new CTAPHID_INIT: stale packets must not reach OpenSK.
        crate::env::hid::flush();
    }

    fn addressed(&mut self, _addr: u8) {
        self.configured.store(false, Ordering::Relaxed);
    }

    fn configured(&mut self, configured: bool) {
        self.configured.store(configured, Ordering::Relaxed);
        if configured {
            info!("USB configured");
        } else {
            info!("USB deconfigured");
            crate::env::hid::flush();
        }
    }

    fn suspended(&mut self, suspended: bool) {
        if suspended {
            info!("USB suspended");
            crate::env::hid::flush();
        }
    }
}
