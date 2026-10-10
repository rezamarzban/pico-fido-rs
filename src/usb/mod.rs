use embassy_executor::SpawnToken;
use embassy_rp::peripherals::USB;
use embassy_rp::usb::Driver;
use embassy_rp::{bind_interrupts, usb::InterruptHandler};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Receiver;
use embassy_usb::class::hid::{HidReaderWriter, State};
use embassy_usb::{Builder, Config, Handler, UsbDevice};

use core::sync::atomic::{AtomicBool, Ordering};
use defmt::*;
use static_cell::StaticCell;
use usbd_hid::descriptor::{KeyboardReport, KeyboardUsage, SerializedDescriptor};

pub mod ctap;
pub use ctap::{ctap_task, Reader as CtapReader, Writer as CtapWriter, FIDO_REPORT_DESC};
pub mod hid;
pub use hid::{hid_reader, hid_writer, HID_CHANNEL_LEN};

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
});

#[embassy_executor::task]
async fn run_usb(mut usb: UsbDevice<'static, Driver<'static, USB>>) {
    usb.run().await;
}

pub fn create_usb_tasks(
    usb: USB,
    keyboard_recv: Receiver<'static, NoopRawMutex, KeyboardUsage, HID_CHANNEL_LEN>,
) -> (
    SpawnToken<impl Sized>,
    SpawnToken<impl Sized>,
    SpawnToken<impl Sized>,
    CtapReader,
    CtapWriter,
) {
    let driver = Driver::new(usb, Irqs);

    // These are what is reconized by ctap apps like yubikey
    // and may need to be changed to be reconized
    // Create embassy-usb Config - VID, PID
    let mut config = Config::new(0xc0de, 0xcafe);
    // Configures usb as a composite device (uses more than one protocol)
    config.composite_with_iads = true;
    config.device_class = 0xEF; // composite class (multiple usb protocols)
    config.device_sub_class = 0x02;
    config.device_protocol = 0x01;
    config.manufacturer = Some("LegtCamper");
    config.product = Some("Pico Fido");
    config.serial_number = Some("12345678");
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

    let (hid_receiver, hid_sender) = {
        let config = embassy_usb::class::hid::Config {
            report_descriptor: KeyboardReport::desc(),
            request_handler: None,
            poll_ms: 60,
            max_packet_size: 64,
        };
        static STATE: StaticCell<State> = StaticCell::new();
        HidReaderWriter::<_, 1, 8>::new(&mut builder, STATE.init(State::new()), config)
    }
    .split();

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
    (
        run_usb(usb),
        hid_writer(hid_sender, keyboard_recv),
        hid_reader(hid_receiver),
        ctap_receiver,
        ctap_sender,
    )
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
        if enabled {
            info!("Device enabled");
        } else {
            info!("Device disabled");
        }
    }

    fn reset(&mut self) {
        self.configured.store(false, Ordering::Relaxed);
        info!("Bus reset, the Vbus current limit is 100mA");
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
