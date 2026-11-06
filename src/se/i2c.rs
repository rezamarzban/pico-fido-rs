//! ATECC608A on the RP2040: I2C1, SDA = GP14, SCL = GP15, 7-bit address 0x60, 100 kHz.
//!
//! embassy-rp refuses reserved addresses (0x00), so the wake pulse is made differently: the bus is
//! slowed to 25 kHz for one write to the chip's own address. A sleeping chip does not answer, but
//! the address byte (1100000 + W) holds SDA low for six bit times = 240 us >= tWLO (60 us), which
//! wakes it. The bus then returns to 100 kHz and we wait tWHI.

use defmt::{info, panic};
use embassy_embedded_hal::SetConfig;
use embassy_rp::i2c::{Blocking, Config, I2c};
use embassy_rp::peripherals::{I2C1, PIN_14, PIN_15};
use embassy_time::{block_for, Duration};
use static_cell::StaticCell;

use super::chip::{Atecc, Bus};
use super::ecdsa;
use super::proto::ADDR_7BIT;

const NORMAL_HZ: u32 = 100_000;
const WAKE_HZ: u32 = 25_000;
const T_WHI_US: u64 = 2_500; // datasheet minimum 1.5 ms

pub struct RpBus {
    i2c: I2c<'static, I2C1, Blocking>,
}

fn cfg(hz: u32) -> Config {
    let mut c = Config::default();
    c.frequency = hz;
    c
}

impl Bus for RpBus {
    fn wake_pulse(&mut self) {
        let _ = self.i2c.set_config(&cfg(WAKE_HZ));
        let _ = self.i2c.blocking_write(ADDR_7BIT, &[0x00]);
        let _ = self.i2c.set_config(&cfg(NORMAL_HZ));
        // set_config may rewrite the pads: keep the internal pull-ups on (see oled.rs).
        pull_ups();
        block_for(Duration::from_micros(T_WHI_US));
    }

    fn write(&mut self, data: &[u8]) -> Result<(), ()> {
        self.i2c.blocking_write(ADDR_7BIT, data).map_err(|_| ())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<(), ()> {
        self.i2c.blocking_read(ADDR_7BIT, buf).map_err(|_| ())
    }

    fn delay_ms(&mut self, ms: u32) {
        block_for(Duration::from_millis(ms as u64));
    }
}

fn pull_ups() {
    for pin in [14usize, 15] {
        embassy_rp::pac::PADS_BANK0.gpio(pin).modify(|w| w.set_pue(true));
    }
}

/// Starts the bus, checks that the chip answers, and registers it for `se::ecdsa`. Halts (panic)
/// if the chip is missing: the credential keys and the RNG seed come from it, so there is nothing
/// useful to do without it.
pub fn init(i2c: I2C1, scl: PIN_15, sda: PIN_14) {
    let bus = I2c::new_blocking(i2c, scl, sda, cfg(NORMAL_HZ));
    pull_ups();
    static CHIP: StaticCell<Atecc<RpBus>> = StaticCell::new();
    let chip = CHIP.init(Atecc::new(RpBus { i2c: bus }));
    ecdsa::install(chip);
    match ecdsa::chip_info() {
        Some(i) => {
            crate::status::set_se(&i);
            if let Some(n) = ecdsa::registrations() {
                crate::status::SE_REGS.store(n, portable_atomic::Ordering::Relaxed);
            }
            info!(
                "ATECC608A ready: serial {=[u8]:x}, revision {=[u8]:x}, config locked {}, data locked {}",
                &i.serial[..],
                &i.revision[..],
                i.config_locked,
                i.data_locked
            )
        }
        None => panic!("ATECC608A not found on I2C1 (SDA GP14, SCL GP15, address 0x60)"),
    }
}
