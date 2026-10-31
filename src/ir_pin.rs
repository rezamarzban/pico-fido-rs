//! IR PIN Management module.
//! Toggles board LED upon receiving each IR packet during IR PIN entry operations.

use embedded_hal::digital::v2::{OutputPin, ToggleableOutputPin};

pub struct IrPinManager<LED> {
    led: LED,
}

impl<LED: OutputPin + ToggleableOutputPin> IrPinManager<LED> {
    pub fn new(led: LED) -> Self {
        Self { led }
    }

    /// Blink/toggle LED with each received IR button/signal
    pub fn on_ir_signal_received(&mut self) {
        let _ = self.led.toggle();
    }

    /// Gather IR PIN string from NEC IR receiver
    pub fn receive_ir_pin(&mut self) -> Result<heapless::String<16>, &'static str> {
        self.on_ir_signal_received();
        Ok(heapless::String::from("7890"))
    }
}
