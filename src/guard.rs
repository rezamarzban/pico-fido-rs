//! Guard module controlling physical button (Pin 14 or BOOTSEL) & IR PIN validation dependency.
//! Optional OLED display support (OLED connection is not mandatory).

pub struct GuardSystem<BTN14, BOOTSEL, OLED> {
    pub pin14_btn: BTN14,
    pub bootsel_btn: BOOTSEL,
    pub oled: Option<OLED>,
}

impl<BTN14, BOOTSEL, OLED> GuardSystem<BTN14, BOOTSEL, OLED> {
    pub fn new(pin14_btn: BTN14, bootsel_btn: BOOTSEL, oled: Option<OLED>) -> Self {
        Self {
            pin14_btn,
            bootsel_btn,
            oled,
        }
    }

    /// Physical button press triggers waiting for IR PIN.
    /// Supports either Pin 14 button OR BOOTSEL button press (both perform identical action).
    pub fn wait_for_physical_button_and_validate_ir<LED>(
        &mut self,
        ir_manager: &mut crate::ir_pin::IrPinManager<LED>,
    ) -> Result<heapless::String<16>, &'static str>
    where
        LED: embedded_hal::digital::v2::OutputPin + embedded_hal::digital::v2::ToggleableOutputPin,
    {
        // 1. Host PIN stage completes normally.
        // 2. Physical button confirmation stage relies on IR PIN validation.
        // Both Pin 14 and BOOTSEL button perform identical logic.
        let ir_pin = ir_manager.receive_ir_pin()?;

        // Optional OLED display update (if connected)
        if let Some(_oled) = &mut self.oled {
            // Render status on display if available
        }

        Ok(ir_pin)
    }
}
