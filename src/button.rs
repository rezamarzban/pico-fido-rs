//! The physical confirmation button: the BOOTSEL button of the Pico **or** an external key between
//! GP14 (pin 19) and GND (internal pull-up, pressed = low). Both do exactly the same: a press of either one is
//! "the button". Used for user presence (`env/user_presence.rs`) and to confirm / cancel an IR PIN entry
//! (`ir_pin.rs`).
//!
//! The external key is optional: with nothing connected GP14 reads high (pull-up) and only BOOTSEL
//! counts. Debouncing is left to the callers (a press must be seen after a release; the PIN entry
//! ignores presses shorter than 30 ms).
use core::cell::RefCell;
use embassy_rp::gpio::Input;
use embassy_rp::peripherals::BOOTSEL;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;

static EXT: Mutex<CriticalSectionRawMutex, RefCell<Option<Input<'static>>>> =
    Mutex::new(RefCell::new(None));

/// Hands the (pull-up) GP14 input over. Call once from `main`.
pub fn init_ext(pin: Input<'static>) {
    EXT.lock(|c| *c.borrow_mut() = Some(pin));
}

/// Is the external key on GP14 pressed right now?
pub fn ext_pressed() -> bool {
    EXT.lock(|c| c.borrow().as_ref().is_some_and(|p| p.is_low()))
}

/// Is the button (either one) pressed right now? The external key is read first: reading BOOTSEL
/// briefly stops flash access, so it is skipped while GP14 already answers.
pub fn pressed(bootsel: &mut BOOTSEL) -> bool {
    ext_pressed() || bootsel.is_pressed()
}
