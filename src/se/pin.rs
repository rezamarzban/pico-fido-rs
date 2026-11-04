//! PIN verification by the chip. The FIDO pinHash (LEFT(SHA-256(PIN),16)) is turned into the PIN
//! key (`auth::pin_key`); the chip compares it with the key in its PIN slot (CheckMac). On success
//! the key is kept in RAM so every later signing session can re-authorise; `lock()` drops it.
//! A wrong PIN is refused by the chip and, because the PIN slot is LimitedUse, burns budget.

use super::auth;
use super::chip::Auth;
use super::ecdsa::{clear_auth, set_auth, with_chip};
use super::proto::Error;

/// `Err(Error::Status(1))` = wrong PIN. Other errors: chip trouble / budget used up.
pub fn verify(pin_hash: &[u8; 16]) -> Result<(), Error> {
    let sn = with_chip(|c| c.serial())?;
    let a = Auth { slot: auth::PIN_SLOT, key: auth::pin_key(&sn, pin_hash) };
    with_chip(|c| c.check_pin(&a))?;
    set_auth(Some(a));
    Ok(())
}

pub fn lock() {
    clear_auth();
}
