# Using the flashed key

**Before you start:** try the key first on a throwaway account such as https://webauthn.io, not on anything important.
The maintainer reports this branch working on a Pico with Linux, Windows and Android browsers; the PIN-wrapping hardening has no detailed test record, and the whole key is still experimental (see `SECURITY.md`).

## 1. Check that the device is detected
- Plug in the Pico. It shows up as a FIDO HID device (VID `c0de`, PID `cafe`, product "Pico Fido").
- **Linux:** you may need a udev rule to use it without root:

  ```
  # /etc/udev/rules.d/70-pico-fido.rules
  KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="c0de", ATTRS{idProduct}=="cafe", TAG+="uaccess"
  ```

  Then `sudo udevadm control --reload && sudo udevadm trigger`.
- **Quick check:** `fido2-token -L` lists the device; `fido2-token -I <device>` shows what it supports (versions,
  options, PIN state).

## 2. Set a PIN
- Without a PIN, anyone who touches the key can use it. In the default build the seed in flash is wrapped with
  Argon2id when a PIN is set and bound to this chip's SRAM PUF (it is only masked by the PUF when no PIN is set), so a
  copy of the flash alone is not enough to guess the PIN offline or to recover the seed; **still use a long
  passphrase**. Anyone who can run code on the device (BOOTSEL, SWD) gets past the PUF (see `SECURITY.md`).
- Set the PIN with `fido2-token -S <device>`, `ykman fido access change-pin`, or the browser's security-key settings:
  - **Chrome / Edge:** Settings -> Privacy and security -> Security -> Manage security keys.
  - **Windows:** Settings -> Accounts -> Sign-in options -> Security key.
- The PIN must be at least **10 characters** (counted as Unicode code points; use a long passphrase). If the key asks for a touch while you set it,
  press BOOTSEL. Write the PIN down: there is no recovery.

## 3. Register
1. On a site, choose "Add security key" / "Register".
2. Enter the PIN if asked.
3. While the key waits for you, the LED is **almost solid** (on for 1 s, off for 0.1 s). **Press BOOTSEL** (the
   white button) briefly.
4. The site confirms the registration.

## 4. Sign in
1. Choose "Sign in with security key" and enter the PIN if asked.
2. **Press BOOTSEL** when the LED is almost solid.

Every registration and every sign-in needs a **new** press. Holding the button before the request does not count:
release it, then press again.

LED: fast blink (200 ms on/off) = ready; very fast flicker = busy (or the browser asked the key to "wink");
almost solid = waiting for your button press.

## 5. Things to know
- **"Hardware failure" when entering the PIN:** with the SRAM PUF the key is re-read from RAM at power-up. If the pattern
  could not be recovered (for example after a very short unplug), unplug the key for about 10 seconds and plug it in
  again. This is not counted as a wrong PIN.
- **PIN after every plug-in:** the key is locked on USB reset, suspend and unplug. Enter the PIN once (any site that asks
  for it) before U2F or no-PIN-prompt logins work; until then they fail. The Argon2 cost is tuned for a target of roughly 0.5 to 1 s per PIN check (`src/wrap.rs`), but the real time
  has not been systematically measured.
- **First install:** erase the whole flash first (the layout changed), then flash the UF2.
- **Wrong PINs:** the usual CTAP rules apply: after 3 wrong PINs in a row, unplug and replug; after 8 wrong PINs
  without a correct one in between, the PIN is blocked. A correct PIN resets the counts. The retry counter is kept
  in the vault and is written before each guess is checked, so cutting power does not give free guesses.
- **Forgotten or blocked PIN:** the only way out is a reset, which **deletes all credentials**. Unplug, replug and run
  the reset (`fido2-token -R <device>` or the browser's "Reset" option) **immediately**: CTAP only accepts a reset
  shortly after power-up. Press the button when asked.
- **Passkeys / U2F:** OpenSK supports discoverable credentials and U2F. Neither has been systematically tested on
  this device. U2F-only sites need an attestation key that this firmware does not ship (see `README.md`).
- **Backup:** credentials depend on the keys stored inside this device (the store, the SRAM-PUF helper sector and the 12 KiB vault at the end of flash, plus the chip's own SRAM pattern), so a
  second key cannot be a clone. Register **two** devices on every account. Flashing firmware that changes the flash
  layout, or erasing the flash, loses every credential.
- **If a site does not recognise the key:** the USB IDs are prototype placeholders; test on webauthn.io first.
