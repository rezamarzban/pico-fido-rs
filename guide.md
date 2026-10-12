# Using the flashed key

**Before you start:** try the key first on a throwaway account such as https://webauthn.io, not on anything important.
It was built from OpenSK and reported working by its maintainer; it is still experimental (see `SECURITY.md`).

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
- Without a PIN, anyone who touches the key can use it. **The PIN does not protect the key material inside the
  device**: OpenSK stores it unencrypted in flash, so a determined attacker with physical access can read it.
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
- **Wrong PINs:** the usual CTAP rules apply: after 3 wrong PINs in a row, unplug and replug; after 8 wrong PINs
  without a correct one in between, the PIN is blocked. A correct PIN resets the counts.
- **Forgotten or blocked PIN:** the only way out is a reset, which **deletes all credentials**. Unplug, replug and run
  the reset (`fido2-token -R <device>` or the browser's "Reset" option) **immediately**: CTAP only accepts a reset
  shortly after power-up. Press the button when asked.
- **Passkeys / U2F:** OpenSK supports discoverable credentials and U2F. Neither has been systematically tested on
  this device. U2F-only sites need an attestation key that this firmware does not ship (see `README.md`).
- **Backup:** credentials depend on the keys stored inside this device (the 80 KiB store at the end of flash), so a
  second key cannot be a clone. Register **two** devices on every account. Flashing firmware that changes the flash
  layout, or erasing the flash, loses every credential.
- **If a site does not recognise the key:** the USB IDs are prototype placeholders; test on webauthn.io first.
