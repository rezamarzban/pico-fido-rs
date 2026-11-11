# Using the flashed key

**Before you start:** try the key first on a throwaway account such as https://webauthn.io, not on anything important.
The whole key is experimental (see `SECURITY.md`).

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
- Without a PIN, anyone who touches the key can use it. The PIN is checked by the Pico firmware; it is stored as a
  hash in the Pico's flash, so it does not protect against someone who can read that flash (see `SECURITY.md`).
- Set the PIN with `fido2-token -S <device>`, `ykman fido access change-pin`, or the browser's security-key settings:
  - **Chrome / Edge:** Settings -> Privacy and security -> Security -> Manage security keys.
  - **Windows:** Settings -> Accounts -> Sign-in options -> Security key.
- The minimum length is OpenSK's default (4). If the key asks for a touch while you set it, press BOOTSEL.
  Write the PIN down: there is no recovery.

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
- **Nine sites at most.** Each *site* uses one key slot (1-9) in the secure element. A new site first takes a slot that
  already holds a key and belongs to no other site; if there is none it takes an empty slot and a new key is generated
  in it. Keys owned by a site are never overwritten. Further accounts at a site that already has a key reuse that key
  and use no new slot (the site can tell that those accounts come from the same key). Registering at a 10th site is
  refused (the key restarts; unplug and replug). The list of which site owns which slot is kept in the Pico's flash (not
  in the chip); a FIDO reset does not clear it, erasing the whole flash does (the keys stay in the chip and are handed
  out again to new sites). The OLED's chip page shows `KEYS n/9 PRESENT` (slots that really hold a key, asked from the chip) and `SITES n/9 ASSIGNED` (slots that belong to a site, from the flash directory) separately, then `SIGNS` (total signatures).
- **Unlimited signatures.** Signatures are not counted, there is no budget. (If your chip was provisioned with the old
  500-signature Counter 0, that counter is simply ignored now.)
- **OLED.** Two pages, switching every 5 s: the device (state, USB, uptime, RAM, flash) and the ATECC608A (I2C
  address, serial number, revision, config/data lock state, key slots in use).
- **Wrong PINs:** the usual CTAP rules apply: after 3 wrong PINs in a row, unplug and replug; after 8 wrong PINs
  without a correct one in between, the PIN is blocked. A correct PIN resets the counts.
- **Forgotten or blocked PIN:** the only way out is a reset, which **deletes all credentials** from the key store (the
  chip keys stay in their slots and the site list is kept, so the same sites get the same keys again). Unplug, replug and run
  the reset (`fido2-token -R <device>` or the browser's "Reset" option) **immediately**: CTAP only accepts a reset
  shortly after power-up. Press the button when asked.
- **Passkeys / U2F:** OpenSK supports discoverable credentials and U2F. U2F-only sites need the attestation key and
  certificate: provision them once (`atecc608a/CONFIG.md`).
- **Backup:** credentials depend on the keys stored inside this device (the flash store and the chip), so a
  second key cannot be a clone. Register **two** devices on every account. Flashing firmware that changes the flash
  layout, or erasing the flash, loses every credential.
- **If a site does not recognise the key:** the USB IDs are prototype placeholders; test on webauthn.io first.
