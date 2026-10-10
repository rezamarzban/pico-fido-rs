# Using the flashed key

**Before you start:** this firmware has not been tested on hardware. Try it first on a throwaway account such as https://webauthn.io, not on anything important.

## 1. Check that the device is detected

- Plug in the Pico. It should show up as a FIDO HID device (VID `c0de`, PID `cafe`, product "Pico Fido").
- **Linux:** you may need a udev rule so you can access it without root:

  ```
  # /etc/udev/rules.d/70-pico-fido.rules
  KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="c0de", ATTRS{idProduct}=="cafe", TAG+="uaccess"
  ```

  Then run `sudo udevadm control --reload && sudo udevadm trigger`.
- **Quick check:** `fido2-token -L` (libfido2) should list the device. `fido2-token -I <device>` should show `FIDO_2_0` and `clientPin`.

## 2. Set a PIN (recommended)

- Without a PIN, anyone who can read the flash can get your keys.
- Set it with `fido2-token -S <device>`, or with `ykman fido access change-pin`, or in the browser's security-key settings:
  - **Chrome / Edge:** Settings → Privacy and security → Security → Manage security keys.
  - **Windows:** Settings → Accounts → Sign-in options → Security key.
- The PIN must be at least **10 characters**. Use a long passphrase.
- You have to press the button to confirm. Write the PIN down somewhere safe, because there is no recovery.

## 3. Register

1. On a site (try https://webauthn.io), choose "Add security key" or "Register".
2. The browser asks for the PIN.
3. The Pico's LED shows a slow blink. **Press BOOTSEL** (the white button) briefly.
4. The site confirms the registration.

## 4. Authenticate

1. Choose "Sign in with security key".
2. Enter the PIN when asked. The key stays unlocked for 2 minutes.
3. **Press BOOTSEL** when the LED blinks.

Every registration and every login needs a new press. Holding the button before the request doesn't count. Release it first and press again.

## 5. Things to know

- **Wrong PINs:** after 3 wrong PINs in a row, unplug and replug. After 8 failures in total, the PIN is blocked.
- **Forgotten or blocked PIN:** the only way out is a reset, which **deletes all credentials**. Unplug, replug, and within 10 seconds run `fido2-token -R <device>` (or use the browser's "Reset" option), then press the button.
- **Limits:** there are no resident keys or passkeys that show up in an account picker. The site has to know which account you are signing in as. It works as a second factor, or as a passwordless key when you type your username first. Some sites may reject the all-zero AAGUID.
- **Backup:** credentials come from the master key inside this device, so a second key can't be a clone. Register **two** devices on every account.
- **If a site doesn't recognise the key:** it may be rejecting the prototype VID/PID. Test with webauthn.io first.
