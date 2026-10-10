# Using the flashed key

**Before you start:** this firmware was tested by its maintainer on a Pico with Linux browsers only (not Windows or Android). Try it first on a throwaway account such as https://webauthn.io, not on anything important.

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

- Without a PIN, anyone who can read the flash can get your keys. A PIN raises the cost of that attack but does not
  remove it: the flash can still be attacked offline, so use a long passphrase (see `SECURITY.md`).
- Set it with `fido2-token -S <device>`, or with `ykman fido access change-pin`, or in the browser's security-key settings:
  - **Chrome / Edge:** Settings → Privacy and security → Security → Manage security keys.
  - **Windows:** Settings → Accounts → Sign-in options → Security key.
- The PIN must be at least **10 characters** (counted as Unicode code points). Use a long passphrase.
- You have to press the button to confirm. Write the PIN down somewhere safe, because there is no recovery.

## 3. Register

1. On a site (try https://webauthn.io), choose "Add security key" or "Register".
2. The browser asks for the PIN.
3. While the key waits for you, the LED is **almost solid** (on for 1 s, off for 0.1 s). **Press BOOTSEL** (the
   white button) briefly.
4. The site confirms the registration.

## 4. Authenticate

1. Choose "Sign in with security key".
2. Enter the PIN when asked. The key stays unlocked for up to 2 minutes (a USB reset or suspend locks it earlier).
3. **Press BOOTSEL** when the LED is almost solid.

Every registration and every login needs a new press. Holding the button before the request doesn't count. Release it first and press again.

LED: fast blink (200 ms on/off) = ready; very fast flicker (50 ms) = busy; almost solid = waiting for your button press.

## 5. Things to know

- **Wrong PINs:** after 3 wrong PINs in a row since power-up, unplug and replug. After 8 wrong PINs without a correct
  one in between, the PIN is blocked; a correct PIN resets both counts (see `SECURITY.md`, "Retry counter").
- **Forgotten or blocked PIN:** the only way out is a reset, which **deletes all credentials**. Unplug, replug, and within 10 seconds run `fido2-token -R <device>` (or use the browser's "Reset" option), then press the button.
- **Limits:** there are no resident keys or passkeys that show up in an account picker. The site has to know which account you are signing in as. It works as a second factor, or as a passwordless key when you type your username first. Some sites may reject the all-zero AAGUID.
- **Backup:** credentials come from the master key inside this device, so a second key can't be a clone. Register **two** devices on every account.
- **If a site doesn't recognise the key:** it may be rejecting the prototype VID/PID. Test with webauthn.io first.
