# Security notes

Experimental firmware; read this before relying on it.

## What is protected, and by what
* **Credential and attestation private keys** are generated in the ATECC608A and never leave it.
  A copy of the Pico's flash contains no private key, only credential handles (slot number +
  fingerprint) inside OpenSK's encrypted credential IDs.
* **No signature limit**: signatures are not counted (the former Counter 0 budget was removed).
  The chip signs as often as it is asked. Consequence: anyone who can run code on the Pico or talk
  to the chip's I2C bus (see below) is no longer stopped by a budget; user presence (BOOTSEL) is
  the only gate for normal use.
* **Randomness** comes only from the chip's TRNG (a ChaCha20 DRBG seeded from it and re-seeded every
  1 KiB of output). If the chip stops answering the firmware halts; there is no weaker fallback.

## What is not protected
* **Everything on the Pico is OpenSK's standard, unprotected storage**: the PIN hash, the master
  keys that encrypt credential IDs, resident-credential data, counters. With physical access
  (BOOTSEL / SWD) an attacker can read all of it. Short PINs can then be guessed offline.
  The PIN is only an access check done by the Pico firmware.
* **The chip does not authenticate the Pico.** Code running on the Pico, or a probe on the I2C
  bus, can make the chip sign (without limit). User presence is the BOOTSEL button,
  checked by the Pico.
* Evicted credentials (more than 9 registrations) are gone for good.
* Attestation with the per-device key (`use_batch_attestation`, and always for U2F) lets sites
  recognise the device.

## Not reviewed
This branch was built and tested on all browsers and operating systems (see README, "Verification
status"), but the code has not been audited. The chip commands follow the datasheet and
cryptoauthlib; verify them with the acceptance test in `atecc608a/CONFIG.md` before locking a chip.
