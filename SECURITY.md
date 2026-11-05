# Security notes

Experimental firmware; read this before relying on it.

## What is protected, and by what
* **Credential and attestation private keys** are generated in the ATECC608A and never leave it.
  A copy of the Pico's flash contains no private key, only credential handles (slot number +
  fingerprint) inside OpenSK's encrypted credential IDs.
* **Signature budget**: the chip's LimitedUse counter stops signing after the configured number of
  signatures. It cannot be reset once the chip's configuration is locked.
* **Randomness** comes only from the chip's TRNG (a ChaCha20 DRBG seeded from it and re-seeded every
  1 KiB of output). If the chip stops answering the firmware halts; there is no weaker fallback.

## What is not protected
* **Everything on the Pico is OpenSK's standard, unprotected storage**: the PIN hash, the master
  keys that encrypt credential IDs, resident-credential data, counters. With physical access
  (BOOTSEL / SWD) an attacker can read all of it. Short PINs can then be guessed offline.
  The PIN is only an access check done by the Pico firmware.
* **The chip does not authenticate the Pico.** Code running on the Pico, or a probe on the I2C
  bus, can make the chip sign (until the budget is spent). User presence is the BOOTSEL button,
  checked by the Pico.
* Evicted credentials (more than 7 registrations) are gone for good.
* Attestation with the per-device key (`use_batch_attestation`, and always for U2F) lets sites
  recognise the device.

## Not reviewed / not tested
The Rust firmware of this revision has not been built or run by its author on hardware after the
slimming (see README, "Verification status"). The chip commands follow the datasheet and
cryptoauthlib; verify them with the acceptance test in `atecc608a/CONFIG.md` before locking a chip.
