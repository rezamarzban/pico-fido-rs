# Security notes

Experimental firmware; read this before relying on it.

## What is protected, and by what
* **Credential and attestation private keys** are generated in the ATECC608A and never leave it.
  A copy of the Pico's flash contains no private key, only credential handles (slot number +
  fingerprint) inside OpenSK's encrypted credential IDs.
* **No signature limit**: signatures are not counted (the former Counter 0 budget was removed).
  The chip signs as often as it is asked. If the chip refuses to sign, the firmware stops (panic) instead of
  returning a dummy signature that would only fail later at the relying party. Consequence: anyone who can run code on the Pico or talk
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
* **Only 9 sites.** A key that belongs to a site is never overwritten or regenerated; a registration at a
  10th site is refused (firmware panic and restart). Accounts at a site that already has a key reuse it. The firmware
  tells a free slot from a used one by asking the chip for the public key (status 0x0F = no private key there); a bus
  error is never taken for "free". A slot that holds a key but belongs to no site is handed to the next new site as it
  is (no GenKey).
* **Accounts at the same site share one public key**, so that site can link them (different sites never share
  one). The site list (which site owns which key slot: the first 16 bytes, 128 bits, of the SHA-256 of the site name,
  per slot) is in two flash sectors of the Pico (below the OpenSK store and below the signature counter), **not in the
  chip** and not encrypted: anyone who can read the Pico's flash can test guesses of site names against it (the same
  flash also holds the PIN hash and the other OpenSK data, see above). The chip itself holds only keys. If two site
  names had the same 16-byte hash prefix they would be given the same key slot: that means the same private key and
  the same public key for both (the chip does not bind a slot to a site), so those two sites could link the user and a
  compromise of that key would affect both. Finding a site name that matches one given site costs about 2^128 hash
  evaluations; the earlier 7-byte (56-bit) tag was not out of reach and was replaced.
* **Chip serial numbers are stored in the Pico's flash** (site list and signature count of every chip this key has
  been used with, next to the other unprotected data). Anyone who can read the flash can see which chips were used and,
  with the site-name guessing described above, which sites each one has. The serial number is read from the chip
  without authentication: a clone that reports the same serial would simply get that chip's site list (it would have to
  hold the same keys to be of any use).
* **The site list is updated copy-on-write.** Adding a site appends one checked record; compacting the log writes
  the whole new list into the other sector and commits it with a generation-numbered header written last, so a power
  failure leaves the complete old or the complete new list, never an empty or truncated one (checked on a host
  model with the power cut after every step and in the middle of every program and erase; not on hardware).
* **If the site list is lost** (the whole flash is erased from outside, or both sectors are destroyed), the keys are
  still in the chip and are taken over again by new sites in slot order. Old credentials keep working (their
  credential ID names the slot), but a new registration may be given a key that an earlier site already uses: those
  two sites could then recognise the same public key. After erasing the flash, register at sites that matter in the
  same order as before, or treat the old credentials as shared.
* **The signature count is not power-fail safe** (its single page is erased and rewritten when its log is full); it
  is only shown on the display and nothing depends on it.
* **Chips used with the previous firmware** kept their site list in data slot 13 (the firmware no longer reads or
  writes it). It is not migrated: the first sites registered afterwards are matched to the existing keys in slot order,
  not to the sites that used them before. The old list stays in the chip until you overwrite that slot yourself.
* Attestation with the per-device key (`use_batch_attestation`, and always for U2F) lets sites
  recognise the device.

## Not reviewed
The `atecc1` code up to "OpenSK based ATECC support v2.1" was reported by the maintainer to have been built and
tested on browsers and operating systems; later changes (see README, "Verification status") were only run on a host
model, the firmware was not built for the Pico and nothing was run on a real chip. The code has not been audited. The chip commands follow the datasheet and
cryptoauthlib; verify them with the acceptance test in `atecc608a/CONFIG.md` before locking a chip.
