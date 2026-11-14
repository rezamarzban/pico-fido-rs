# Security notes

Experimental firmware; read this before relying on it.

## What is protected, and by what
* **Credential and attestation private keys** are generated in the ATECC608A and never leave it.
  A copy of the Pico's flash contains no private key, only credential handles (slot number +
  fingerprint) inside OpenSK's encrypted credential IDs.
* **No signature limit**: signatures are not counted (the former Counter 0 budget was removed).
  The chip signs as often as it is asked. If the chip refuses to sign, OpenSK gets an error and the host a failed command (since OpenSK
  #835 signing can fail) instead of a dummy signature that would only fail later at the relying party. Consequence: anyone who can run code on the Pico or talk
  to the chip's I2C bus (see below) is no longer stopped by a budget; user presence (BOOTSEL) is
  the only gate for normal use.
* **Randomness** comes only from the chip's TRNG (an HMAC-DRBG seeded from it and re-seeded every
  1 KiB of output). If the chip stops answering the firmware halts; there is no weaker fallback.

## What is not protected
* **Flash is encrypted, RAM is not.** The PIN hash, the master keys that encrypt credential IDs, resident-credential
  data, counters, the site directory and the signature counts are AES-256-GCM ciphertext in flash (README, "Flash layout
  and encryption"); the key is rebuilt from the SRAM power-up pattern and never stored. A copy of the flash (dump,
  backup, chip read in a programmer) therefore does not allow offline PIN guessing. Anyone who can **run code** on the
  Pico (BOOTSEL / SWD) can read the same RAM and derive the key: this is protection against flash theft, not against
  a device that is attacked live.
* **PUF caveats.** 256 bits is an upper bound; the real strength is the min-entropy of this chip's SRAM pattern (the
  public helper data leaks some of it). The error rate is logged at every boot; above ~10 % the key may fail to rebuild
  (then the LED blinks 3x and the key stays locked until a re-plug). Temperature/voltage extremes and ageing change
  the pattern. If the helper sector is lost or the SRAM of the chip changes for good, **all sealed data is
  unrecoverable** (the chip's keys stay, credentials do not): there is no backup of the key by design.
* **Not hidden:** store key ids, value lengths and write timing; there is **no rollback protection** (an old copy of the
  flash can be restored with its old, valid ciphertext). Large-blob shards are split over two store entries (one transaction); other values over 994 bytes are refused.
* A stack overflow of less than 1 KiB runs into the reserved PUF RAM (flip-link's guard is the end of RAM): the key can
  then no longer be rebuilt and the firmware halts, by design.
* **The chip does not authenticate the Pico.** Code running on the Pico, or a probe on the I2C
  bus, can make the chip sign (without limit). User presence is the BOOTSEL button,
  checked by the Pico.
* **Only 9 sites.** A key that belongs to a site is never overwritten or regenerated; a registration at a
  10th site is refused (OpenSK answers the host with a CTAP error). Accounts at a site that already has a key reuse it. The firmware
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
