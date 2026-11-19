# Security notes

Experimental firmware; read this before relying on it.

## What is protected, and by what
* **Credential and attestation private keys** are generated in the ATECC608A and never leave it.
  A copy of the Pico's flash contains no private key, only credential handles (slot number +
  fingerprint) inside OpenSK's encrypted credential IDs.
* **No signature limit**: the former chip Counter 0 budget was removed. The Pico's signature tally is telemetry only.
  The chip signs as often as it is asked. If the chip refuses to sign, the host gets a CTAP error instead of a
  dummy signature that would only fail later at the relying party. Consequence: anyone who can run code on the Pico or talk
  to the chip's I2C bus (see below) is no longer stopped by a budget; user presence (BOOTSEL) is
  the only gate for normal use.
* **Randomness** comes only from the chip's TRNG (a ChaCha20 DRBG seeded from it and re-seeded every
  1 KiB of output). If the chip stops answering the firmware halts; there is no weaker fallback.

## What is not protected
* **Flash is encrypted, RAM is not.** The PIN hash, the master keys that encrypt credential IDs, resident-credential
  data, counters, the site directory and the signature counts are AES-256-GCM ciphertext in flash (README, "Flash layout
  and encryption"); the key is rebuilt from the SRAM power-up pattern and never stored. A copy of the flash (dump,
  backup, chip read in a programmer) therefore does not allow offline PIN guessing, **unless the attacker also holds a chip that has a record in the PUF-secret
  backup (next bullets)**. Anyone who can **run code** on the
  Pico (BOOTSEL / SWD) can read the same RAM and derive the key: this is protection against flash theft, not against
  a device that is attacked live.
* **The PUF-secret backup ties the flash encryption to the chip.** The secret that every flash key is derived from is also
  stored in the backup sector, sealed with SHA-256 of an HMAC digest that only a chip with the right key in its data
  slot 11 can compute (HMAC-SHA-256 of a fixed challenge; the key is random, from the chip's own RNG; it cannot be read back out of the chip, but while a new key is being written it is
  briefly in the RP2040's RAM, like the PUF secret itself, and is zeroized afterwards). The secret is the same for every chip, so ANY chip with a record opens the backup. Therefore: a copy of the
  Pico's flash alone, or public data (attestation certificate, public keys) does not open it; anyone who holds a chip
  with a record does, because the chip answers HMAC to whoever talks to it (no authentication). With the chip in the
  attacker's hands the same attacker could in any case use its signing keys. The backup was added on purpose, for
  availability: with it a noisy SRAM sample, a damaged or erased helper sector or a failing PUF no longer locks the key
  out. Without the backup an attacker who holds the chip still has to read the SRAM of the device.
* **Where the HMAC key comes from.** The firmware can initialise a blank slot 11 when the chip allows a clear write.
  It can also rotate a populated slot for a new backup record. It writes and verifies the replacement record before
  committing the new key; if the chip refuses the clear write, it keeps the current key. With fewer than two free records
  it skips rotation. A blank slot that cannot be provisioned provides no backup. Replacing the key makes records
  under the old key unreadable.
* **Backup capacity is 55 records, not necessarily 55 chips.** Old or failed-rotation records can still occupy space.
  The backup record identifies the sealing key by a digest-derived ID rather than storing the chip serial there.
  The firmware refuses to erase an unknown or damaged backup sector.
* **The device in hand beats the flash encryption.** BOOTSEL plus `picotool` can very likely read RAM (including the
  PUF region) without any code of ours, and the chip does not check who talks to it (see below), so a stolen device
  can be made to sign without the PIN by anyone who can reflash it. What it does stop: cloning the keys (they never
  leave the chip) and reading a copy of the flash alone.
* **PUF caveats.** 256 bits is an upper bound. The helper data of a repetition code gives away the majority of every
  column, so a biased SRAM weakens the secret: under a model of independent cells with a known bias of the pair stream
  (`host-test/puf_sim.py`) it keeps ~256 bits at 50 % ones, 244 at 52 %, 212 at 54 %, 167 at 56 %, 77 at 60 %. Pairs of
  cells are XORed first (70 % ones raw is 42 % after the XOR) and enrolment is refused outside 46..54 % pair ones, but
  the model ignores cells whose bias is the same on every chip of this model (an attacker with several boards could
  use that): **measure real boards** (`puf: ... ones: raw .. pairs ..` is logged at every boot). The error rate is
  logged too; above ~10 % raw the key may fail to rebuild (then the LED blinks 3x and the key stays locked until a
  re-plug). Temperature/voltage extremes and ageing change
  the pattern. If the helper sector is lost or the SRAM of the chip changes for good, **all sealed data is
  unrecoverable unless a usable slot-11 backup exists**. The credential keys stay in the chip, but without the
  flash data they do not restore the credentials.
* **Not hidden:** store key ids, value lengths and write timing; there is **no rollback protection** (an old copy of the
  flash can be restored with its old, valid ciphertext, e.g. the PIN retry counter).
* The PUF RAM is at the top of the striped SRAM, so flip-link's stack guard (the bottom of RAM) still works: a stack
  overflow runs into unmapped memory and faults. The two 4 KiB scratch banks above it are unused.
* **The chip does not authenticate the Pico.** Code running on the Pico, or a probe on the I2C
  bus, can make the chip sign (without limit). User presence is the BOOTSEL button,
  checked by the Pico.
* **Only 9 sites.** A key that belongs to a site is never overwritten or regenerated; a registration at a
  10th site is refused (a CTAP error). Accounts at a site that already has a key reuse it. The firmware
  tells a free slot from a used one by asking the chip for the public key (status 0x0F = no private key there); a bus
  error is never taken for "free". An unowned slot that already holds a key gets a new key before being assigned.
* **Accounts at the same site share one public key**, so that site can link them (different sites never share
  one). The site list (which site owns which key slot: the first 16 bytes, 128 bits, of the SHA-256 of the site name,
  per slot) is sealed in two flash sectors of the Pico, not stored in the chip. If two site
  names had the same 16-byte hash prefix they would be given the same key slot: that means the same private key and
  the same public key for both (the chip does not bind a slot to a site), so those two sites could link the user and a
  compromise of that key would affect both. Finding a site name that matches one given site costs about 2^128 hash
  evaluations; the earlier 7-byte (56-bit) tag was not out of reach and was replaced.
* **Chip serial numbers are sealed in the Pico's flash** with the site list and signature tallies. The serial number
  read from the chip is not authenticated: reporting the same serial selects that chip's metadata, but does not
  reproduce its keys.
* **The site list is updated copy-on-write.** Adding a site appends one checked record; compacting the log writes
  the whole new list into the other sector and commits it with a generation-numbered header written last, so a power
  failure leaves the complete old or the complete new list in the host flash model. This models interruptions
  during program and erase steps; it is not a hardware power-loss qualification.
* **If the site list is lost** (the whole flash is erased from outside, or both sectors are destroyed), the slots still hold
  keys but belong to nobody: new sites get those slots in slot order and GenKey replaces the old key each time, so
  no two sites ever share a public key by this route. The price: credentials that were registered in such a slot
  stop working (their key is gone for good). Treat a lost site list as the loss of those credentials.
* **The signature count can lag by the signatures in flight.** It is copy-on-write between two flash regions like the
  site directory, so a power cut during a compaction leaves the old or the new counts, never blank or older ones; the
  signature that was being counted at that moment may be missing. If a flash write fails the display shows the last
  value that flash is known to hold and the next successful write catches up. It is only shown on the display and
  nothing depends on it. After updating from a firmware with the single-page counter the counts start from 0 once
  (the old page is in another format and is ignored).
* **Chips used with v3** may still hold an old site directory in slot 13. The firmware does not read, write or
  migrate it. An unowned slot selected by the current firmware is regenerated before it is assigned to a site.
* Attestation with the per-device key (`use_batch_attestation`, and always for U2F) lets sites
  recognise the device.

## Not reviewed
The maintainer reports testing every `atecc1` firmware revision on all browsers and operating systems.
The compatibility report is not an independent test or security audit. See [verification status](README.md#verification-status)
for the scope and run the [chip acceptance tests](atecc608a/CONFIG.md) before locking a chip.
