# Security notes and threat model

This is a small, software-only FIDO2 key for the RP2040. Read this before relying on it.

## What it protects against
* Phishing and credential theft over the network: credentials are bound to the website (RP ID) and signed with ES256.
* A stolen/lost device that is never opened: nothing is exposed over USB except signatures.
* Each action (register / sign / reset) needs a **fresh** press of the BOOTSEL button; a button that is already
  held down when a request arrives is ignored until it has been released and pressed again. This is enforced by
  the authenticator itself: a getAssertion with `options.up = false` still requires (and reports) a touch.

## What it does NOT protect against
* **Anyone who can read the flash, when no PIN is set.** Without a PIN the 32-byte master key is stored in plain
  flash (see `src/store.rs`). The RP2040 has no secure storage, no flash encryption and no OTP key area, and the
  USB bootloader or SWD can read the whole flash. With the master key and a credential ID, the private key
  can be re-derived. **Set a PIN** (see below) to raise the cost of this attack; it does not remove it.
  A secure element (e.g. ATECC608, OPTIGA) that signs internally is the only real fix.
* **Anyone who can read the flash, when a PIN is set: offline PIN guessing.** The wrapped key can be attacked at
  Argon2id speed on a fast PC; the retry counter only limits attempts made through the USB interface. With
  `m = 96 KiB` (RAM-limited, see `src/wrap.rs`) the memory hardness is low, so security rests on the
  **PIN entropy**: use a long passphrase (the firmware enforces at least 10 characters; 5 random words or more is
  much better). The Argon2 parameters were not measured on hardware.
* **Anyone who can read RAM while a PIN session is open** (debugger / SWD): the unwrapped key is in RAM for up to
  2 minutes after a successful PIN entry. The RP2040 has no debug lockout.
* **Cutting power at exactly the right moment** can defeat the retry counter only for an attacker who controls
  the device's power with millisecond precision; such an attacker can read the flash anyway (see above).
* **Weak randomness.** The RP2040 has a ring oscillator, not a certified TRNG. `keys.rs` consumes 512 raw bytes
  per 32 output bytes, mixes timer jitter and a running pool through SHA-256, and halts if continuous health tests
  (`src/health.rs`: SP 800-90B-style repetition-count and adaptive-proportion tests, plus a check for identical
  consecutive samples) fail. These detect gross failures such as a frozen or heavily biased source only; they do
  not measure entropy. Hashing cannot create entropy that is not there; the key is only as unpredictable as the
  ROSC. Not evaluated against NIST SP 800-90B. Do not use for high-value accounts without reviewing this.
* **Side channels / fault injection.** No countermeasures.

## Behaviour worth knowing
* Credentials are stateless (no resident keys, sign counter always 0, attestation "none").
* **PIN (optional, CTAP2 ClientPIN, protocols 1 and 2).** Setting a PIN replaces the plain key in flash with a
  *wrapped* record: the master key encrypted-then-MACed under keys from Argon2id(PIN hash, random salt)
  (`src/wrap.rs`). The plain key is not in flash and is only in RAM while a PIN session is valid:
  `getPinToken` unwraps it and returns a token valid for 2 minutes; the key is wiped when the token expires
  (checked once a second while idle and at every request), on USB reset, suspend or disable, and on `lock`.
  Credentials created before the PIN stay valid (the master key itself does not change).
  Every `makeCredential`/`getAssertion` then needs a valid `pinUvAuthParam` **and** the button; the UV flag is set.
  `setPIN`/`changePIN` also need the button, so an attacker with USB access cannot silently set a PIN.
* **Retry counter.** An attempt is written to flash *before* the guess is evaluated and marked correct only
  afterwards, so cutting power does not give free guesses. 8 failures block the PIN (`PIN_BLOCKED`); 3 in a row
  since power-up require a power cycle (`PIN_AUTH_BLOCKED`). A blocked or forgotten PIN is recovered only by a
  CTAP reset (touch, within 10 s of plug-in), which destroys all credentials. A correct PIN needs no flash erase.
* If the wrapped record is damaged there is no way to recover the key (by design); reset is the way out.
* Minimum PIN length is 10 Unicode code points (`MIN_PIN_LEN`), enforced by the authenticator
  (`PIN_POLICY_VIOLATION`).
* The firmware needs a 160 KiB heap for Argon2 and reserves the last **12 KiB** of flash (retry counter + two
  key slots). Records written by older firmware (56-byte plain key) are still read.
* If the key record is damaged or flash cannot be read, the device **refuses to operate** (CTAP error
  `OTHER`) instead of silently generating a new key. A CTAP reset (touch, within 10 s of plugging in) starts over.
  Reset destroys every credential.
* Key updates are crash-safe: two slots, SHA-256 integrity hash, write-then-verify, then wipe the old slot.
  Every update re-reads **both** slots and writes `newest seq + 1` into the other one, so a surviving old record can
  never outrank the new key, even if its sector cannot be erased. If an update fails, the flash is re-read and the
  running firmware uses exactly the key the next boot will load (or none if that cannot be determined), so a
  failed reset cannot "succeed after reboot" with a different key. If the old slot cannot be wiped the new key still
  wins, but old key material may remain readable (logged as a warning).
* `reset` is only accepted if the request arrived within 10 s of power-up (judged on arrival, not on the touch).
* CTAP2 requests must be canonical CBOR (minimal integers, map keys int/text in canonical order); floats in
  unknown fields are accepted and ignored.
* The USB serial number (flash unique ID) lets hosts recognise the device across connections; build without the
  `usb_serial` feature to omit it. It is also omitted if the ID cannot be read.
* P-256 runs without yielding (a CANCEL or keepalive cannot be handled while it runs). The firmware logs `crypto took N ms` (defmt/RTT) for each operation so you can
  measure it on your board; USB servicing pauses for that long.
