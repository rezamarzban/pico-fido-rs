# Security notes and threat model

This is a small, software-only FIDO2 key for the RP2040. Read this before relying on it.

## What it protects against
* Phishing and credential theft over the network: credentials are bound to the website (RP ID) and signed with ES256.
* A stolen/lost device that is never opened: nothing is exposed over USB except signatures.
* Each action (register / sign / reset) needs a **fresh** press of the BOOTSEL button; a button that is already
  held down when a request arrives is ignored until it has been released and pressed again.

## What it does NOT protect against
* **Anyone who can read the flash.** The 32-byte master key is stored in plain flash (two sectors at the end,
  see `src/store.rs`). The RP2040 has no secure storage, no flash encryption and no OTP key area, and the
  USB bootloader or SWD can read the whole flash. With the master key and a credential ID, the private key
  can be re-derived. Treat physical access as full compromise. A secure element (e.g. ATECC608, OPTIGA) that
  signs internally is the only real fix.
* **Weak randomness.** The RP2040 has a ring oscillator, not a certified TRNG. `keys.rs` consumes 512 raw bytes
  per 32 output bytes, mixes timer jitter and a running pool through SHA-256, and halts if the source is stuck
  at a constant value. Hashing cannot create entropy that is not there; the key is only as unpredictable as the
  ROSC. Not evaluated against NIST SP 800-90B. Do not use for high-value accounts without reviewing this.
* **Side channels / fault injection.** No countermeasures.

## Behaviour worth knowing
* Credentials are stateless (no resident keys, no PIN, sign counter always 0, attestation "none").
* If the key record is damaged or flash cannot be read, the device **refuses to operate** (CTAP error
  `OTHER`) instead of silently generating a new key. A CTAP reset (touch, within 10 s of plugging in) starts over.
  Reset destroys every credential.
* Key updates are crash-safe: two slots, SHA-256 integrity hash, write-then-verify, then wipe the old slot.
* `reset` is only accepted within 10 s of power-up.
* P-256 runs without yielding. The firmware logs `crypto took N ms` (defmt/RTT) for each operation so you can
  measure it on your board; USB servicing pauses for that long.
