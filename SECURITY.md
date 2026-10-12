# Security notes and threat model

A small, software-only FIDO2/U2F key for the RP2040 on top of OpenSK. Read this before relying on it.

## What it protects against
* Phishing and credential theft over the network: credentials are bound to the website (RP ID) and signed.
* A lost device that is never opened: nothing is exposed over USB except signatures.
* User presence is a **fresh press of BOOTSEL** (`src/env/user_presence.rs`): the button must be seen released
  after the check started and then pressed, so a button already held down when a request arrives does not count.
  Which operations ask for presence is decided by OpenSK following the CTAP rules.

## What it does NOT protect against
* **Anyone who can read the flash.** OpenSK keeps its key material and the PIN hash in the key-value store *in
  clear* (`src/env/persist.rs`; OpenSK's generic key store does not encrypt them). The RP2040 has no secure
  storage, no flash encryption and no OTP key area, and the USB bootloader or SWD can read the whole flash.
  With the stored keys, credentials can be recreated; with the PIN hash, the PIN can be guessed offline at PC speed.
  This is **weaker than the earlier custom firmware**, which wrapped the master key with an Argon2id key derived from
  the PIN. A secure element that signs internally is the only real fix.
* **Short PINs.** The firmware requires at least 10 code points because of the point above; use a long
  passphrase.
* **Reading RAM** (debugger/SWD): the RP2040 has no debug lockout.
* **Weak randomness.** The RP2040 has a ring oscillator, not a certified TRNG. `src/keys.rs` consumes 512 raw bytes
  per 32 output bytes, mixes timer jitter and a running pool through SHA-256, and `src/health.rs` halts the firmware if
  repetition-count / adaptive-proportion tests fail. These detect gross failures only; they do not measure
  entropy, and hashing cannot create entropy that is not there. Not evaluated against NIST SP 800-90B.
* **Side channels / fault injection.** No countermeasures. P-256 runs in software on the thread executor.
* **Bugs in OpenSK or in this platform layer.** OpenSK is a large library used here in a configuration that
  upstream does not ship for the RP2040. Results from other boards do not carry over.

## Behaviour worth knowing
* **Store.** The last 80 KiB of flash (`STORE_PAGES` = 20) are the store. If that area holds nothing the
  store understands, it is erased once at boot and started empty. A reset or a damaged store therefore loses
  credentials; keep **two** devices registered per account.
* **Flash writes** run from RAM with interrupts masked: the USB interrupt can be delayed for the duration of a
  sector erase (tens of ms).
* **USB reset / suspend** drops the packets queued between USB and OpenSK (`src/env/hid.rs`). Session handling
  beyond that (PIN token lifetime, cancelling a pending request) is OpenSK's.
* **Attestation.** `use_batch_attestation` is off: FIDO2 registrations use self attestation. U2F registration needs
  an attestation key provisioned with OpenSK's tools; none is shipped.
* **USB serial number** (flash unique ID) is only present when built with `usb_serial`; it lets hosts correlate the
  device across connections.
* **Unpinned dependencies.** Without a committed `Cargo.lock` and a pinned OpenSK commit (`third_party/OPENSK_REV`)
  builds are not reproducible.
* **Verification.** The maintainer reports it works on Linux, Windows and Android. Hardware behaviour for flash
  failures, power loss and timing was not systematically tested. See `README.md`, "Verification status".
