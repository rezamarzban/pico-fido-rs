# Security notes and threat model

A small, software-only FIDO2/U2F key for the RP2040 on top of OpenSK. Read this before relying on it.

## What it protects against
* Phishing and credential theft over the network: credentials are bound to the website (RP ID) and signed.
* A lost device that is never opened: nothing is exposed over USB except signatures.
* User presence is a **fresh press of BOOTSEL** (`src/env/user_presence.rs`): the button must be seen released
  after the check started and then pressed, so a button already held down when a request arrives does not count.
  Which operations ask for presence is decided by OpenSK following the CTAP rules.

## What it does NOT protect against
* **Anyone who can read the flash, when no PIN is set.** The seed is then stored in clear in the vault. The RP2040 has
  no secure storage, no flash encryption and no OTP key area, and the USB bootloader or SWD can read the whole
  flash. A secure element that signs internally is the only real fix.
* **Offline PIN guessing on a flash dump, when a PIN is set.** The seed is wrapped with Argon2id (64 KiB), but the
  RP2040 can only afford a small cost, so a short PIN falls quickly to a GPU/ASIC attacker. Use a long passphrase.
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
* **Store and vault.** The last 12 KiB of flash are the vault, the 80 KiB below it (`STORE_PAGES` = 20) the store. If that area holds nothing the
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

## Hardened key storage (vault + HardenPersist)

* The master seed (32 bytes) lives in a dual-slot, power-cut-safe vault in the last 12 KiB of flash.
  With a PIN set it is wrapped with Argon2id (64 KiB, `T_COST` passes) + HMAC-SHA-256; the PIN
  check is the wrap tag, no PIN hash is stored (the OpenSK PIN record holds zeros and the length).
* From the seed, 128 bytes of OpenSK master keys are derived in RAM. Non-resident credentials
  (credential IDs) and cred-random depend on them; resident credentials are additionally encrypted
  and authenticated before they reach the key-value store. Metadata (counters, large blobs,
  settings) stays in clear.
* The PIN retry counter is the vault's (8 tries, written before each guess).
* **Without a PIN the seed is stored in clear**: the device is then only as secure as its flash.
* The master is forgotten on USB reset / suspend / unplug (next packet) and on power-off. While
  locked, credential-ID operations (including U2F and `uv=false` assertions) fail until the PIN is
  entered once.
* **Offline guessing:** an attacker with a flash dump can try PINs offline at the cost of Argon2
  with 64 KiB. The RP2040 cannot make that expensive; use a long passphrase (min. 10 code points
  by default).
* Not protected: RAM while a session is open, side channels, fault injection; the RNG is the ROSC
  (not a certified TRNG).
* Reflash with a full flash erase: the layout moved (vault at the end, store 12 KiB lower).
* An interrupted setPIN (power cut between the vault write and the PIN record) can leave a state that only a CTAP
  reset fixes. A damaged vault makes the device refuse to work until a reset.
