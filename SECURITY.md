# Security notes and threat model

A small, software-only FIDO2/U2F key for the RP2040 on top of OpenSK. Read this before relying on it.

## What it protects against
* Phishing and credential theft over the network: credentials are bound to the website (RP ID) and signed. This assumes an uncompromised browser/OS and a relying party that checks the RP ID; it does not help against malware on the host.
* A lost device that is never opened: the USB interface does not export the private keys or the master key
  material. It answers ordinary CTAP requests, and which of them need a fresh BOOTSEL press is decided by
  OpenSK following the CTAP rules (see below). **Without a PIN, whoever holds the device can use it to sign in.**
* User presence is a **fresh press of BOOTSEL** (`src/env/user_presence.rs`): the button must be seen released
  after the check started and then pressed, so a button already held down when a request arrives does not count.
  Which operations ask for presence is decided by OpenSK following the CTAP rules.

## What it does NOT protect against
* **Anyone who can read the flash, when no PIN is set.** The seed is then stored in clear in the vault. The RP2040 has
  no secure storage, no flash encryption and no OTP key area, and the USB bootloader or SWD can read the whole
  flash. A secure element that signs internally would keep the key out of flash, but is not a complete fix: the ATECC608 used in the `atecc-*` branches, for example, has no user-presence check, so anyone with access to its bus can still request signatures.
* **Offline PIN guessing on a flash dump, when a PIN is set.** The seed is wrapped with Argon2id (64 KiB), but the
  RP2040 can only afford a small cost, so a short PIN falls quickly to a GPU/ASIC attacker. Use a long passphrase.
* **Short PINs.** The firmware requires at least 10 code points because of the point above; use a long
  passphrase.
* **Reading RAM** (debugger/SWD): the RP2040 has no debug lockout. The RAM guard (below) only raises the cost of
  partial or one-shot RAM reads; it does not stop an attacker who halts the CPU and reads everything, or one who
  reads the flash of a device with no PIN.
* **Weak randomness.** The RP2040 has a ring oscillator, not a certified TRNG. `src/keys.rs` consumes 512 raw bytes
  per 32 output bytes, mixes timer jitter and a running pool through SHA-256, and `src/health.rs` halts the firmware if
  repetition-count / adaptive-proportion tests fail. These detect gross failures only; they do not measure
  entropy, and hashing cannot create entropy that is not there. Not evaluated against NIST SP 800-90B.
* **Side channels / fault injection.** No countermeasures. P-256 runs in software on the thread executor.
* **Bugs in OpenSK or in this platform layer.** OpenSK is a large library used here in a configuration that
  upstream does not ship for the RP2040. Results from other boards do not carry over.

## Behaviour worth knowing
* **Store and vault.** The last 12 KiB of flash are the vault, the 80 KiB below it (`STORE_PAGES` = 20) the store. If the store area holds nothing the
  store understands, it is erased once at boot and started empty; a vault sector holding unrecognised data is not
  erased, and the device refuses to work until a CTAP reset. A reset or a damaged store therefore loses
  credentials; keep **two** devices registered per account.
* **Flash writes** run from RAM with interrupts masked: the USB interrupt can be delayed for the duration of a
  sector erase (tens of ms).
* **USB reset / suspend / disable / deconfigure** cancel the running CTAP operation (epoch check in the
  user-presence wait, packet waits and `send`), forget the seed when a PIN is set, drop queued packets and let
  OpenSK forget pending state (`Ctap::cancel_in_flight`). A signature that is already being computed finishes, but
  nothing is sent. One response packet that the USB task had already taken from the queue may still go out; it
  carries the old channel ID, which a new host session ignores.
* **Attestation.** `use_batch_attestation` is off: FIDO2 registrations use self attestation. U2F registration needs
  an attestation key provisioned with OpenSK's tools; none is shipped.
* **USB serial number** (flash unique ID) is only present when built with `usb_serial`; it lets hosts correlate the
  device across connections.
* **Unpinned dependencies.** Without a committed `Cargo.lock` and a pinned OpenSK commit (`third_party/OPENSK_REV`)
  builds are not reproducible.
* **Verification.** The maintainer reports that this branch was built, flashed to a Pico and tested, and works on Linux, Windows and Android;
  the hardening has no detailed test record. Hardware behaviour for flash
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
* The master is forgotten on USB reset / suspend / unplug (at once, from the USB handler) and on power-off. While
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

## RAM guard (`src/ram_guard.rs`, `src/guard.rs`)
**What it is.** The master seed exists in RAM as 8 XOR shares in scattered, non-adjacent slots of a decoy-filled
pool, re-randomised every millisecond and around each key use, with masks from a ChaCha20 DRBG (seeded at boot, reseeded
about once a second). Plaintext temporaries are `Zeroizing`.

**What it buys.** A RAM read that is not a consistent snapshot of all shares (cold boot decay, a slow or partial
dump, a stale copy in a crash dump) does not yield the seed, and shares captured at different moments cannot be
combined.

**What it does not buy.**
* The seed is reconstructed in a stack buffer during every key use, and the 128-byte OpenSK master derived from it
  exists in clear for the length of that call. An attacker who halts the CPU at that moment, or who controls code on
  the device, wins. So does anyone with SWD access, because refreshing changes nothing about a full snapshot.
* The software crypto (P-256, HMAC, SHA-256 inside the `hmac`/`sha2`/OpenSK crates) keeps its own internal state
  and key blocks in RAM; those are outside this module's control.
* The per-credential keys in OpenSK's own structures are not masked; only the seed is.
* The DRBG state is plain RAM (`rand_chacha` does not zeroize). It only protects the masks, not the seed.
* Entropy: the flash unique ID is not secret, and the ROSC/ADC inputs are as weak as described above. Hashing them
  does not add entropy.
* The refresh costs CPU time (about 10 % at 1 ms; measure it) and briefly masks interrupts.
* `secrecy` is not used: it only adds `Debug` redaction and `ExposeSecret` ergonomics, and none of these types
  derive `Debug` at all.

## Vault updates
`set_pin` and factory reset fail, and never report success, if (a) the retry counter cannot be cleared, or (b) the
previous record (plain seed, or one wrapped under the old PIN) could not be verified wiped (erase retried, then
zero-programmed, then read back; the area must read uniformly 0xFF or 0x00). If the flash state after a failed
update cannot be determined, the device refuses to use any key until a CTAP reset. After a failed wipe in `set_pin`
the new record is already the one loaded at boot: set the PIN again in the same session (it retries the erase),
otherwise a CTAP reset is needed. A failed reset keeps its marker and is repeated at the next boot.
