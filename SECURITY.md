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
* **Anyone who can read the flash, when no PIN is set.** Without the SRAM PUF the seed is then stored in clear in the vault; with it (the default in
  this branch) a flash-only copy is not enough, but anyone who can run code on the device can still recover it (see
  *SRAM PUF* below). The RP2040 has
  no secure storage, no flash encryption and no OTP key area, and the USB bootloader or SWD can read the whole
  flash. A secure element that signs internally would keep the key out of flash, but is not a complete fix: the ATECC608 used in the `atecc-*` branches, for example, has no user-presence check, so anyone with access to its bus can still request signatures.
* **Offline PIN guessing, when a PIN is set and the attacker has the PUF secret or the PUF is off.** With the default SRAM PUF
  working, a flash-only dump does not contain the PUF-derived value mixed into the Argon2 password, so guesses cannot be tested
  offline. If the PUF is disabled (`build.sh -P`) or its secret is obtained (code execution on the device: BOOTSEL, SWD), guessing
  is limited only by Argon2id (64 KiB), which the RP2040 can only afford at a small cost: a short PIN then falls quickly to a
  GPU/ASIC attacker. Use a long passphrase.
* **IR remote PIN** (feature `ir`): a key press is about log2(number of keys) bits (about 4.4 on a 21-key remote), because a
  NEC code is `address, ~address, command, ~command`: 8 keys are about 35 bits. The codes are fixed per key and IR can be
  watched or recorded, exactly like a typed PIN seen over the shoulder. An attacker cannot complete an entry without
  pressing BOOTSEL on the device (physical presence), cannot see the codes on the OLED (only `*`), and cannot guess faster
  than the retry counter (8) allows. The magic PIN `0000000000` can never be a normal PIN while the feature is on.
  Offline guessing needs the PUF secret as before. A cancelled entry counts as a failed attempt.
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
* **Store and vault.** The last 12 KiB of flash are the vault, the 8 KiB below it the two PUF helper sectors, the 72 KiB below that (`STORE_PAGES` = 18) the store. If the store area holds nothing the
  store understands, it is erased once at boot and started empty; a vault sector holding unrecognised data is not
  erased, and the device refuses to work until a CTAP reset. A reset or a damaged store therefore loses
  credentials; keep **two** devices registered per account.
* **Flash writes** run from RAM with interrupts masked: the USB interrupt can be delayed for the duration of a
  sector erase (tens of ms).
* **USB reset / suspend / disable / deconfigure** cancel the running CTAP operation (epoch check in the
  user-presence wait, packet waits and `send`), forget the seed when a PIN is set, drop queued packets and let
  OpenSK forget pending state (`Ctap::cancel_in_flight`). A signature that is already being computed finishes, but
  nothing is sent. One response packet that the USB task had already taken from the queue may still go out; it
  carries the old channel ID, which a new host session ignores. A request packet that was dequeued just before a reset is
  dropped (checked after the dequeue in the main loop, the packet waits and the user-presence wait), and each operation is stamped
  with the epoch of its packet. A response is checked and enqueued as one step with respect to the reset handler (critical
  section), so a reset cannot flush the queue in between. The USB task abandons its pending endpoint read on a reset (signal) and drops a packet whose read
  completed across an epoch change; the first packet of the new session is accepted because the read is restarted. After a reset, suspend or deconfigure the USB task also reads and discards
  whatever the endpoint still holds (until nothing arrives for 2 ms), so old-session data cannot be delivered to the new read. Residual: a
  genuine packet of the new session that arrives within that 2 ms is dropped (the host retries INIT). Needs a hardware test.
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
* **Without a PIN the seed is stored unwrapped** (in clear unless the SRAM PUF masks it, see below): without the PUF
  the device is then only as secure as its flash; with it, a flash-only copy is not enough.
* The master is forgotten on USB reset / suspend / unplug (at once, from the USB handler) and on power-off. While
  locked, credential-ID operations (including U2F and `uv=false` assertions) fail until the PIN is
  entered once.
* **Offline guessing:** without the SRAM PUF, an attacker with a flash dump can try PINs offline at the cost
  of Argon2 with 64 KiB; with it (see below) a flash-only dump is not enough, but code execution on the device is. The RP2040 cannot make that expensive; use a long passphrase (min. 10 code points
  by default).
* Not protected: RAM while a session is open, side channels, fault injection; the RNG is the ROSC
  (not a certified TRNG).
* **PIN retry counter, full sector:** the counter sector is erased by `finish_try`, i.e. right after a correct PIN, when every
  earlier failure has just been forgiven, and only when fewer than `TRIES_MAX` (8) pages are left. A power cut during that erase
  therefore cannot lose a pending failure, and `begin_try` can no longer meet a full sector with failures pending (its old
  erase-and-rewrite path remains only as a fallback if that erase failed). A torn erase can only count against the user.
* Reflash with a full flash erase: the layout moved (vault at the end, store 12 KiB lower).
* An interrupted setPIN is repaired at the next boot (see "setPIN power cut" below). A damaged vault makes the device refuse to
  work until a reset.

## SRAM PUF (`src/puf.rs`)

* **What it does:** the power-up state of 496 reserved RAM bytes (first 512 bytes of SRAM, outside the linker's RAM)
  is turned into a 256-bit key by a code-offset fuzzy extractor (128-bit secret, 31x repetition code, interleaved).
  The public helper data and an 8-byte check sit in one flash sector. The key is mixed into the Argon2 password of a
  PIN-wrapped seed and masks the seed of a no-PIN record, and is derived on demand (never stored in RAM).
* **What it buys:** a dump, backup or programmer read of the **flash only** is no longer enough to test PIN guesses
  offline or to recover the seed, and a seed cannot be moved to another RP2040.
* **What it does NOT buy:** anyone who can run code on the device can read the same RAM at power-up and combine it
  with the helper data: BOOTSEL (flash a dumping firmware, then boot it without losing the pattern) and SWD both give
  that on the RP2040, which has no debug lock-out. Against an attacker who holds the device it only adds a step.
* **Unknowns (measure them):** RP2040 SRAM start-up behaviour is not characterised by the vendor. Bias, bit error
  rate over temperature / supply ramp / ageing, and whether the boot ROM leaves the first 512 bytes alone are
  **unverified**. Every boot logs `puf: N bit errors of 3968`; the 31x code corrects up to 15 flips per bit-group, so
  a healthy chip should show well under 15 % (< 600). Enrolment uses a single sample and does not select stable
  cells; the entropy of the 128-bit secret is assumed, not measured. The repetition code leaks structure in the
  helper data; if the cells are strongly biased the effective secret is smaller than 128 bits.
* **Remanence / warm resets:** a quick unplug-replug can leave the old RAM content in place (not a fresh power-up
  pattern). Enrolment is only done on a power-on reset and checks that the sample is roughly balanced; recovery is
  attempted every boot and verified by the check. If it fails, the PIN dialog errors out without counting a wrong PIN:
  unplug for about 10 s. After a UF2 reflash the bootloader may have overwritten the reserved RAM; same remedy.
* **Fail closed:** with `sram_puf` the key is required. If it is unavailable the device locks and the LED blinks 3
  short blinks + pause. Nothing is created, bound, wrapped or reset in that state: a blank vault is initialised only
  with a PUF-bound seed, `set_pin` is refused, a CTAP reset is refused unless the PUF can be (re-)enrolled on a
  power-on reset, and an existing unbound record is used only after it has been bound (an unbound record plus an
  unavailable key locks the device instead of running unbound). In these states the retry counter is not touched (no attempt counted, none forgiven: a refund would call
  `finish_try`, which forgives earlier failures and would let anyone who can make the key unavailable reset the counter).
* **Missing helper data is not "new device":** a blank or damaged helper sector with an existing PUF-bound (or unreadable)
  vault record never triggers enrolment. A new PUF secret would orphan the seed (and, before the record tag existed, silently
  yield a wrong seed). The device stays locked with the LED fault pattern; a CTAP reset on a power-on reset re-enrols. The helper
  has two slots and the vault record names the slot it was bound to (record flag bit 2): a re-enrolment writes the other slot and the
  old one is erased only after the new record is durable (`Puf::commit`), so a power cut in a CTAP reset cannot leave a record
  without its helper. If the slot a record names holds no valid helper while the other does, the PUF is reported damaged
  (locked, fault pattern) rather than using a different secret.
* **Migration is not "protected" until the old record is gone:** binding an old unbound/untagged record (or a PIN record) to the PUF
  locks the device if the older record could not be wiped (and, with the PUF required, `vault::open` refuses a vault whose older
  record cannot be wiped). Software cannot erase flash that cannot be written: that case stays locked rather than claiming protection.
* **setPIN power cut:** the PIN metadata is written BEFORE the vault commit and `init` repairs the two inconsistent states: metadata
  without a PIN-wrapped vault (cut before the commit: the metadata is removed, the seed is intact, set the PIN again) and, for
  vaults written by older firmware, a PIN-wrapped vault without metadata (restored with the minimum PIN length). No CTAP reset is
  needed any more. A failed commit that leaves the old plain record removes the metadata again.
* **Watchdog (feature `watchdog`, off by default):** fed only by the main thread (polling waits and the main loop), so a hang or a
  stack-overflow HardFault ends in a reset after 8 s. Off because a single blocking step longer than that (Argon2, a signature, a
  store compaction) would reset the device mid-command: measure the longest step on hardware first.
* **set_pin with an unwipable older record:** the new record and the PIN metadata are both written, then an error is returned; the
  device then needs the older record wiped (next boot retries; with the PUF required the vault stays locked until then).
* **Stack overflow:** the firmware is linked with `flip-link`, so the stack is the lowest RAM region and an overflow runs off the
  bottom of RAM into a HardFault instead of corrupting the heap or the RAM-guard state. The fault stops the device (no reset unless built
  with the `watchdog` feature): unplug it. An overflow first passes through the 512 reserved PUF bytes, so a power cycle is needed before the PUF key
  works again. Peak stack use is measured with `--features stack_probe` (development builds; see README).
* **Key-value store:** only a store reported as invalid (foreign, older layout or corrupt: indistinguishable) is formatted; flash I/O
  and other errors stop the boot without erasing credentials or a pending reset marker.
* **Failure modes:** a PUF-bound record with an unrecoverable key stays locked until the key returns or a CTAP reset
  (which re-enrols, needs a power-on reset). A chip whose SRAM pattern is unusable can only run a build without
  `sram_puf`, and then loses PUF-bound records. A power cut during the one-time enrolment write leaves a damaged helper
  sector: CTAP reset repairs it. Build with `sram_puf` off (`build.sh -P`) to run without it.

## RAM guard (`src/ram_guard.rs`, `src/guard.rs`)
**What it is.** The master seed exists in RAM as 8 XOR shares in scattered, non-adjacent slots of a decoy-filled
pool, re-randomised adaptively (0.5 to 2 ms while a seed is held, in 7 short critical sections) and around each key use, with masks from a ChaCha20 DRBG (seeded at boot, reseeded
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
* The refresh costs CPU time (up to about 10 % at the fast 0.5 ms rate while the device is in use; measure it) and
  briefly masks interrupts. Each of the 7 steps is its own critical section, so the longest interrupt-off time is one
  step, not a whole refresh (`guard_log` reports it).
* Refreshing faster does not make a snapshot of all shares any less useful: it only shortens the time during which
  a slow or partial read stays consistent. Against code running on the device it buys nothing.
* Stack scrubbing (`src/scrub.rs`) clears dead stack frames, not CPU registers or the internal state of live
  library objects, and a 4 KiB scrub does not reach residue deeper than that (the boot scrub covers 32 KiB).
* `secrecy` is not used: it only adds `Debug` redaction and `ExposeSecret` ergonomics, and none of these types
  derive `Debug` at all.

## Vault updates
`set_pin` and factory reset fail, and never report success, if (a) the retry counter cannot be cleared, or (b) the
previous record (plain seed, or one wrapped under the old PIN) could not be verified wiped (erase retried, then
zero-programmed, then read back; the area must read uniformly 0xFF or 0x00). If the flash state after a failed
update cannot be determined, the device refuses to use any key until a CTAP reset. After a failed wipe in `set_pin`
the new record is already the one loaded at boot: set the PIN again in the same session (it retries the erase),
otherwise a CTAP reset is needed. A failed reset keeps its marker and is repeated at the next boot.
