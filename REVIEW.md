# Review history

This file records the review rounds of the project. **Rounds 1-4 concern the earlier custom CTAP implementation
(`src/ctap.rs`, `src/cbor.rs`, `src/pin.rs`, `src/wrap.rs`, `src/store.rs`, `src/ctaphid.rs`), which was removed
in the OpenSK migration.** They are kept for history only: that code and its host tests no longer exist, and none of the fixes below apply to
the current firmware. This branch re-introduces files named `src/wrap.rs` and `src/store.rs` (plus `src/vault.rs`)
for its PIN-wrapped vault; the findings, parameters (for example Argon2 96 KiB, t=24) and test counts in Rounds
1-4 describe the earlier versions of those files, not the new ones.

# OpenSK migration (current firmware)

| Area | Before (custom code) | Now (OpenSK) |
|------|----------------------|--------------|
| CTAP2 / CBOR / CTAPHID / ClientPIN | own code, ~3000 lines | OpenSK library (pinned commit in `third_party/OPENSK_REV`) |
| U2F (CTAP1) | none | `ctap1` feature (attestation key must be provisioned) |
| Credentials | stateless, derived from one master key, ES256 only | OpenSK credential model (store-backed, discoverable credentials possible) |
| PIN protection of key at rest | Argon2id wrapping of the master key | Argon2id wrapping of a 32-byte seed in the vault (`src/wrap.rs`, `src/vault.rs`); OpenSK master keys derived from it; resident credentials encrypted (`src/env/harden.rs`). No PIN hash stored. Without a PIN: seed masked with the SRAM-PUF key and authenticated (in clear only in a build without `sram_puf`) |
| Flash use | 12 KiB (two key slots + retry counter) | 12 KiB vault + 4 KiB SRAM-PUF helper + 76 KiB `wasefire-store` (`src/env/flash_store.rs`) |
| Heap | 160 KiB (Argon2) | 128 KiB (OpenSK); Argon2 uses a separate static 64 KiB buffer |
| Concurrency | single executor, cooperative | OpenSK blocking in thread mode, USB/LED on an interrupt executor, packet queues in between |
| Touch | BOOTSEL, fresh press (own code) | BOOTSEL, fresh press via OpenSK's `UserPresence` (`src/env/user_presence.rs`) |
| Tests | 79 unit tests + python-fido2 end-to-end | OpenSK's own library tests only (`host-test/run.sh`); the platform layer is hardware-tested only |
| USB serial | on by default | off by default (`usb_serial` feature) |

Motivation: the custom firmware worked in Linux browsers but not on Windows and Android; the exact cause was never
established (differences from a working U2F+CTAP2 key included no U2F, PIN policy and touch behaviour). Reported
result after the move (maintainer, hardware): works on Linux, Windows and Android with all tried browsers.

## Review of openSK-based-se3 (static review, then fixes)

An external static review plus a second pass over the tree. Nothing here was compiled or run on hardware (no toolchain was
available when the fixes were written): build, `cargo clippy`, `sh host-test/run.sh` and a hardware test are still open.

| # | Finding | Result |
|---|---------|--------|
| BUG-1 | A blank PUF helper sector triggered enrolment even when the vault held a PUF-bound record: new PUF secret, orphaned seed; a no-PIN record has no tag, so a wrong seed was used silently | Fixed. No enrolment unless the vault is blank or holds an unbound record. PUF-masked plain records now carry an HMAC tag (older untagged ones are accepted once and re-sealed). |
| BUG-2 | USB reset between dequeue and processing: the stale packet was processed and the operation was stamped with the new epoch | Fixed. Epoch re-checked after the dequeue (main loop, `wait_packet`, `recv_packet`, user-presence wait); the operation is stamped with the epoch of its packet (`begin_op_at`). |
| BUG-3 | `try_decode` returned the PUF secret in a plain array; `is_some()` callers never wiped it | Fixed. Returned in `Zeroizing`; the code word and sample buffers are `Zeroizing` too. |
| BUG-4 | Stored Argon2 time cost unbounded (up to 255) | Fixed. `MAX_T_COST` = 64 in `kdf`. |
| DOC-1..8 | Wrong build branch, "only read at start-up", "never kept in RAM", offline-guessing claims, "clear" no-PIN record, fail-closed and cancellation claims | Fixed in README.md, SECURITY.md and this file. |
| extra | Damaged vault / read error / seed-store failure locked the device without any LED signal | Fixed. LED fault pattern (no halt: a CTAP reset must stay possible). |
| extra | LED fault flag was cleared at the start of a reset even if the reset later failed | Fixed. Cleared only after a completed reset. |
| extra | `build.sh` fell back to an unlocked build and defaulted to the wrong branch | Fixed. |
| extra | Host test `vault.rs` did not compile (`Record` literal without `puf`) | Fixed; `wrap.rs` is now covered by host tests. |
| se3 review 2 | Migration continued although the older record could not be wiped | Fixed: lock + fault (unbound bind, legacy re-seal, PIN bind); `vault::open` locks with the PUF required. |
| se3 review 2 | Legacy re-seal failure (`Kept`) kept using the untagged record | Fixed: fail closed until the tagged record is durable. |
| se3 review 2 | Response enqueue could race `cancel_all` | Fixed with a critical section around check + enqueue. The incoming side cannot be tagged with an arrival epoch (see SECURITY.md). |
| se3 review 2 | `fail_closed()` did not show the LED | Fixed: `fail_closed()` sets the fault. |
| se3 review 2 | Any `Store::new()` error formatted the store | Fixed: only `InvalidStorage` formats. |
| se3 review 2 | Failed PIN-record re-wrap (`wrap()` = None) still reported unlock | Fixed: seed cleared, fault, hardware failure. |
| se3 review 3 | General faults were conflated with the PUF-key fault that makes `init` postpone a reset | Fixed: separate `SEC_FAULT` flag; LED shows either. |
| se3 review 3 | Incoming USB read could complete after a reset | Mitigated: read restarted via `RESET_SIG`, epoch re-checked on completion. |
| se3 review 3 | `set_pin` left a PIN-wrapped vault without PIN metadata when the old record could not be wiped | Fixed: metadata written, error reported afterwards. |
| se3 review 4 | Stale endpoint data after suspend/deconfigure could reach the new read | Mitigated: endpoint drained after the reset signal (2 ms quiet time). Hardware test open. |
| se3 review 4 | A failed pending reset in `init()` aborted the boot (`CtapState::new` unwraps) | Fixed: lock + fault, marker kept, retried next boot. |
| se3 review 4 | `ctap.rs` comment indentation (rustfmt) | Fixed. |
| se4 review | 17 clippy warnings (`Cow<[u8]>` lifetime, `&**k`, `% n == 0`, doc lists) | Fixed (not re-run: no toolchain here). |
| se4 review | Ignored `enroll()` result in `reset`; ignored `finish_try` result | `enroll()` failure now logged, `finish_try` failure logged (the attempt stays counted, which is the safe direction; it does not lose a try). |
| se4 stack | No stack-overflow protection: the stack grew down into `.bss` (128 KiB heap, RAM-guard statics) | `flip-link` is now the linker (`.cargo/config.toml`, installed by `build.sh` and CI): the stack is the lowest RAM region and an overflow faults. Peak use can be logged with `--features stack_probe`. Not built or run here; the measured peak is still open. |
| se4 wdog | No hardware watchdog | Optional feature `watchdog` (`src/wdog.rs`): fed by the main thread only, 8 s. Off by default until the longest blocking step is measured on hardware. Not compiled. |
| open | Flash store erase budget (`max_page_erases` = 10000 per page) is a conservative software limit; reaching it makes the store refuse writes | Documented only |
| se4 puf2 | PUF helper was a single sector: a power cut inside a CTAP reset left the old record without its helper | Fixed: two helper slots, the record names its slot, the old helper is erased only after the new record is durable. Layout change (store 19 -> 18 pages): old images must be erased. Not compiled or power-cut tested. |
| se4 ctr | PIN counter lost pending failures when its full sector was erased and rewritten | Fixed without a new sector: `finish_try` recycles the sector at the moment all failures are forgiven (host tests: never erased with failures pending). |
| se4 setpin | A power cut between the vault commit and the PIN metadata needed a CTAP reset | Fixed: metadata first, `init` reconciles both inconsistent states. Not power-cut tested. |
| se4 guard | Refresh used a fixed 1 ms tick in one long critical section, and the idle main thread spun | Adaptive period (0.5 ms active, 2 ms idle, 50 ms locked), 7 short critical sections, `wfi` sleep in the waits. Not built, not measured. |
| se4 guard | Copies of secrets left in dead stack frames (by-value returns, hash/HMAC state) | `master_into` instead of a by-value return, `scrub::stack()` after every command / cancel, `scrub::stack_boot()` at boot. |
| se4 oled | No device status | SSD1306 status screen (`src/oled.rs`, feature `oled`): FIDO, USB, PIN/PUF, CPU, RAM, stack, guard rate, flash. Not built or run. |
| se4 oled2 | OLED stayed blank although the MicroPython example works | Two causes found by reading the code against `ssd1306.py`: (1) `build.sh` builds with `--no-default-features`, so the `oled` feature was never compiled in: now added by default (`-O` omits it). (2) embassy-rp leaves the I2C pull-ups off while MicroPython turns them on: now enabled on GP16/GP17 after the driver setup, bus at 100 kHz, 100 ms power-up wait, first retry after 0.5 s, init failures logged. Not built or run here (no toolchain). |
| se5 ir | PIN entry with a VS1838B IR remote (magic PIN of ten zeros, >= 8 keys, BOOTSEL confirm, double entry when setting, OLED entry screen, keepalives) | `src/ir.rs`, `src/nec.rs`, `src/ir_pin.rs`, hooks in `set_pin` / `unlock_with_pin`; pure helpers host-tested (`host-test/guard/tests/nec.rs`). Not built or run here. To check on hardware: NEC decoding with your remote, host timeout behaviour during a long entry (Chrome, Windows, libfido2), that a cancelled entry counts as one failed attempt. |
| open | Stress test (USB latency, authentication reliability, power, watchdog under load) | Procedure in README.md ("Stress test"); `guard_log` feature logs the numbers. Not run. |
| open | No `Cargo.lock` | Needs a successful build to generate. |

## Status and open items
* **Verified:** the firmware patch applies cleanly; `src/` here equals it. The OpenSK library alone, at the pinned
  commit, type-checks for `thumbv6m-none-eabi`. Everything else about the build and the hardware behaviour is
  maintainer-reported.
* [ ] Commit `Cargo.lock` and the submodule pointer at the pinned commit.
* [ ] Run `cargo fmt --check`, `cargo clippy -- --deny=warnings` and the CI workflow (never run on this tree).
* [ ] Test matrix on hardware: PIN dialogs, discoverable credentials, U2F-only sites, reset, power loss during a flash
  write, long idle, two clients, repeated registrations, P-256 timing, RAM headroom.
* [ ] Provision a U2F attestation key (OpenSK `tools/configure.py`) if U2F-only sites matter.
* [x] Security: PIN-wrapped master seed + resident-credential encryption added (this branch). Built and run on a Pico by the maintainer; no detailed test record.
* [ ] Hardening tests on hardware: Argon2 time (tune `T_COST`), RAM headroom, setPIN/changePIN/verify, resident credentials across reboot, lock on USB reset, power loss during setPIN and reset, 8-try block, reset recovery of a damaged vault.
* [ ] Re-validate `third_party/opensk-harden.patch` on every `OPENSK_REV` change.
* [ ] Security: consider a secure element; offline guessing is limited by Argon2 at 64 KiB only when the PUF is off or its secret is known (a flash-only dump lacks the PUF-derived password input).
* [ ] Replace the prototype USB VID/PID and strings (`src/usb/mod.rs`).
* [ ] Tests for `src/env/*` that can run on the host (flash store geometry, packet queues).

---

# Round 1: response to the code review (custom firmware)

| # | Finding | Result |
|---|---------|--------|
| 1.1 | Held button satisfies presence | Fixed. Must be released, then pressed and held 30 ms (`usb/ctap.rs`). |
| 1.2 | Stalled CTAPHID message blocks others | Fixed. 500 ms message timeout, injected clock, tested. |
| 1.3 | INIT does not abort active transaction | Fixed. Same-channel INIT aborts; the waiting task drops the request and sends nothing. Tested. |
| 1.4 | Lenient CBOR | Fixed centrally in `cbor::validate`: minimal encodings only, no tags/floats/indefinite (floats in unknown fields were accepted again in round 2, #6), no duplicate keys, nesting <= 4, no trailing bytes, UTF-8 checked. Commands without a body must have none. |
| 1.5 | `user` / descriptors not validated | Fixed. `user.id` required (1..64 bytes), `pubKeyCredParams` required, descriptors need `type` and `id` (other types ignored). |
| 2.1 | Master key in plain flash | Cannot be fixed on RP2040. Documented in SECURITY.md. |
| 2.2 | RNG not justified | Hardened (more raw input, pool, stuck-source halt) and documented honestly. Still ROSC-based. |
| 2.3 | Read error / corrupt record re-keys device | Fixed. Only truly blank flash is initialised; otherwise the device refuses to work until an explicit reset. |
| 2.4 | No integrity / recovery | Fixed. `store.rs`: two slots, hash, sequence number, verify, power-loss tested at every step. |
| 3.1 | Crypto blocks the task | Not changed (P-256 cannot yield cheaply). A keepalive is sent first and the duration is logged for measurement on hardware. Cancel is only meaningful while waiting for touch. |
| 3.2 | Channel allocation | Fixed. Registry of 8 channels, unique IDs, unknown channels rejected, oldest evicted. |
| 3.3 | WINK inconsistent | Fixed by removal: not advertised, not accepted. |
| 3.4 | Reset window | Fixed. Reset only within 10 s of power-up. |
| 4.1 | Host tests not in CI | Fixed. `host-tests` CI job runs `host-test/run.sh`. |
| 4.2 | FFI validation | Fixed. Null/length/capacity checks, panics caught. |
| 5 | Flash error panic | Fixed (errors are returned and reported as CTAP `OTHER`). |
| 5 | Fixed USB serial | Fixed. Derived from the flash chip unique ID. |
| 5 | Unused keyboard interface | Removed (`src/usb/hid.rs`, `usbd-hid`), leaving a single FIDO HID interface. |

# Round 2: second review round (custom firmware)

Written without a Rust toolchain; **compiled and tested since** (see the verification summary under *Integration of round 4*).

| # | Finding | Result |
|---|---------|--------|
| 1 | getAssertion `up=false` skips touch | Fixed. `up` is validated but ignored; touch always required, UP flag set. e2e test updated. |
| 2 | Reset with unknown storage position can resurrect old key | Fixed. `store::save` always scans both slots (read errors abort), uses `newest seq + 1` in the other slot, wipes the old slot with erase-retry then zero-overwrite fallback. Tests: higher-seq survivor, stuck slots. |
| 3 | Reset fails in session but succeeds after reboot | Fixed. `store::replace` re-reads flash after any failure and returns `New` / `Kept` / `NoKey` / `Unknown`; the firmware sets its key from that (fail closed on `Unknown`). Failed unverified record is rolled back. Tests added. |
| 4 | Reset deadline checked after touch | Fixed. The arrival timestamp is used for both calls. |
| 5 | Map order / key types | Fixed. Canonical order (length, then bytewise) and int/text keys enforced at every depth. |
| 6 | Floats rejected | Fixed. float16/32/64 and simple values 20..23 accepted; other simple values / break rejected. |
| 7 | CANCEL handling | Fixed. Ignored unless it targets the active transaction; non-zero length -> INVALID_LEN. |
| 8 | Zero-length CBOR | Fixed. INVALID_LEN at framing level, before any assembly. |
| 9 | Channel eviction | Fixed. LRU; never evicts the active channel or one with a partial message; evicted-channel state is cleared. |
| 10 | Nested missing-field error | Fixed. `CBOR_UNEXPECTED_TYPE` for missing user.id, descriptor members and pubKeyCredParams members. Top-level missing keys stay `MISSING_PARAMETER`. |
| 11 | Stable CI vs nightly feature | Fixed by making nightly explicit: firmware CI, clippy and fmt use nightly; the host tests use a stable `host-test/rust-toolchain.toml`. |
| 12 | Clippy `map_or` | Fixed (rewritten as a `match`; `--all-features` removed from CI because `flash_*` are exclusive). |
| 13 | Fault-injection tests | Added: erase refused with data intact, stuck slots, verify-read failure, unknown position, unreadable flash, wrap-around. |
| 14 | RNG health | Improved (RCT, APT, repeated sample) and documented as a failure detector only. Not entropy validation. |
| 15 | Flash size | Configurable via `flash_*` features; `build.rs` generates `memory.x`. No runtime chip-size check (not verified on hardware). |
| 16 | Unique-ID errors | Fixed. Serial omitted if unreadable or constant. |
| 17 | CBOR 64-bit writer | Fixed + boundary tests. |
| 18 | Crypto blocks CTAP task | Not changed (design limitation, documented; measure on hardware). |
| 19 | Allocation / quadratic key check | Fixed. Linear, allocation-free map validation. |
| 20 | Prototype USB IDs | Not fixable in code: constants isolated and documented; a real VID/PID must be obtained. |
| 21 | Persistent serial privacy | `usb_serial` feature (default on) can be disabled. |
| 22 | Docs | README added; SECURITY.md updated; hardware-verification gaps stated. |

# Round 3: PIN round (custom firmware)

Written without a Rust toolchain; **compiled and tested since** (see the verification summary under *Integration of round 4*).

| Area | Change |
|------|--------|
| `src/pin.rs` (new) | PIN/UV protocols 1 and 2: ECDH + HKDF / SHA-256, AES-256-CBC, HMAC. Known-answer tests use values computed independently with python `cryptography`. |
| `src/wrap.rs` (new) | Argon2id KEK (96 KiB, t=24, **unmeasured**), encrypt-then-MAC wrap with HMAC-SHA-256 only; parameters stored in the record and bounded on read. |
| `src/store.rs` | Versioned 110-byte record (plain or wrapped; legacy 56-byte still read). Persistent retry counter (16 flag pages, attempt written before evaluation, refund without erase). `Vault` trait. |
| `src/ctap.rs` | `Broken / Plain / Locked / Unlocked` key state, command 0x06, PIN checks in makeCredential/getAssertion (UV flag), reset through the vault, session expiry (`tick`, `lock`), zeroizing. |
| `src/keys.rs`, `src/usb/*`, `src/main.rs`, `build.rs` | Flash vault with logging, idle expiry timer, wipe on USB reset/suspend/disable, 160 KiB heap, 12 KiB flash reservation. |
| Tests | Retry-counter and compaction tests, wrap tamper tests, PIN crypto KATs, full flows for both protocols (set/change/token/expiry/lockout/reset/failed writes), python-fido2 end-to-end section. |

Known limits: offline PIN guessing against a flash dump (Argon2 memory is RAM-limited), key in RAM during a session,
no `pinUvAuthToken` permissions / RP-ID binding (CTAP 2.0 style `getPinToken` only). (`minPINLength` is reported by `getInfo` since round 4.)

# Round 4: firmware-fixes.patch + tests-fixes.patch (custom firmware)

| # | Finding | Result |
|---|---------|--------|
| `main.rs` assert | `use defmt::*` shadows the const `assert!` | Fixed: `core::assert!`. The `sed` step in `build.sh` is now a no-op. |
| 1 | Old key slot not wiped | Fixed. `commit()` reports "done" or "done, old record remains"; in the second case setPIN / changePIN / reset answer `0x7F` but the new durable state is adopted. `purge_stale()` retries the wipe at every boot. |
| 9 | Erase not read back | Fixed. `wipe()` reads the slot back after every erase (software read-back, not proof of physical erasure). |
| 2 | USB wipe during touch wait / crypto | Fixed. `wait_touch()` polls `WIPE` every 10 ms; the task re-checks after the touch, before the second pass and before the response. |
| 3 | Key-agreement key survives a session | Fixed. `lock()` clears it (so expiry does too). |
| 4 | `finish_try` result ignored | Fixed. A failure fails the command: no key, no token. |
| 5 | `clear_tries` result ignored | Fixed. The error is propagated in reset and setPIN. |
| 6 | Wrong APT cutoff | Fixed. 410 -> 311 (SP 800-90B, W = 512, H = 1 bit/byte). |
| 7 | COSE metadata unchecked | Fixed. `kty` = 2 and `crv` = 1 required; `alg` = -25 if present. |
| 8 | Stale timestamp | Fixed. `handle_at(arrived_ms, now_ms)`: the reset window uses the arrival time, token expiry the current time. `handle()` is kept as a wrapper. |
| 18 | `minPINLength` | Added to `getInfo`; `versions` stays `FIDO_2_0` on purpose. |
| - | Clippy `deprecated` (GenericArray) | `#![allow(deprecated)]` in `pin.rs`, to be removed with the cipher 0.5 / generic-array 1.x move. |

Behaviour changes: a failed wipe now reports an error although the new state is active (retry is safe); a USB
reset/suspend while a command waits for the button cancels it; clients whose key-agreement object omits `kty` or
`crv` are rejected (test with your real client set).

## Integration of round 4
* Both patches applied cleanly to `pico-fido-rs-lite-3`; no `.orig`/`.rej` files.
* **One test-helper fix:** `a_token_that_expires_while_the_button_is_awaited_is_refused` failed after the patches
  (79th test, `PIN_INVALID`). Cause: the test helper sent *getKeyAgreement* with a fixed clock of 1000 ms right
  before a *getPinToken* at 200 000 ms, so time ran backwards; the expiry tick of the second request then discarded
  the key-agreement key (fix #3) and the PIN hash could not be decrypted. The helper now takes the clock of the
  call it belongs to (`Plat::agree_at`). The firmware was not changed. A real client would have to see the old
  session expire exactly between its two back-to-back requests; the effect would be one spurious failed PIN try
  (forgiven by the next correct PIN).
* `rustfmt` applied to `src/`; the new code in `ctap.rs` was not formatted.
* `.gitignore` no longer ignores `Cargo.lock` (see below) and ignores `out/` and `work/`.
* **Verified here:** 79 unit tests + the python-fido2 2.2.1 end-to-end test pass; the firmware builds and links
  for 2/4/8/16 MiB flash (with and without `usb_serial`) with zero warnings (Ubuntu rustc 1.91.1,
  `RUSTC_BOOTSTRAP=1`, `-Zbuild-std`; not the CI nightly); enabling two `flash_*` features is refused by `build.rs`.
* **Not verified:** clippy, the CI workflow, `build.sh` end to end, anything on hardware. Still open from earlier
  rounds: P-256 / Argon2 timing on the Pico, RNG on a real ring oscillator, real flash failures, USB IDs.
* Tests still missing for this round: wipe or counter failures, session expiry during a touch wait, COSE metadata
  cases (the patches did not add them).

## RAM guard, USB cancellation and vault updates (se1 additions)
Documented in `README.md` and `SECURITY.md`; this file had no verification record for them.
* [ ] Record what was built and run for `src/ram_guard.rs`, `src/guard.rs`, `env::hid::cancel_all()` /
  `Ctap::cancel_in_flight()` and the vault-update checks (`host-test/guard` is the only test the README names).
* [ ] Measure the share-refresh cost (estimated at about 100 us per refresh; `REFRESH_MS`).
* [ ] Test USB reset / suspend during a button wait and during a signature.
* [ ] Test a failed wipe in setPIN / reset (the device refuses to work until a CTAP reset).

## SRAM PUF (this round; built and run on a Pico by the maintainer, no detailed test record)
* [ ] Compile and run; read the logged `puf: N bit errors` on several chips, cold boots, temperatures.
* [ ] Confirm the first 512 bytes of RAM are left alone by the boot ROM / boot2 on a normal flash boot, and see what
  BOOTSEL / UF2 flashing does to them.
* [ ] Check bias / entropy of the enrolled sample over several chips; consider multi-sample enrolment and cell selection.
* [ ] Test: first boot enrolment, upgrade of an existing device (no-PIN and PIN-set), PIN verify with the key
  unavailable (no retry counted), reset re-enrolment, power cut during enrolment, quick unplug-replug.
* [ ] `HAD_POR` is read from CHIP_RESET (0x4006_4008, bit 8): confirm on hardware.

## SRAM PUF fail-closed round (written without compiling)
Fixes the issue that a PUF failure could silently produce a plain / unbound seed record.
* `vault::open(flash, create_plain)`: with the PUF required a blank vault stays blank and the first record is created
  PUF-bound in `HardenPersist::new` (no plain seed ever reaches flash).
* `new`: required + no key -> locked, `puf::set_fault(true)`. Boot-time bind failure (`Kept`/`NoKey`/`Unknown`) -> locked.
* `incr_pin_fails` refuses before counting while the vault is closed or the PUF key is missing (a "refund" via `finish_try` would have forgiven earlier failures = counter bypass; removed); `set_pin` refuses without the key.
* `reset`: refused before any write (no marker) unless the PUF can be (re-)enrolled; `init` no longer panics the boot when
  only the PUF blocks a pending reset.
* LED: 3 short blinks + pause while `puf::fault()`.
* [ ] Build and test: blank first boot, enrolment failure (non-POR first boot), noisy sample with an unbound record,
  noisy sample with a PUF-bound record, reset with and without a power-on reset, a flash write failure during binding.
