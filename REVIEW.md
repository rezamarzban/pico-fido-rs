# Response to the code review

| # | Finding | Result |
|---|---------|--------|
| 1.1 | Held button satisfies presence | Fixed. Must be released, then pressed and held 30 ms (`usb/ctap.rs`). |
| 1.2 | Stalled CTAPHID message blocks others | Fixed. 500 ms message timeout, injected clock, tested. |
| 1.3 | INIT does not abort active transaction | Fixed. Same-channel INIT aborts; the waiting task drops the request and sends nothing. Tested. |
| 1.4 | Lenient CBOR | Fixed centrally in `cbor::validate`: minimal encodings only, no tags/floats/indefinite, no duplicate keys, nesting <= 4, no trailing bytes, UTF-8 checked. Commands without a body must have none. |
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

# Second review round (se-harden0 follow-up)

Written without a Rust toolchain; **compiled and tested since** (see the verification summary of the third round).

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

# PIN round (ClientPIN + wrapped master key)

Written without a Rust toolchain; **compiled and tested since** (see the verification summary of the third round).

| Area | Change |
|------|--------|
| `src/pin.rs` (new) | PIN/UV protocols 1 and 2: ECDH + HKDF / SHA-256, AES-256-CBC, HMAC. Known-answer tests use values computed independently with python `cryptography`. |
| `src/wrap.rs` (new) | Argon2id KEK (96 KiB, t=24, **unmeasured**), encrypt-then-MAC wrap with HMAC-SHA-256 only; parameters stored in the record and bounded on read. |
| `src/store.rs` | Versioned 110-byte record (plain or wrapped; legacy 56-byte still read). Persistent retry counter (16 flag pages, attempt written before evaluation, refund without erase). `Vault` trait. |
| `src/ctap.rs` | `Broken / Plain / Locked / Unlocked` key state, command 0x06, PIN checks in makeCredential/getAssertion (UV flag), reset through the vault, session expiry (`tick`, `lock`), zeroizing. |
| `src/keys.rs`, `src/usb/*`, `src/main.rs`, `build.rs` | Flash vault with logging, idle expiry timer, wipe on USB reset/suspend/disable, 160 KiB heap, 12 KiB flash reservation. |
| Tests | Retry-counter and compaction tests, wrap tamper tests, PIN crypto KATs, full flows for both protocols (set/change/token/expiry/lockout/reset/failed writes), python-fido2 end-to-end section. |

Known limits: offline PIN guessing against a flash dump (Argon2 memory is RAM-limited), key in RAM during a session,
no `pinUvAuthToken` permissions / RP-ID binding (CTAP 2.0 style `getPinToken` only). (`minPINLength` is reported by `getInfo` since the third round.)

# Third round (firmware-fixes.patch + tests-fixes.patch, `build.sh`, `guide.md`)

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

## Integration of the third round
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
