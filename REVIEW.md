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

Edited without a Rust toolchain: nothing below has been compiled or run. Run `cargo fmt`, clippy and `host-test/run.sh`.

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
