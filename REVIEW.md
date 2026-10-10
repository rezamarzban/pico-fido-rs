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
