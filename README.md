# pico-fido-rs

A small, software-only FIDO2 / CTAP2 security key for the Raspberry Pi Pico (RP2040), written in Rust
with Embassy. **Experimental. Read `SECURITY.md` before relying on it.**

## Supported CTAP subset
`authenticatorGetInfo`, `authenticatorMakeCredential`, `authenticatorGetAssertion`,
`authenticatorReset`, `authenticatorSelection`. ES256 only, attestation `none`, no resident keys,
no PIN, no U2F/CTAP1, sign counter always 0. Credentials are stateless (derived from one master key).
Every signature, registration, selection and reset needs a fresh press of BOOTSEL; the `up` option of
getAssertion cannot disable this.

## Build
The firmware needs the **nightly** toolchain (`rust-toolchain.toml`; `#![feature]` in `src/main.rs`).
There is no stable firmware build.

    cargo build --release                       # 2 MiB board (default)
    cargo build --release --no-default-features \
        --features rp2040_board,flash_4m,usb_serial   # e.g. a 4 MiB board

Enable **exactly one** `flash_*` feature (`flash_2m`, `flash_4m`, `flash_8m`, `flash_16m`); `build.rs`
generates `memory.x` from it and the last 8 KiB of flash hold the key slots. Do not use `--all-features`.
Omit the `usb_serial` feature to expose no persistent USB serial number (privacy).

## Tests
    sh host-test/run.sh     # Rust unit tests (CBOR, CTAPHID, flash-store fault injection, RNG health)
                            # + end-to-end test with python-fido2 (pip install fido2); builds on stable

## Verification status (be honest about it)
* Host tests exercise the protocol logic and a *simulated* flash. They are not a substitute for tests on
  physical flash.
* **Not verified on hardware:** USB enumeration with real browsers/OSes, BOOTSEL handling, real flash
  erase/write failures and power loss, P-256 timing (watch the `crypto took N ms` RTT log), the RNG
  health tests on a real ring oscillator (thresholds are conservative but unvalidated).
* The code in this revision was edited without access to a Rust toolchain: run `cargo fmt`,
  `cargo clippy -- --deny=warnings` and the host tests first and fix anything they report.
* USB VID/PID (`0xc0de:0xcafe`) and strings are prototype placeholders (`src/usb/mod.rs`).
