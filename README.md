# pico-fido-rs

A small, software-only FIDO2 / CTAP2 security key for the Raspberry Pi Pico (RP2040), written in Rust
with Embassy. **Experimental. Read `SECURITY.md` before relying on it.**

## Supported CTAP subset
`authenticatorGetInfo`, `authenticatorMakeCredential`, `authenticatorGetAssertion`,
`authenticatorClientPIN` (getPinRetries, getKeyAgreement, setPIN, changePIN, getPinToken),
`authenticatorReset`, `authenticatorSelection`. ES256 only, attestation `none`, no resident keys,
no U2F/CTAP1, sign counter always 0. PIN/UV auth protocols 1 and 2; the PIN is optional.
Credentials are stateless (derived from one master key).
Every signature, registration, selection and reset needs a fresh press of BOOTSEL; the `up` option of
getAssertion cannot disable this.

## Build
The firmware needs the **nightly** toolchain (`rust-toolchain.toml`; `#![feature]` in `src/main.rs`).
There is no stable firmware build.

    cargo build --release                       # 2 MiB board (default)
    cargo build --release --no-default-features \
        --features rp2040_board,flash_4m,usb_serial   # e.g. a 4 MiB board

Enable **exactly one** `flash_*` feature (`flash_2m`, `flash_4m`, `flash_8m`, `flash_16m`); `build.rs`
generates `memory.x` from it and the last 12 KiB of flash hold the retry counter and the key slots. Do not use `--all-features`.
Omit the `usb_serial` feature to expose no persistent USB serial number (privacy).

## PIN
Without a PIN the master key is stored in plain flash, so anyone who can read the flash owns your
credentials. Set a PIN with any FIDO2 client (`fido2-token -S`, `ykman fido access change-pin`,
Chrome/Windows security-key settings). The PIN must be at least 10 characters. It wraps the master
key with Argon2id; the unwrapped key lives in RAM only during a PIN session (2 minutes). A
forgotten PIN cannot be recovered: reset the key (touch within 10 s of plugging in), which destroys
all credentials. The security of a *stolen* device then depends on your PIN's entropy, because the flash
can be attacked offline. See `SECURITY.md`.

## Tests
    sh host-test/run.sh     # Rust unit tests (CBOR, CTAPHID, flash-store + retry-counter fault injection, RNG health, PIN crypto known-answer
                            # tests, key wrapping, full ClientPIN flows for both protocols)
                            # + end-to-end test with python-fido2 (pip install fido2); builds on stable

## Verification status (be honest about it)
* Host tests exercise the protocol logic and a *simulated* flash. They are not a substitute for tests on
  physical flash.
* **Not verified on hardware (PIN in particular):** Argon2 timing and memory fit (`ctap command took N ms`
  in the RTT log; tune `M_KIB`/`T_COST` in `src/wrap.rs`), compatibility with real browsers/OS PIN dialogs,
  the retry counter on physical flash. Also: USB enumeration with real browsers/OSes, BOOTSEL handling, real flash
  erase/write failures and power loss, P-256 timing (watch the `crypto took N ms` RTT log), the RNG
  health tests on a real ring oscillator (thresholds are conservative but unvalidated).
* The code in this revision was edited without access to a Rust toolchain: run `cargo fmt`,
  `cargo clippy -- --deny=warnings` and the host tests first and fix anything they report.
* USB VID/PID (`0xc0de:0xcafe`) and strings are prototype placeholders (`src/usb/mod.rs`).
