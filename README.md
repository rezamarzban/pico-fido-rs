# pico-fido-rs

A small, software-only FIDO2 / CTAP2 security key for the Raspberry Pi Pico (RP2040), written in Rust
with Embassy. **Experimental. Read `SECURITY.md` before relying on it.**

## Supported CTAP subset
`authenticatorGetInfo`, `authenticatorMakeCredential`, `authenticatorGetAssertion`,
`authenticatorClientPIN` (getPinRetries, getKeyAgreement, setPIN, changePIN, getPinToken),
`authenticatorReset`, `authenticatorSelection`. ES256 only, attestation `none`, no resident keys,
no U2F/CTAP1, sign counter always 0. PIN/UV auth protocols 1 and 2; the PIN is optional (`getInfo` reports `minPINLength` = 10 and stays at
`FIDO_2_0` on purpose, because CTAP 2.1 features such as credential management are not implemented).
Credentials are stateless (derived from one master key).
Every signature, registration, selection and reset needs a fresh press of BOOTSEL; the `up` option of
getAssertion cannot disable this.

## Using the key
See **`guide.md`** (detecting the device, setting a PIN, registering, signing in, reset, backups).
Try it on a throwaway account such as https://webauthn.io first.

## Build
The firmware needs the **nightly** toolchain (`rust-toolchain.toml`; `#![feature]` in `src/main.rs`).
There is no stable firmware build.

    cargo build --release                       # 2 MiB board (default)
    cargo build --release --no-default-features \
        --features rp2040_board,flash_4m,usb_serial   # e.g. a 4 MiB board

Enable **exactly one** `flash_*` feature (`flash_2m`, `flash_4m`, `flash_8m`, `flash_16m`); `build.rs`
generates `memory.x` from it and the last 12 KiB of flash hold the retry counter and the key slots. Do not use `--all-features`.
Omit the `usb_serial` feature to expose no persistent USB serial number (privacy).

### One-command UF2 build (`build.sh`)
`bash build.sh [-s 2|4|8|16] [-n] [-t TOOLCHAIN] [-r REPO_URL] [-b BRANCH] [-o OUT_DIR]` clones the
repository, installs the nightly toolchain and `elf2uf2-rs`, builds with the right `--features`
(`-s` = flash size in MiB, `-n` = no USB serial) and writes `out/pico-fido-rs-<N>m.uf2`. Hold BOOTSEL while
plugging in and copy the file to the `RPI-RP2` drive. It also works in Colab (`!bash build.sh -s 2`).
**Pick the flash size that matches your board**: a wrong size makes the firmware read and write flash at the
wrong addresses. `build.sh` builds the *committed* revision of the repository, so commit your changes first;
`Cargo.lock` must be committed too (it pins `fixed` to a version the pinned nightly can compile). The script
itself has only been syntax-checked, not run end to end.

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
What **was** done on this revision (in a sandbox, not on the pinned nightly):
* `host-test/run.sh`: 79 Rust unit tests + the python-fido2 2.2.1 end-to-end test (PIN protocols 1 and 2,
  lockout, reset, persistence) all pass.
* The firmware cross-compiles and links for `thumbv6m-none-eabi` with the 2, 4, 8 and 16 MiB `flash_*`
  features (with and without `usb_serial`) with **zero compiler warnings**, using Ubuntu's rustc 1.91.1 with
  `RUSTC_BOOTSTRAP=1` and `-Zbuild-std` (not the `nightly` channel the CI uses). Default build: about 200 KB of
  flash and 168 KB of RAM (160 KiB of it is the Argon2 heap).
* `rustfmt` was applied to `src/`. Mutation checks on earlier revisions confirmed the tests fail when fixes are reverted.

What was **not** done:
* `cargo clippy -- --deny=warnings` and the CI workflow were never run. Run them first.
* **Nothing was run on hardware.** Host tests exercise the protocol logic and a *simulated* flash; they are not a
  substitute for tests on physical flash. Unverified on a real Pico: USB enumeration with real browsers/OSes,
  BOOTSEL handling, real flash erase/write failures and power loss, retry counter on physical flash, P-256 timing
  (`crypto took N ms` in the RTT log), Argon2 timing and memory fit (`ctap command took N ms`; tune
  `M_KIB`/`T_COST` in `src/wrap.rs`), compatibility with real browser/OS PIN dialogs, and the RNG health tests on a
  real ring oscillator (thresholds are conservative but unvalidated).
* `build.sh` was only syntax-checked (no network in the sandbox).
* USB VID/PID (`0xc0de:0xcafe`) and strings are prototype placeholders (`src/usb/mod.rs`).
