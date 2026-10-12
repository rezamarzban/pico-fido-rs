# pico-fido-rs

A FIDO2 / U2F security key for the Raspberry Pi Pico (RP2040), written in Rust with Embassy. The CTAP
protocol itself is **Google's OpenSK library** (Apache-2.0); this repository is the RP2040 platform layer
around it (USB, flash store, button, RNG). **Experimental. Read `SECURITY.md` before relying on it.**

## Architecture
| Part | Where |
|------|-------|
| CTAP2 / CTAP1 (U2F), CTAPHID, ClientPIN, credential logic | OpenSK, `third_party/OpenSK/libraries/opensk` (git submodule; commit in `third_party/OPENSK_REV`) |
| `opensk::env::Env` for the Pico | `src/env/mod.rs` (`PicoEnv`; customization: minimum PIN length 10, batch attestation off) |
| Persistent store (credentials, keys, PIN state) | `src/env/persist.rs` + `src/env/flash_store.rs`, on the `wasefire-store` crate |
| User presence = fresh BOOTSEL press | `src/env/user_presence.rs` |
| Packet bridge between USB (async) and OpenSK (blocking) | `src/env/hid.rs` (two queues) |
| Random numbers | `src/env/rng.rs` -> `src/keys.rs` (ring oscillator + SHA-256, `src/health.rs` health tests) |
| Clock | `src/env/clock.rs` |
| USB device, LED, main loop | `src/usb/`, `src/main.rs` |

OpenSK blocks (waiting for the button, computing signatures), so it runs in thread mode. USB, the LED and the
packet pump run on a **higher-priority interrupt executor** (`SWI_IRQ_1`), so USB keeps being serviced
meanwhile. OpenSK features enabled: `ctap1` (U2F), `config_command`, `software_crypto` (RustCrypto, ES256).
What the device really reports is whatever `authenticatorGetInfo` returns (`fido2-token -I`).

## OpenSK version
The commit is pinned in **`third_party/OPENSK_REV`** (`79e85b9a72a1ad99745e0d07aec9708d2f7ad6a9`). Always build
the pinned commit: an unpinned OpenSK (for example a branch name) can change between builds. When you update the
pin, rebuild, retest on hardware and update the file.

## Flash layout
The **last 80 KiB** of flash (20 pages of 4 KiB, `STORE_PAGES` in `src/main.rs`) hold the OpenSK key-value store.
`build.rs` keeps exactly that area out of the linker's FLASH region and derives everything from the single
`flash_*` feature, so firmware and store cannot overlap. On first boot, if that area holds nothing the store
understands (for example leftovers of the earlier custom firmware), it is **erased once** and started empty.
Credentials and PINs from that earlier firmware are gone: register again.

## Build
Needs the **nightly** pinned in `rust-toolchain.toml` (`nightly-2026-06-03`, the one OpenSK pins; OpenSK is
edition 2024). There is no stable firmware build. Release builds are size-optimised (`opt-level = "s"`, LTO,
stripped).

    # one-time: OpenSK as a submodule at the pinned commit (do NOT fetch its nested submodules)
    git submodule add --depth 1 https://github.com/google/OpenSK.git third_party/OpenSK
    git -C third_party/OpenSK fetch --depth 1 origin $(cat third_party/OPENSK_REV)
    git -C third_party/OpenSK checkout $(cat third_party/OPENSK_REV)
    git add .gitmodules third_party/OpenSK

    cargo build --release                       # 2 MiB board; USB serial number off (default)
    cargo build --release --no-default-features \
        --features rp2040_board,flash_4m,usb_serial   # e.g. a 4 MiB board with a USB serial number

Enable **exactly one** `flash_*` feature (`flash_2m`, `flash_4m`, `flash_8m`, `flash_16m`) and pick the size that
matches your board; do not use `--all-features`. `usb_serial` adds the flash unique ID as the USB serial number
(off by default: it lets hosts recognise the device across connections).

**Commit `Cargo.lock`.** There is none in this tree; without it every build resolves the newest crates and a future
release can break a working build. Generate it with a successful build and commit it.

### One-command UF2 build (`build.sh`)
`bash build.sh [-s 2|4|8|16] [-u] [-t TOOLCHAIN] [-r REPO_URL] [-b BRANCH] [-o OUT_DIR]` clones the repository,
fetches OpenSK at the pinned commit (or the submodule commit), installs the toolchain and `elf2uf2-rs`, builds with
the right `--features` (`-s` flash size in MiB, `-u` adds the USB serial number) and writes
`out/pico-fido-rs-<N>m.uf2`. Hold BOOTSEL while plugging in and copy the file to the `RPI-RP2` drive. It builds the
*committed* revision of the repository. This script itself was only syntax-checked; the maintainer's Colab build
(same toolchain and features) is what was run on hardware.

## U2F attestation
U2F registration needs an attestation key and certificate, which this firmware does not contain. OpenSK provides
`tools/configure.py` (uses the `config_command` feature) to write them; that path was not tried here.
`use_batch_attestation` is off, so FIDO2 registrations use self attestation.

## PIN
At least **10 code points** (`default_min_pin_length` in `src/env/mod.rs`). Set it with any FIDO2 client
(`fido2-token -S`, `ykman fido access change-pin`, Chrome/Windows security-key settings). **OpenSK stores the PIN
hash and the key material in clear in flash**: there is no Argon2 wrapping any more, and anyone who can read the
flash can attack the PIN offline. See `SECURITY.md`.

## Tests
    sh host-test/run.sh     # OpenSK's own library unit tests (the protocol logic), run on the host

The earlier host tests (custom CBOR, CTAPHID, PIN, key store, python-fido2 end-to-end) tested code that no longer
exists and were removed. **Nothing in this repository tests `src/env/*`, the USB bridge or the executor split**:
they are checked on hardware only.

## Verification status (be honest about it)
Reported by the maintainer (not independently verified): firmware built with the Colab script
(`nightly-2026-06-03`, `flash_2m`, no `usb_serial`, size-optimised release profile), flashed to a Pico, and
**working on Linux, Windows and Android with all tried browsers**. This is the behaviour the earlier custom
firmware did not have on Windows and Android.

Checked while preparing this tree:
* The firmware patch that created `src/env/*` and the OpenSK wiring applies cleanly, and `src/`, `build.rs` and
  `rust-toolchain.toml` here are identical to it.
* The OpenSK library alone, at the pinned commit, with `ctap1,software_crypto`, type-checks for
  `thumbv6m-none-eabi` (check only).

**Not done / unknown:**
* `cargo clippy -- --deny=warnings`, `cargo fmt --check` and the CI workflow were never run on this tree.
* No documented test matrix: which sites, PIN dialogs, U2F-only sites, resident keys, reset, power loss during a
  flash write, P-256 signing time, RAM headroom (128 KiB heap), and RNG health tests on a real ring oscillator.
* `build.sh` end to end, and U2F attestation provisioning.
* USB VID/PID (`0xc0de:0xcafe`) and strings are prototype placeholders (`src/usb/mod.rs`).
