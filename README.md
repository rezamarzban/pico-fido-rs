# pico-fido-rs

A FIDO2 / U2F security key for the Raspberry Pi Pico (RP2040), written in Rust with Embassy. The CTAP
protocol itself is **Google's OpenSK library** (Apache-2.0); this repository is the RP2040 platform layer
around it (USB, flash store, button, RNG). This branch adds a PIN-wrapped master-key vault to the OpenSK-based firmware. **Experimental, and the hardening is new and untested on hardware. Read `SECURITY.md` before relying on it.**

## Architecture
| Part | Where |
|------|-------|
| CTAP2 / CTAP1 (U2F), CTAPHID, ClientPIN, credential logic | OpenSK, `third_party/OpenSK/libraries/opensk` (git submodule; commit in `third_party/OPENSK_REV`) |
| `opensk::env::Env` for the Pico | `src/env/mod.rs` (`PicoEnv`; customization: minimum PIN length 10, batch attestation off) |
| Persistent store (credentials, metadata, PIN length) | `src/env/persist.rs` + `src/env/flash_store.rs`, on the `wasefire-store` crate (cleartext backend) |
| Hardening: master key + resident-credential encryption, PIN verifier, retry counter | `src/env/harden.rs` (`HardenPersist`), `src/vault.rs`, `src/store.rs`, `src/wrap.rs`; PIN hook in `third_party/opensk-harden.patch` |
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
The **last 92 KiB** of flash are kept out of the linker's FLASH region (`build.rs`):
* the last **12 KiB** (`VAULT_BYTES`) are the vault: `[PIN retry counter][seed slot 0][seed slot 1]` (`src/vault.rs`);
* the **80 KiB** below it (20 pages of 4 KiB, `STORE_PAGES`) are the OpenSK key-value store.

`build.rs` derives everything from the single `flash_*` feature, so firmware, store and vault cannot overlap.
This layout differs from the earlier branches: **erase the whole flash before the first install** (a vault sector
holding old data is reported as damaged and the device refuses to work until a CTAP reset). On first boot a blank
vault gets a fresh random seed; a store area the store does not understand is erased once.

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

## PIN and key protection
At least **10 code points** (`default_min_pin_length` in `src/env/mod.rs`). Set it with any FIDO2 client
(`fido2-token -S`, `ykman fido access change-pin`, Chrome/Windows security-key settings).

With a PIN set, the 32-byte master seed is wrapped with **Argon2id** (64 KiB static buffer, `M_KIB`/`T_COST` in
`src/wrap.rs`) and no PIN hash is stored; the Argon2 tag is the PIN verifier. The 128 bytes of OpenSK master keys
are derived from the seed in RAM after a correct PIN and dropped on USB reset / suspend / unplug. Resident
credentials are encrypted under keys derived from the master. The PIN retry counter (8 tries) is the vault's.

**Consequences:** after every USB reset the PIN must be entered once before *any* credential-ID operation works,
including U2F and `uv=discouraged` assertions. Without a PIN the seed is in clear in flash. `T_COST` is untuned:
time a PIN check on hardware. See `SECURITY.md`.

## OpenSK patch
`third_party/opensk-harden.patch` (applied by `build.sh`, or manually with `patch -p1 -d third_party/OpenSK <
third_party/opensk-harden.patch`) adds `Persist::unlock_with_pin` (default: legacy behaviour) and calls it in
`verify_pin_hash_enc`. Re-check it whenever `OPENSK_REV` changes.

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

**Hardening status:** `HardenPersist`, the vault and the patch were written without compiling. The first build
found three errors (a status-code name, `swap` on `thumbv6m` atomics, now `portable_atomic`), fixed in this tree;
the rest of the build is unconfirmed. Not yet tested: Argon2 timing and heap/RAM headroom, PIN set/change/verify on
hardware, resident credentials after reboot, power loss during setPIN/reset, lock on USB reset.

**Not done / unknown:**
* `cargo clippy -- --deny=warnings`, `cargo fmt --check` and the CI workflow were never run on this tree.
* No documented test matrix: which sites, PIN dialogs, U2F-only sites, resident keys, reset, power loss during a
  flash write, P-256 signing time, RAM headroom (128 KiB heap), and RNG health tests on a real ring oscillator.
* `build.sh` end to end, and U2F attestation provisioning.
* USB VID/PID (`0xc0de:0xcafe`) and strings are prototype placeholders (`src/usb/mod.rs`).
