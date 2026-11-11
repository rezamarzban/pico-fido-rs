# pico-fido-rs

A FIDO2 / U2F security key for the Raspberry Pi Pico (RP2040) with an ATECC608A secure element, written
in Rust with Embassy. The CTAP protocol is **Google's OpenSK library** (Apache-2.0, plus one 14-line patch); this
repository is the RP2040 platform layer around it. **Experimental. Read `SECURITY.md`.**

## What is where
| In the ATECC608A (`src/se/`) | On the Pico |
|---|---|
| 9 credential private keys, **one per site** (GenKey, ECDSA signing; unlimited signatures) and the site directory (data slot 13) | OpenSK with its standard key-value store (`src/env/persist.rs`, `flash_store.rs`) |
| 1 attestation private key (slot 0, created once) | ClientPIN, PIN hash, credential-ID encryption keys, resident credentials: all OpenSK standard |
| Public-key extraction | SHA-256 / HMAC / AES / HKDF / ECDH in software (`src/se/crypto.rs`) |
| Random (the only entropy source) | RNG = ChaCha20 DRBG seeded and re-seeded from the chip (`src/env/rng.rs`) |
| | BOOTSEL as user presence (`src/env/user_presence.rs`), USB HID (`src/usb/`, `src/env/hid.rs`) |

Chip details, wiring, slot layout and provisioning: `atecc608a/CONFIG.md`.

## Layout of the source
| Part | File |
|---|---|
| Main loop, flash layout constants | `src/main.rs` |
| `opensk::env::Env` for the Pico | `src/env/mod.rs` |
| Chip: protocol, commands, OpenSK `Ecdsa`, I2C bus | `src/se/{proto,chip,ecdsa,crypto,i2c}.rs` |
| Status display (optional, feature `oled`) | `src/oled.rs`, `src/status.rs` |

OpenSK blocks (waiting for the button, waiting for the chip), so it runs in thread mode. USB, the LED and
the packet pump run on a higher-priority interrupt executor (`SWI_IRQ_1`). OpenSK features: `ctap1` (U2F),
`config_command`, `software_crypto`. `use_batch_attestation` is off (see `src/env/mod.rs`).

## OpenSK version
Pinned in `third_party/OPENSK_REV` (`79e85b9a72a1ad99745e0d07aec9708d2f7ad6a9`) plus **one 14-line patch**,
`third_party/opensk-rp-hint.patch`: OpenSK tells the RNG which site (RP ID hash) a new key is for, so the chip
keeps one key per site (`src/se/ecdsa.rs`). It only adds two default methods to `Rng` and two calls; nothing else
changes. `build.sh`, `host-test/run.sh` and CI apply it with `sh third_party/apply-opensk-patch.sh` (safe to run again).

## Flash layout
The last **72 KiB** of flash (18 pages of 4 KiB, `STORE_PAGES`) are the OpenSK key-value store; `build.rs`
keeps them out of the linker's FLASH region and derives everything from the single `flash_*` feature.
This differs from the previous revision (which also had a vault and PUF sectors): **erase the whole flash
before the first install**; credentials of the old firmware are not usable anyway.

## Build
Needs the **nightly** pinned in `rust-toolchain.toml` and `flip-link`. Release builds are size-optimised.

    git submodule add --depth 1 https://github.com/google/OpenSK.git third_party/OpenSK
    git -C third_party/OpenSK fetch --depth 1 origin $(cat third_party/OPENSK_REV)
    git -C third_party/OpenSK checkout $(cat third_party/OPENSK_REV)
    sh third_party/apply-opensk-patch.sh          # the RP-hint patch

    cargo build --release                         # 2 MiB board, no USB serial number
    cargo build --release --no-default-features --features rp2040_board,flash_4m,usb_serial

Enable **exactly one** `flash_*` feature. `usb_serial` adds the flash unique ID as USB serial number (off by
default: it lets hosts recognise the device). `oled` (default) is an SSD1306 on I2C0 (SDA GP16, SCL GP17,
0x3C); build without it by leaving it out of `--features`. **Commit `Cargo.lock`** (none in this tree).
`build.sh [-s 2|4|8|16] [-u] [-O]` builds a UF2 from the repository (needs network).

## Provisioning the chip (once per chip)
See `atecc608a/CONFIG.md`: write and lock the configuration (`tools/gen_atecc_config.py`), then `tools/make_attest_cert.py` creates the attestation key in the chip and its self-signed
certificate, which is stored in the token once with OpenSK's `tools/configure.py`.

## Tests
    sh host-test/run.sh        # OpenSK's library unit tests + host-test/se (chip protocol, command layer,
                               # OpenSK ECDSA adapter incl. attestation slot, against a software chip model)
    python3 atecc608a/tools/test_gen_config.py
    python3 atecc608a/tools/make_attest_cert.py --selftest

## Verification status
**The `atecc1` code up to "OpenSK based ATECC support v2.1" was built and tested on browsers and operating
systems** (reported by the maintainer, not independently verified). **Not compiled by their author:** the later changes (unlimited signatures, no counters, keys never overwritten, the chip page of the
OLED, the Info/Read chip commands, one key per site). For the last one, `host-test/se` (26 tests, incl. the site directory against a
software chip model) and OpenSK's own unit tests (353 / 374, with the patch applied) were run on a host; the firmware itself
(thumbv6m, nightly) was not built and nothing was run on a real chip or in a browser. Build, then run `host-test/run.sh` and the acceptance test in
`atecc608a/CONFIG.md` on a spare chip before locking a chip you care about. USB VID/PID
(`0xc0de:0xcafe`) are prototype placeholders (`src/usb/mod.rs`).

`guide.md` is the user guide (udev rule, PIN, registering, LED).
