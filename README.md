# pico-fido-rs

A FIDO2 / U2F security key for the Raspberry Pi Pico (RP2040) with an ATECC608A secure element, written
in Rust with Embassy. The CTAP protocol is **Google's OpenSK library** (Apache-2.0, unmodified); this
repository is the RP2040 platform layer around it. **Experimental. Read `SECURITY.md`.**

## What is where
| In the ATECC608A (`src/se/`) | On the Pico |
|---|---|
| 7 credential private keys (GenKey, ECDSA signing, signature limit by the chip counter) | OpenSK with its standard key-value store (`src/env/persist.rs`, `flash_store.rs`) |
| 1 attestation private key (created once, no signature limit) | ClientPIN, PIN hash, credential-ID encryption keys, resident credentials: all OpenSK standard |
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
Pinned in `third_party/OPENSK_REV` (`79e85b9a72a1ad99745e0d07aec9708d2f7ad6a9`) and used **unpatched**.

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

    cargo build --release                         # 2 MiB board, no USB serial number
    cargo build --release --no-default-features --features rp2040_board,flash_4m,usb_serial

Enable **exactly one** `flash_*` feature. `usb_serial` adds the flash unique ID as USB serial number (off by
default: it lets hosts recognise the device). `oled` (default) is an SSD1306 on I2C0 (SDA GP16, SCL GP17,
0x3C); build without it by leaving it out of `--features`. **Commit `Cargo.lock`** (none in this tree).
`build.sh [-s 2|4|8|16] [-u] [-O]` builds a UF2 from the repository (needs network); its default `-b` is `openSK-based-se5` (a different firmware), so pass `-b atecc0`.

## Provisioning the chip (once per chip)
See `atecc608a/CONFIG.md`: write and lock the configuration (`tools/gen_atecc_config.py`), set the signature
budget, then `tools/make_attest_cert.py` (**this script is not in the repository**: `atecc608a/tools/` has only `gen_atecc_config.py` and `test_gen_config.py`, so the attestation step cannot be run as written) creates the attestation key in the chip and its self-signed
certificate, which is stored in the token once with OpenSK's `tools/configure.py`.

## Tests
    sh host-test/run.sh        # OpenSK's library unit tests + host-test/se (chip protocol, command layer,
                               # OpenSK ECDSA adapter incl. attestation slot, against a software chip model)
    python3 atecc608a/tools/test_gen_config.py
    # atecc608a/tools/make_attest_cert.py --selftest: script missing from this tree

## Verification status
**This revision was not compiled.** The firmware, `host-test/se` and the OpenSK interplay were edited
without a Rust toolchain and without the OpenSK sources at hand. The two Python tools were run. Before
anything else: build, run `host-test/run.sh`, then the acceptance test in `atecc608a/CONFIG.md` on a spare
chip. Never tested on hardware: the chip commands, attestation through OpenSK's attestation store with a
handle instead of a private key, the RNG (re-seed timing), the OLED lines. USB VID/PID (`0xc0de:0xcafe`)
are prototype placeholders (`src/usb/mod.rs`).

`guide.md` is the user guide (udev rule, PIN, registering, LED).
