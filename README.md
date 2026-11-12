# pico-fido-rs

A FIDO2 / U2F security key for the Raspberry Pi Pico (RP2040) with an ATECC608A secure element, written
in Rust with Embassy. The CTAP protocol is **Google's OpenSK library** (Apache-2.0, plus one 14-line patch); this
repository is the RP2040 platform layer around it. **Experimental. Read `SECURITY.md`.**

## What is where
| In the ATECC608A (`src/se/`) | On the Pico |
|---|---|
| 9 credential private keys, **one per site** (GenKey, ECDSA signing; unlimited signatures). **Nothing else is stored in the chip** | OpenSK with its standard key-value store (`src/env/persist.rs`, `flash_store.rs`) and the **site directory** (which site owns which key slot, `src/env/dir_flash.rs`, `src/se/dirlog.rs`) |
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
| Site directory in the Pico's flash | `src/se/dirlog.rs` (two-sector copy-on-write format), `src/env/dir_flash.rs` (flash access) |
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
The last **84 KiB** of flash are kept out of the linker's FLASH region by `build.rs` (derived from the single `flash_*`
feature). From the end of flash downwards: **72 KiB** (18 pages of 4 KiB, `STORE_PAGES`) are the OpenSK key-value store;
**4 KiB** site directory sector A (`src/env/dir_flash.rs`); **4 KiB** signature counter (`src/env/tally_flash.rs`);
**4 KiB** site directory sector B. The directory is two sectors because it is updated copy-on-write: a compaction
writes the complete new directory into the inactive sector and only then makes it the active one (generation number in
its header, written last), so a power failure can never leave an empty or truncated directory (`src/se/dirlog.rs`).
The directory sectors are not part of the store: OpenSK's reset and the store's format never touch them. Erasing the
whole flash clears them too (see "Key slots" below).
This differs from the previous revision (which also had a vault and PUF sectors): **erase the whole flash
before the first install**; credentials of the old firmware are not usable anyway. The directory record format also
changed (16-byte site tag, two sectors): a directory written by an earlier build is not read.

## Key slots (one key per site)
The site directory (which site owns which of the 9 credential slots) is in the Pico's flash, not in the chip. For a
site that has no slot yet, `se/ecdsa.rs` takes, in this order: (1) the first slot that already **holds a private key**
and belongs to no other site (the key is used as it is, no GenKey); (2) otherwise the first **empty** slot, where it runs
GenKey. Slots owned by another site are never touched. A power failure cannot lose the directory (see above). If it is lost anyway (flash erased from outside), the keys are still in
the chip and are taken over again, one per site, in slot order; credentials registered earlier keep working (their
credential ID names the slot), but a site may then end up with another site's old key (see `SECURITY.md`).

## Several chips
Every ATECC608A has a unique 9-byte serial number. The Pico's flash keeps the **site directory** and the **signature count**
separately for each serial number (`src/se/dirlog.rs`, `src/se/tallylog.rs`). The serial is read from the chip at start-up
(and again before each new registration), and from then on that chip's own information is used; swapping the chip
(with the key unplugged) switches to the information of the chip that is now connected, and a chip that was never seen
starts empty. Up to 14 completely used chips fit in a directory sector (127 records); the signature log keeps the 32 chips
with the highest totals. The OLED chip page shows the serial of the chip that is in use.
What is NOT per chip: the PIN, the credential-ID encryption keys and resident credentials are OpenSK's single store.
A credential made with chip A cannot sign while chip B is connected (the handle in its credential ID names a key B does
not have); it works again when A is back. After updating from a build with the single-chip pages, the directory and the
count start empty once (the keys stay in the chip and are taken over again, see above).

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
OLED, the Info/Read chip commands, one key per site, **and the move of the site directory from chip slot 13 to the Pico's flash with taking over existing keys**; the
latter was written without a compiler and has not been built or run). `host-test/se` (the directory tests use a two-sector flash model and a `DirStore`, and cut the power after every step of every kind of update and in the middle of every program/erase step; run them to see the current count) and OpenSK's own unit tests (353 / 374, with the patch applied) were run on a host; the firmware itself
(thumbv6m, nightly) was not built and nothing was run on a real chip or in a browser. Build, then run `host-test/run.sh` and the acceptance test in
`atecc608a/CONFIG.md` on a spare chip before locking a chip you care about. USB VID/PID
(`0xc0de:0xcafe`) are prototype placeholders (`src/usb/mod.rs`).

`guide.md` is the user guide (udev rule, PIN, registering, LED).
