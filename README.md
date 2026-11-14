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
| Site directory in the Pico's flash | `src/se/dirlog.rs` (two-sector copy-on-write format, plaintext page image), `src/env/dir_flash.rs` (sealed flash access) |
| Flash encryption | `src/seal.rs` (AES-256-GCM), `src/sealed_log.rs` (log pages <-> sealed sectors), `src/puf.rs` (SRAM PUF key), `src/layout.rs` |
| Status display (optional, feature `oled`) | `src/oled.rs`, `src/status.rs` |

OpenSK blocks (waiting for the button, waiting for the chip), so it runs in thread mode. USB, the LED and
the packet pump run on a higher-priority interrupt executor (`SWI_IRQ_1`). OpenSK features: `ctap1` (U2F),
`config_command`, `software_crypto`. `use_batch_attestation` is off (see `src/env/mod.rs`).

## OpenSK version
Pinned in `third_party/OPENSK_REV` (`f53621c33a02eee001cae82a87aa719fca61565b`, "Allow custom PIN hash verification
(#836)") plus **one 14-line patch**,
`third_party/opensk-rp-hint.patch`: OpenSK tells the RNG which site (RP ID hash) a new key is for, so the chip
keeps one key per site (`src/se/ecdsa.rs`). It only adds two default methods to `Rng` and two calls; nothing else
changes. This revision has OpenSK's fallible `EcSecretKey::random` / `sign` (#835), which `src/se/ecdsa.rs` uses to
answer a refused registration or signature with a CTAP error instead of stopping, and `rand_core` 0.10 (`src/env/rng.rs`).
`build.sh`, `host-test/run.sh` and CI apply it with `sh third_party/apply-opensk-patch.sh` (safe to run again).

## Flash layout and encryption
Everything sensitive in the Pico's flash is encrypted with **AES-256-GCM**; the key comes from the **SRAM PUF**
(`src/puf.rs`, `src/seal.rs`, `src/sealed_log.rs`, `src/layout.rs`). The last **104 KiB** of flash are kept out of the
linker's FLASH region by `build.rs`. From the end of flash downwards:

| Area | Size | Content |
|---|---|---|
| OpenSK key-value store | 72 KiB | **every value sealed** (PIN hash, master keys, resident credentials, attestation certificate, counters), `src/env/persist.rs` |
| Site directory sectors A, B | 2 x 8 KiB | **every record sealed** (chip serials, site hashes), `src/env/dir_flash.rs` |
| Signature counter | 12 KiB | **every record sealed**, `src/env/tally_flash.rs` |
| SRAM-PUF helper data | 4 KiB | public by design (useless without this chip's SRAM pattern) |

* **Key.** 4 KiB at the TOP of the striped SRAM (0x2003F000..0x20040000) are carved out of the linker's RAM
  (`build.rs`) and never written (at the top so that flip-link's stack, at the bottom of RAM, still faults on overflow).
  Their power-up pattern is turned into a 256-bit secret by a code-offset fuzzy extractor (`src/puf_code.rs`): cell pairs
  are XORed first (this removes most of an SRAM bias: 60 % ones becomes 48 %), then a 63x repetition code with
  bit-sliced majority decoding; the helper data is in the helper sector. A sample whose pair stream is outside 46..54 %
  ones is refused at enrolment (a biased chip would give a weaker secret, see SECURITY.md). Root key =
  HMAC-SHA-256(secret, label); per area two keys are derived from it (AES-256 key and a nonce key). The root key is never
  stored: it is rebuilt from the RAM for every flash operation and wiped.
* **Format.** `nonce(12) || ciphertext || tag(16)`; associated data = store key id / record position. Nonces are
  derived (HMAC of the data), so no counter or RNG is needed and a nonce is never used for two different messages.
* **First start.** With an erased helper sector the firmware wipes store, directory and counter (an older firmware left
  plaintext there), then writes the helper sector (the commit). This needs a **power-on reset: unplug the key and plug it
  in again after flashing**; otherwise the LED shows 3 short blinks + pause and nothing runs. The same blink means
  "no usable key" later (damaged helper sector, sample does not decode: re-plug; still failing: erase the flash).
* **Upgrading** from an unencrypted build, or from an earlier encrypted one (the helper format is now `PUF3`, 4 KiB of RAM,
  and the store entries have a new format): erase the whole flash first (BOOTSEL `flash_nuke.uf2`). Credentials of the old
  firmware are not kept; the chip's keys stay and are taken over again (see "Key slots"). Directory capacity: unchanged.
* Values: one store entry holds 994 bytes of plaintext once sealed; a longer value (OpenSK's 1023-byte large-blob
  shards) is split over two entries (the second at key + 2048, one store transaction, `src/spill.rs`), up to 1988 bytes.
  Key ids and value sizes are visible; no rollback protection. See `SECURITY.md`.

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
systems** (reported by the maintainer, not independently verified). Everything after it, including the flash
encryption, was checked like this (stable Rust 1.99 with `RUSTC_BOOTSTRAP=1`, `-Zbuild-std=core,alloc`, no nightly pin):

* `cargo check`, `cargo clippy -- --deny=warnings` and `cargo build --release` for `thumbv6m-none-eabi` pass (linked with
  `rust-lld`; flip-link is not installed in that setup); the image is about 230 KB, `.data`+`.bss` end well below the
  PUF region, and `rustfmt --check` is clean.
* `host-test/se` (67 tests): the chip model and the OpenSK adapter, the two-sector directory with the power cut after
  every step and in the middle of every program/erase step, the sealed log layouts with known-answer vectors from
  `host-test/seal_ref.py`, the PUF arithmetic (bit-sliced majority against a naive one, noise at 10 %, bias
  refusal) and the long-value splitting.
* OpenSK's own unit tests pass at the pinned revision with the patch applied (350, and 401 with `config_command,ctap1`).
* **Not done:** nothing was run on a Pico, a real ATECC608A or real SRAM. **Before relying on the flash encryption, flash a spare Pico and
  read the `puf: ... bit errors ... ones: raw ... pairs ...` line at several boots, temperatures and on several
  boards:** the sample must stay near 50 % pairs and the error rate well below 10 %.
Run `host-test/run.sh` and the acceptance test in `atecc608a/CONFIG.md` on a spare chip before locking a chip you care
about. USB VID/PID (`0xc0de:0xcafe`) are prototype placeholders (`src/usb/mod.rs`).

`guide.md` is the user guide (udev rule, PIN, registering, LED).
