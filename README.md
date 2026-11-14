# pico-fido-rs

A FIDO2 / U2F security key for the Raspberry Pi Pico (RP2040) with an ATECC608A secure element, written
in Rust with Embassy. The CTAP protocol is **Google's OpenSK library** (Apache-2.0, plus one 14-line patch (+1 import)); this
repository is the RP2040 platform layer around it. **Experimental. Read `SECURITY.md`.**

## What is where
| In the ATECC608A (`src/se/`) | On the Pico |
|---|---|
| 9 credential private keys, **one per site** (GenKey, ECDSA signing; unlimited signatures). **Nothing else is stored in the chip** | OpenSK with its standard key-value store (`src/env/persist.rs`, `flash_store.rs`) and the **site directory** (which site owns which key slot, `src/env/dir_flash.rs`, `src/se/dirlog.rs`) |
| 1 attestation private key (slot 0, created once) | ClientPIN, PIN hash, credential-ID encryption keys, resident credentials: all OpenSK standard |
| Public-key extraction | SHA-256 / HMAC / AES / HKDF / ECDH in software (`src/se/crypto.rs`) |
| Random (the only entropy source) | RNG = HMAC-DRBG (SP 800-90A, SHA-256) seeded and re-seeded from the chip (`src/env/rng.rs`) |
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
Pinned in `third_party/OPENSK_REV` (`f53621c33a02eee001cae82a87aa719fca61565b`, "Allow custom PIN hash verification (#836)", 2026-11-09) plus **one 14-line patch (+1 import)**,
`third_party/opensk-rp-hint.patch`: OpenSK tells the RNG which site (RP ID hash) a new key is for, so the chip
keeps one key per site (`src/se/ecdsa.rs`). It only adds two default methods to `Rng` and two calls; nothing else
changes. `build.sh`, `host-test/run.sh` and CI apply it with `sh third_party/apply-opensk-patch.sh` (safe to run again).

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

* **Key.** The first 1 KiB of RAM is carved out of the linker's RAM (`build.rs`) and never written. Its power-up
  pattern is turned into a 256-bit secret by a code-offset fuzzy extractor (31x repetition, helper data in the helper
  sector). Root key = HMAC-SHA-256(secret, label); per area two keys are derived from it (AES-256 key and a nonce key).
  The root key is never stored: it is rebuilt from the RAM for every flash operation and wiped.
* **Format.** `nonce(12) || ciphertext || tag(16)`; associated data = store key id / record position. Nonces are
  derived (HMAC of the data), so no counter or RNG is needed and a nonce is never used for two different messages.
* **First start.** With an erased helper sector the firmware wipes store, directory and counter (an older firmware left
  plaintext there), then writes the helper sector (the commit). This needs a **power-on reset: unplug the key and plug it
  in again after flashing**; otherwise the LED shows 3 short blinks + pause and nothing runs. The same blink means
  "no usable key" later (damaged helper sector, sample does not decode: re-plug; still failing: erase the flash).
* **Upgrading** from an unencrypted build: erase the whole flash first (BOOTSEL `flash_nuke.uf2`). Credentials of the old
  firmware are not kept; the chip's keys stay and are taken over again (see "Key slots"). Directory capacity: unchanged.
* Limits: a sealed large-blob shard (1023 bytes plain) does not fit one store entry (1023 bytes max), so it is split
  over two entries in one store transaction; any other value over 994 bytes is refused; key ids and value sizes
  are visible; no rollback protection. See `SECURITY.md`.

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
systems** (reported by the maintainer, not independently verified). **Flash encryption (AES-256-GCM, SRAM PUF) was written without a compiler and has not been built, run on a Pico or tested on real SRAM; its host tests (`host-test/se`, incl. known-answer vectors from `host-test/seal_ref.py`) have not been run either. Check the logged `puf: ... bit errors` on your chip first.** **Not compiled by their author:** the later changes (unlimited signatures, no counters, keys never overwritten, the chip page of the
OLED, the Info/Read chip commands, one key per site, **and the move of the site directory from chip slot 13 to the Pico's flash with taking over existing keys**; the
latter was written without a compiler and has not been built or run). `host-test/se` (the directory tests use a two-sector flash model and a `DirStore`, and cut the power after every step of every kind of update and in the middle of every program/erase step; run them to see the current count) and OpenSK's own unit tests (353 / 374, with the patch applied) were run on a host; the firmware itself
(thumbv6m, nightly) was not built and nothing was run on a real chip or in a browser. Build, then run `host-test/run.sh` and the acceptance test in
`atecc608a/CONFIG.md` on a spare chip before locking a chip you care about. USB VID/PID
(`0xc0de:0xcafe`) are prototype placeholders (`src/usb/mod.rs`).

`guide.md` is the user guide (udev rule, PIN, registering, LED).

## OpenSK update (f53621c, 2026-11-09)
Moved from `79e85b9` (31 commits). What changed for this project: OpenSK now uses the RustCrypto "0.11 generation"
(`rand_core` 0.10, `sha2` 0.11, `hmac` 0.13, `aes` 0.9, `p256` 0.14) and `EcSecretKey::random` / `sign` return
`Result` (#835): the chip adapter returns an error instead of panicking (no free slot, chip not answering, directory not
saveable), the RNG is now an HMAC-DRBG on the `TryRng` API (no `rand_chacha`), `third_party/opensk-rp-hint.patch` was
regenerated, `max_large_blob_array_size` is gone (shards are fixed: 4 x 1023 bytes), `decrypt_pin_hash` became
`verify_pin_hash` (default used, nothing to do), and the pinned nightly is `nightly-2026-10-02`. `aes-gcm` stays on 0.10
(its own `aes` 0.8 next to OpenSK's 0.9). **Not built**: Embassy 0.6 / embassy-rp 0.2 may not build on this nightly.
