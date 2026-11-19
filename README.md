# pico-fido-rs

A FIDO2 / U2F security key for the Raspberry Pi Pico (RP2040) with an ATECC608A secure element, written
in Rust with Embassy. The CTAP protocol is **Google's OpenSK library** (Apache-2.0, plus one small patch); this
repository is the RP2040 platform layer around it. **Experimental. Read `SECURITY.md`.**

The optional carrier-board design and wiring are documented in [PCB/HARDWARE.md](PCB/HARDWARE.md).

## What is where
| In the ATECC608A (`src/se/`) | On the Pico |
|---|---|
| 9 credential private keys, **one per site** (GenKey, ECDSA signing; unlimited signatures) | OpenSK with its key-value store (`src/env/persist.rs`, `flash_store.rs`) and the **site directory** (which site owns which key slot, `src/env/dir_flash.rs`, `src/se/dirlog.rs`); both are sealed in flash |
| 1 attestation private key (slot 0, created once) | ClientPIN, PIN hash, credential-ID encryption keys, resident credentials: all OpenSK standard |
| HMAC key for the PUF-secret backup (data slot 11, when provisioned) | Sealed PUF backup records and signature tallies |
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
| Flash encryption | `src/seal.rs` (AES-256-GCM), `src/sealed_log.rs` (log pages <-> sealed sectors), `src/puf.rs` (SRAM PUF key), `src/puf_backup.rs` + `src/env/backup_flash.rs` (backup of the PUF secret), `src/layout.rs` |
| Status display (optional, feature `oled`) | `src/oled.rs`, `src/status.rs` |

OpenSK blocks (waiting for the button, waiting for the chip), so it runs in thread mode. USB, the LED and
the packet pump run on a higher-priority interrupt executor (`SWI_IRQ_1`). OpenSK features: `ctap1` (U2F),
`config_command`, `software_crypto`. `use_batch_attestation` is off (see `src/env/mod.rs`).

## OpenSK version
Pinned in `third_party/OPENSK_REV` (`f53621c33a02eee001cae82a87aa719fca61565b`, "Allow custom PIN hash verification
(#836)") plus **one small patch** (12 added lines in three OpenSK files),
`third_party/opensk-rp-hint.patch`: OpenSK tells the RNG which site (RP ID hash) a new key is for, so the chip
keeps one key per site (`src/se/ecdsa.rs`). It only adds two default methods to `Rng` and two calls; nothing else
changes. This revision has OpenSK's fallible `EcSecretKey::random` / `sign` (#835), which `src/se/ecdsa.rs` uses to
answer a refused registration or signature with a CTAP error instead of stopping, and `rand_core` 0.10 (`src/env/rng.rs`).
`build.sh`, `host-test/run.sh` and CI apply it with `sh third_party/apply-opensk-patch.sh` (safe to run again).

## Flash layout and encryption
Everything sensitive in the Pico's flash is encrypted with **AES-256-GCM**; the key comes from the **SRAM PUF**
(`src/puf.rs`, `src/seal.rs`, `src/sealed_log.rs`, `src/layout.rs`). The last **120 KiB** of flash are kept out of the
linker's FLASH region by `build.rs`. From the end of flash downwards:

| Area | Size | Content |
|---|---|---|
| OpenSK key-value store | 72 KiB | **every value sealed** (PIN hash, master keys, resident credentials, attestation certificate, counters), `src/env/persist.rs` |
| Site directory sectors A, B | 2 x 8 KiB | **every record sealed** (chip serials, site hashes), `src/env/dir_flash.rs` |
| Signature counter, region A | 12 KiB | **every record sealed**, `src/env/tally_flash.rs` (copy-on-write between regions A and B; a signature interrupted before its count is committed may be missing) |
| SRAM-PUF helper data | 4 KiB | public by design (useless without this chip's SRAM pattern) |
| Backup of the PUF secret | 4 KiB | sealed backup records, `src/puf_backup.rs` (see below); below the helper sector, so the first-start wipe never touches it |
| Signature counter, region B | 12 KiB | as region A; lies below the backup so that the helper and the backup keep their place; the first-start wipe erases it explicitly |

* **Key.** 4 KiB at the TOP of the striped SRAM (0x2003F000..0x20040000) are carved out of the linker's RAM
  (`build.rs`) and never written (at the top so that flip-link's stack, at the bottom of RAM, still faults on overflow).
  Their power-up pattern is turned into a 256-bit secret by a code-offset fuzzy extractor (`src/puf_code.rs`): cell pairs
  are XORed first (this removes most of an SRAM bias: 60 % ones becomes 48 %), then a 63x repetition code with
  bit-sliced majority decoding; the helper data is in the helper sector. A sample whose pair stream is outside 46..54 %
  ones is refused at enrolment (a biased chip would give a weaker secret, see SECURITY.md). Root key =
  HMAC-SHA-256(secret, label); per area two keys are derived from it (AES-256 key and a nonce key). The root key is never
  stored: it is rebuilt from the RAM for every flash operation and wiped.
* **Backup of the PUF secret.** Whenever the PUF works and the connected chip can give its **backup key**, the PUF secret
  is also written once to the backup sector: AES-256-GCM sealed with a key derived (SHA-256) from an **HMAC digest computed
  inside the chip**: HMAC-SHA-256 of a fixed challenge with a random 32-byte key kept in the chip's data slot 11 (the SHA
  command in HMAC mode, the same as `hmac-dgst` of atecc-util-py; the key cannot be read back out of the chip). That key comes from the
  chip's own RNG and is written once: by the firmware itself the first time it finds slot 11 blank (all zeros or all
  ones; possible only while the chip lets a clear write through, i.e. before the data zone is locked, and checked by
  comparing the chip's HMAC with the software HMAC of the key), or beforehand with `hmac-write-key 11 0 key_file` of atecc-util-py.
  Every time a NEW backup record is written (first record of a chip, or after a re-enrolment) slot 11 gets a **new random
  key**, in a power-fail safe order: the new key is drawn (its digest is computed in software), the record sealed under it is
  written to flash and read back, and only then the key is written into the chip and checked with the chip's HMAC. A power cut
  in between leaves the old key and the old record usable. The old key is not used again; older records of that chip no longer
  open and stay in the sector as dead records (they use up room, and the OLED chip count may count a chip more than once).
  If the slot cannot be rewritten (e.g. data zone locked), the record is written again under the key that is in the chip. A start that needs no new record writes nothing. With fewer than two free records the key is not replaced (the record is written under the current key).
  **A backup sector with unknown or damaged content is never erased** (it could still hold other chips' records): no
  backup is written (the OLED shows the backup error) and, if the PUF helper is also blank, start-up halts instead of
  wiping; erase the whole flash (BOOTSEL `flash_nuke.uf2`) to start over. Blank, half-formatted and older-format sectors are formatted as before; "older format" means the complete 16-byte header of the old format, not just its magic (a current sector whose version byte got damaged is `Damaged` and never erased). A blank slot that cannot be written means no backup (the OLED says
  NO HMAC KEY), because a blank slot would give a known constant. The sector holds 55 records total, including records made obsolete by key rotation. If a later start cannot
  read the PUF (the sample does not decode, the helper sector is damaged or erased), connecting any chip that has a record
  brings the secret back and with it every key; if the sample allows it (power-on reset, balanced pattern) a new helper
  sector is written from the current power-up pattern, so the next starts use the PUF again, otherwise the secret stays in
  RAM for that power cycle. Nothing is wiped on this path. A blank helper sector with records of *other* chips only (or
  an unreadable backup) halts instead of wiping. **Trade-off:** the secret is the same for every chip, so anyone who
  holds the Pico's flash AND any ONE chip with a record (the board is enough: it answers HMAC to anyone who asks) opens
  the backup and then everything (`SECURITY.md`); a copy of the flash alone, or public data such as the attestation
  certificate, does not.
* **Format.** `nonce(12) || ciphertext || tag(16)`; associated data = store key id / record position. Nonces are
  derived (HMAC of the data), so no counter or RNG is needed and a nonce is never used for two different messages.
* **First start.** With an erased helper sector the firmware wipes store, directory and counter (an older firmware left
  plaintext there), then writes the helper sector (the commit). This needs a **power-on reset: unplug the key and plug it
  in again after flashing**; otherwise the LED shows 3 short blinks + pause and nothing runs. The same blink means
  "no usable key" later (damaged helper sector, sample does not decode and the connected chip has no backup record: re-plug,
  or connect a chip that has one; still failing: erase the flash). The OLED then stays on its SRAM PUF page and says why.
* **Upgrading** from an unencrypted build, or from an earlier encrypted one (the helper format is now `PUF3`, 4 KiB of RAM,
  and the store entries have a new format): erase the whole flash first (BOOTSEL `flash_nuke.uf2`). Credentials of the old
  firmware are not kept; the chip's keys stay in their slots and are regenerated by new sites (see "Key slots"). Directory capacity: unchanged.
* Values: one store entry holds 994 bytes of plaintext once sealed; a longer value (OpenSK's 1023-byte large-blob
  shards) is split over two entries (the second at key + 2048, one store transaction, `src/spill.rs`), up to 1988 bytes.
  Key ids and value sizes are visible; no rollback protection. See `SECURITY.md`.

## Key slots (one key per site)
The site directory (which site owns which of the 9 credential slots) is in the Pico's flash, not in the chip. For a
site that has no slot yet, `se/ecdsa.rs` takes, in this order: (1) the first slot that already **holds a private key**
and belongs to no other site: GenKey runs there and the old key is discarded (never used); (2) otherwise the first
**empty** slot, where it runs GenKey as well. Slots owned by another site are never touched. A power failure cannot lose the directory (see above). If it is lost anyway (flash erased from outside), the slots still hold
keys but belong to nobody, so new sites get those slots in order with NEW keys (GenKey). Credentials registered earlier
in such a slot stop working (their key is gone); see `SECURITY.md`.

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
count start empty once (the keys stay in the chip; new sites regenerate them, see above).

## Build
Needs the **nightly** pinned in `rust-toolchain.toml` and `flip-link`. Release builds are size-optimised.

    sh third_party/fetch-opensk.sh               # fetch the pinned OpenSK commit
    sh third_party/apply-opensk-patch.sh          # the RP-hint patch

    cargo build --release --locked                # 2 MiB board, no USB serial number
    cargo build --release --locked --no-default-features --features rp2040_board,flash_4m,usb_serial

Enable **exactly one** `flash_*` feature. `usb_serial` adds the flash unique ID as USB serial number (off by
default: it lets hosts recognise the device). `oled` (default) is an SSD1306 on I2C0 (SDA GP16, SCL GP17,
0x3C); build without it by leaving it out of `--features` with `--no-default-features`. The root `Cargo.lock` is committed.
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
The maintainer reports that every `atecc1` firmware revision was tested on all browsers and operating systems.
No version-by-platform test matrix was supplied, and these results have not been independently reproduced.
The PCB commit contains design files only; it does not change the tested v6.5 firmware.

Host-model coverage includes the chip adapter, flash interruption handling, sealing, PUF decoding, large-value
splitting and backups. Compatibility testing does not establish real-SRAM reliability across boards and conditions,
hardware power-loss behavior, or a security audit. Before relying on the encryption, check PUF logs over multiple
cold boots and on your target boards. Run `sh host-test/run.sh` and the [chip acceptance tests](atecc608a/CONFIG.md)
on a spare chip before locking hardware. The USB VID/PID (`0xc0de:0xcafe`) are prototype placeholders.

`guide.md` is the user guide (udev rule, PIN, registering, LED).
