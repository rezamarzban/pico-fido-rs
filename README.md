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
| Flash encryption | `src/seal.rs` (AES-256-GCM), `src/sealed_log.rs` (log pages <-> sealed sectors), `src/puf.rs` (SRAM PUF key), `src/puf_backup.rs` + `src/env/backup_flash.rs` (backup of the PUF secret), `src/layout.rs` |
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
(`src/puf.rs`, `src/seal.rs`, `src/sealed_log.rs`, `src/layout.rs`). The last **120 KiB** of flash are kept out of the
linker's FLASH region by `build.rs`. From the end of flash downwards:

| Area | Size | Content |
|---|---|---|
| OpenSK key-value store | 72 KiB | **every value sealed** (PIN hash, master keys, resident credentials, attestation certificate, counters), `src/env/persist.rs` |
| Site directory sectors A, B | 2 x 8 KiB | **every record sealed** (chip serials, site hashes), `src/env/dir_flash.rs` |
| Signature counter, region A | 12 KiB | **every record sealed**, `src/env/tally_flash.rs` (copy-on-write between regions A and B, like the directory: a power cut never loses the counts) |
| SRAM-PUF helper data | 4 KiB | public by design (useless without this chip's SRAM pattern) |
| Backup of the PUF secret | 4 KiB | one sealed record per chip, `src/puf_backup.rs` (see below); below the helper sector, so the first-start wipe never touches it |
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
  command in HMAC mode, the same as `hmac-dgst` of atecc-util-py; the key never leaves the chip). That key comes from the
  chip's own RNG and is written once: by the firmware itself the first time it finds slot 11 blank (all zeros or all
  ones; possible only while the chip lets a clear write through, i.e. before the data zone is locked, and checked by
  comparing the chip's HMAC with the software HMAC of the key), or beforehand with `hmac-write-key 11 0 key_file` of atecc-util-py.
  Every time a NEW backup record is about to be written (first record of a chip, or after a re-enrolment), slot 11 first
  gets a **new random key** (`rotate_backup_key`, proven with the chip's HMAC) and the record is sealed under it; the old
  key is not used again, so older records of that chip can no longer be opened. If the slot cannot be rewritten (e.g. data
  zone locked), the current key is used for that record. A start that needs no new record writes nothing. A blank slot that cannot be written means no backup (the OLED says
  NO HMAC KEY), because a blank slot would give a known constant. One record per chip (55 fit). If a later start cannot
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
  "no usable key" later (damaged