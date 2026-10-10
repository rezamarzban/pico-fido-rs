# pico-fido-rs

A FIDO2 / U2F security key for the Raspberry Pi Pico (RP2040), written in Rust with Embassy.
**Experimental. Nothing here is audited. Read the `SECURITY.md` of the
branch you use before relying on it.**

**Hardware testing (reported by the maintainer, not independently verified):** every branch except the ATECC branches was built, flashed to a Raspberry Pi Pico and tested. The OpenSK-based branches (`openSK-based`, `-se0` .. `-se5`) were tested and work on **Linux, Windows and Android** browsers; the `se-harden*` branches were tested and work on **Linux only**. The `atecc1` branch was built and tested on **all browsers and operating systems**. None of the other ATECC branches (`atecc0`, `atecc-se0` .. `atecc-se3`, `atecc-support`) was compiled or run.

This branch (`main`) carries no firmware documentation of its own, but it is **not empty**: it still holds the earliest custom firmware (stateless ES256 credentials from one 32-byte master key kept in plain flash, in the last 4 KiB of a 2 MiB chip; no PIN, no resident keys; a USB keyboard HID interface next to the FIDO one; no `flash_*` features, no `build.sh`). The `build.sh` scripts of the other branches default to `-b main`, which does not build (no `flash_*` features): always pass `-b <branch>`. The documented work lives in the branches below;
each has its own `README.md` / `SECURITY.md` / `REVIEW.md` (some also `guide.md`; `atecc-se0` and `atecc-support` only have `README-ATECC.md`; the other ATECC branches also keep `atecc608a/CONFIG.md`).

| Branch | What it is |
|--------|------------|
| `openSK-based` | RP2040 platform layer around Google's OpenSK (Apache-2.0). Key material and PIN hash are stored in clear in flash. The maintainer reports it working on Linux, Windows and Android. |
| `openSK-based-se0` | Adds a PIN-wrapped master-seed vault (Argon2id). Built and tested on a Pico. |
| `openSK-based-se1` | Adds a RAM guard (XOR shares of the seed), USB-cancellation handling and vault-update checks. Built and tested on a Pico. |
| `openSK-based-se2` | Adds binding of the vault seed to the chip's SRAM power-up pattern (PUF). Built and tested on a Pico. |
| `se-harden0` .. `se-harden3` | The earlier custom CTAP implementation (stateless credentials, no resident keys, no U2F). `se-harden0`: no PIN. `se-harden1`: review round 2 fixes. `se-harden2`: ClientPIN with an Argon2id-wrapped master key. `se-harden3`: further fixes, `build.sh`, `guide.md`. Tested on a Pico on Linux only (not Windows or Android). |
| `openSK-based-se3` | PUF fail-closed behaviour: enrolment gating, HMAC-tagged PUF-masked records, `MAX_T_COST` bound, LED fault pattern (3 short blinks). No `Cargo.lock` is committed. |
| `openSK-based-se4` | Two PUF helper slots with commit (power-cut safe re-enrolment), setPIN/migration repairs, atomic USB reset handling, `flip-link` stack protection, optional `watchdog` and `stack_probe` features. Flash: 72 KiB store + 8 KiB PUF + 12 KiB vault. |
| `openSK-based-se5` | Adaptive RAM-guard refresh in short critical sections, stack scrubbing (`scrub.rs`), `wfi` idle, optional SSD1306 status display (`oled`, default). |
| `atecc-support`, `atecc-se0` | Variants that keep the private keys in an ATECC608. Not compiled or run by the author. |
| `atecc-se1` | `openSK-based-se5` plus the default `se_atecc` feature: 8 credential keys, signature budget (LimitedUse + Counter 0) and TRNG in an ATECC608A. Software parts unchanged. Not compiled or run. |
| `atecc-se2`, `atecc-se3` | As `atecc-se1` with 7 credential slots and an optional chip-side PIN (`se_pin`, off by default). `atecc-se3` adds `table.md` (what is in the chip and what is not). Not compiled or run. |
| `atecc0` | Slimmed ATECC608A firmware on unpatched OpenSK: 7 credential keys + attestation slot 7, signature budget, PIN hash in the clear on the Pico (no vault, PUF or RAM guard). Not compiled. |
| `atecc1` | As `atecc0` with 9 credential slots (1-9), attestation key in slot 0 and no signature limit; OLED shows chip status. Built and tested on all browsers and operating systems. |

`openSK-based/REVIEW.md` records why the project moved from the custom implementation to OpenSK: the custom firmware
worked in Linux browsers but not on Windows and Android, and the cause was never established.

Usage guides: `guide.md` in `openSK-based`, `openSK-based-se0` .. `openSK-based-se5`, `atecc0`, `atecc1`, `atecc-se1` .. `atecc-se3` and
`se-harden3`. Try any build on a throwaway account (for example https://webauthn.io) first.

# Project Changelog & Branch History

> Note: `openSK-based` branches from the "basic edition" commit (`9aa7f6b`), not from `se-harden3`.
> The `se-harden*` chain and the `openSK-based*` chain are two separate lines of development.

## Line 1: custom firmware

### main -> se-harden0
- **CBOR hardening:** strict central validation (`cbor::validate`): minimal encodings, no duplicate keys, nesting limits, no trailing bytes, UTF-8 checks.
- **CTAP/CTAPHID parsing fixes:** stricter request handling in `ctap.rs` and `ctaphid.rs`.
- **Key store:** crash-safe two-slot key storage (`store.rs`) with an integrity hash and write-then-verify.
- **Housekeeping:** removed `usb/hid.rs`; added `SECURITY.md`, `REVIEW.md`, CI workflow and host tests.

### se-harden0 -> se-harden1 (review round 2)
- `getAssertion` with `up=false` no longer skips the touch; user presence is always required.
- A reset can no longer resurrect an old key (both slots scanned, newest sequence used, old slot wiped).
- Reset deadline is checked against the request's arrival time.
- LRU channel eviction, stricter CANCEL handling, zero-length CBOR rejected at the framing level.
- RNG health tests (RCT, APT) added, documented as a failure detector only.
- `build.rs` generates `memory.x`, so flash size is configurable via `flash_*` features.
- Added fault-injection tests for the store.

### se-harden1 -> se-harden2 (PIN round)
- ClientPIN with PIN/UV protocols 1 and 2 (`pin.rs`).
- Master key wrapped with an Argon2id-derived key (`wrap.rs`), encrypt-then-MAC.
- Persistent PIN retry counter.
- Key and session wiped on USB reset, suspend and disable; idle session expiry.

### se-harden2 -> se-harden3 (round 3)
- Wipe now reads the slot back after erasing; stale old-key slot is purged at boot (`purge_stale`).
- USB reset during a touch wait cancels the command.
- Key-agreement key cleared on lock and expiry.
- COSE key checks (`kty`=2, `crv`=1, `alg`=-25 if present); APT cutoff corrected to 311.
- `minPINLength` reported in `getInfo`.
- Committed `Cargo.lock`; added `build.sh` and `guide.md`.

## Line 2: OpenSK-based firmware

### (basic edition) -> openSK-based
- Migration to Google OpenSK: new `env/` layer (flash store, HID, RNG, clock, user presence, persistence) and a pinned OpenSK revision.
- Drops the earlier custom firmware and its hardening code; this branch carries none of the `se-harden*` protections.

### openSK-based -> openSK-based-se0
- Re-introduces hardening on top of OpenSK: `env/harden.rs`.
- PIN-wrapped vault (`vault.rs`, `wrap.rs`, `store.rs`) using Argon2id on a 32-byte seed.
- OpenSK master keys derived from the seed; resident credentials encrypted.
- `third_party/opensk-harden.patch` applied to OpenSK.

### openSK-based-se0 -> openSK-based-se1
- RAM guard (`ram_guard.rs`, `guard.rs`) and vault-update checks.
- Epoch-based USB cancellation (`env/hid.rs`): reset, suspend or unplug cancels in-flight operations and drops stale packets.
- User-presence waits abort on cancellation.
- PIN wrapping: constant-time tag comparison, `Zeroizing` results.
- Added `host-test/guard` tests.

### openSK-based-se1 -> openSK-based-se2
- **SRAM PUF** (`puf.rs`): key reconstructed on demand from a repetition-coded SRAM sample, with helper data in a dedicated flash sector.
- PUF key mixed into the Argon2 password (`HMAC(K_puf, PIN hash)`) and used to mask the seed of a no-PIN vault.
- Power-on-reset detection for enrolment; `build.sh -P` builds without `sram_puf`.
- Flash layout adjusted for the helper sector.

### openSK-based-se2 -> openSK-based-se3
- **PUF Enrolment Gating:** helper sector enrolment only on blank vaults or unbound records; prevents secret/seed orphaning.
- **HMAC Tagging:** PUF-masked records carry an HMAC tag, eliminating silent wrong-seed generation on key mismatch. Older untagged records are accepted once and re-sealed.
- **Secret Zeroization:** `Zeroizing` wrappers for PUF secrets, sample buffers and repetition codewords.
- **Argon2 Bounds:** `MAX_T_COST = 64` prevents resource exhaustion from malformed flash records.
- **Fail-Closed & Fault Indicators:** PUF failure never creates a plain or unbound seed record; the device stays locked, shows an LED fault pattern (3 short blinks, pause), and a CTAP reset remains possible.
- **Build & Documentation:** `build.sh` defaults to `openSK-based-se3` and builds `--locked` only when a `Cargo.lock` exists (none is committed in this branch: without it the script warns and builds unlocked); documentation updated for security guarantees and limits.

### openSK-based-se3 -> openSK-based-se4
- **PUF helper slots:** two 4 KiB helper sectors; a re-enrolment writes the other slot and the new vault record names its slot, so a power cut in a CTAP reset leaves a usable (record, helper) pair. Flash: 72 KiB store (18 pages) + 8 KiB PUF + 12 KiB vault.
- **Migration and setPIN repairs:** binding an older record to the PUF counts as done only when the old record is wiped; an interrupted setPIN is repaired at boot.
- **PIN retry counter:** the counter sector is cleared by `finish_try`, right after a correct PIN.
- **USB:** a pending endpoint read is abandoned on reset and the endpoint is drained for 2 ms; a response is checked and queued in one critical section.
- **Stack and watchdog:** linked with `flip-link`; `stack_probe` (development) and `watchdog` (8 s, off by default) features.

### openSK-based-se4 -> openSK-based-se5
- **RAM guard:** adaptive refresh (0.5 ms in use, 2 ms idle with a seed, 50 ms without), 7 independent pair steps each in its own critical section; `guard_log` feature.
- **Scrubbing and idle:** `scrub.rs` overwrites dead stack frames after every command (32 KiB at boot); the main thread sleeps in `wfi`.
- **Status display:** `oled` feature (default): SSD1306 on I2C0 (SDA GP16, SCL GP17, 0x3C); `build.sh -O` leaves it out.

## Line 3: ATECC608A secure element
`atecc-support` / `atecc-se0` (see their `README-ATECC.md`) are the older single-file variants. The newer branches:
- **`atecc-se1`** (from `openSK-based-se5`): feature `se_atecc` (default; `build.sh -X` disables it): credential keys, ECDSA signing, a signature budget (LimitedUse slots + Counter 0) and extra entropy in an ATECC608A on I2C1 (GP14/GP15). 8 slots (`se_slots_16`: 16, unverified). Seed vault, PUF and RAM guard stay in software.
- **`atecc-se2`**: 7 credential slots, slot 7 configured as attestation key but not used by the firmware; optional chip-side PIN (`se_pin`, `gen_atecc_config.py --pin-gate`, PIN key in slot 11). **`atecc-se3`**: the same plus `table.md`.
- **`atecc0`** (from `atecc-se1`): removes the vault, PUF, RAM guard and PIN gate; OpenSK stays unpatched with its standard store. **`atecc1`**: 9 credential slots (1-9), attestation key in slot 0, no signature limit (Counter 0 unused).
- None of these except `atecc1` was compiled or run on a Pico; `atecc1` was built and tested on all browsers and operating systems.

## Caveat
Per the repository's own `REVIEW.md`, much of the code in the `openSK-based-se*` branches was first written without a Rust toolchain; the maintainer has since built and run them (see above) but there is no detailed test record, and the ATECC branches other than `atecc1` were never compiled or run. Treat the entries above as describing what the code changes, not as verified behaviour.
