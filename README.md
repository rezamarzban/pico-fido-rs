# pico-fido-rs

A FIDO2 / U2F security key for the Raspberry Pi Pico (RP2040), written in Rust with Embassy.
**Experimental. Nothing here is audited. Read the `SECURITY.md` of the
branch you use before relying on it.**

**Hardware testing (reported by the maintainer, not independently verified):** every branch except the two `atecc-*` branches was built, flashed to a Raspberry Pi Pico and tested. The OpenSK-based branches (`openSK-based`, `-se0`, `-se1`, `-se2`) were tested and work on **Linux, Windows and Android** browsers; the `se-harden*` branches were tested and work on **Linux only**. The `atecc-*` branches were not compiled or run.

This branch (`main`) carries no firmware documentation of its own, but it is **not empty**: it still holds the earliest custom firmware (stateless ES256 credentials from one 32-byte master key kept in plain flash, in the last 4 KiB of a 2 MiB chip; no PIN, no resident keys; a USB keyboard HID interface next to the FIDO one; no `flash_*` features, no `build.sh`). The `build.sh` scripts of the other branches default to `-b main`, which does not build (no `flash_*` features): always pass `-b <branch>`. The documented work lives in the branches below;
each has its own `README.md` / `SECURITY.md` / `REVIEW.md` (some also `guide.md`; the `atecc-*` branches only have `README-ATECC.md`).

| Branch | What it is |
|--------|------------|
| `openSK-based` | RP2040 platform layer around Google's OpenSK (Apache-2.0). Key material and PIN hash are stored in clear in flash. The maintainer reports it working on Linux, Windows and Android. |
| `openSK-based-se0` | Adds a PIN-wrapped master-seed vault (Argon2id). Built and tested on a Pico. |
| `openSK-based-se1` | Adds a RAM guard (XOR shares of the seed), USB-cancellation handling and vault-update checks. Built and tested on a Pico. |
| `openSK-based-se2` | Adds binding of the vault seed to the chip's SRAM power-up pattern (PUF). Built and tested on a Pico. |
| `se-harden0` .. `se-harden3` | The earlier custom CTAP implementation (stateless credentials, no resident keys, no U2F). `se-harden0`: no PIN. `se-harden1`: review round 2 fixes. `se-harden2`: ClientPIN with an Argon2id-wrapped master key. `se-harden3`: further fixes, `build.sh`, `guide.md`. Tested on a Pico on Linux only (not Windows or Android). |
| `atecc-support`, `atecc-se0` | Variants that keep the private keys in an ATECC608. Not compiled or run by the author. |

`openSK-based/REVIEW.md` records why the project moved from the custom implementation to OpenSK: the custom firmware
worked in Linux browsers but not on Windows and Android, and the cause was never established.

Usage guides: `guide.md` in `openSK-based`, `openSK-based-se0`, `openSK-based-se1`, `openSK-based-se2` and
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
- **Build & Documentation:** `build.sh` builds `--locked` with a committed `Cargo.lock` and defaults to `openSK-based-se3`; documentation updated for security guarantees and limits.

## Caveat
Per the repository's own `REVIEW.md`, much of the code in the `openSK-based-se*` branches was written without a Rust toolchain and has no detailed test record. Treat the entries above as describing what the code changes, not as verified behaviour.
