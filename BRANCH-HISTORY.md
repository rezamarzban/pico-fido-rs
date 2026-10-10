# Branch and commit history

This file combines the branch index and the changelog for `pico-fido-rs`. It covers every commit reachable from the 19 named branches (60 commits), grouped by firmware line and listed oldest first within each group. Hashes are valid for `main` at `005d8e2` and `atecc1` at `fc61fcf`.

Every entry was checked against the repository itself: each commit's diff against its actual parent (`git diff <parent> <commit>`), the parent/child graph, and tree comparisons for the documentation-only variants. Commit messages were not used as evidence, and successively numbered branch tips are not treated as Git ancestors. SHA abbreviations identify snapshots; version names and branch names are separate. Dates are author dates.

Several branches end on a documentation variant of a commit that another branch carries; where that is so, the entry says which firmware tree it shares. The firmware lines branch from `90c9e5d`, not from the `main` tip `005d8e2`. `main` is a sibling of `90c9e5d` (both are children of `d460927`), and it contains none of the later commits.

## Branch tips

| Branch | Tip | Source lineage or documentation difference |
| --- | --- | --- |
| `main` | `005d8e2` | Child of `d460927`, sibling of `90c9e5d`; same firmware tree as `90c9e5d`, adds `README.md` (branch index) and `BRANCH-HISTORY.md`. |
| `se-harden0` | `d778604` | Same non-documentation tree as `87cd486`; adds README and security-note changes. |
| `se-harden1` | `c105225` | Same non-documentation tree as `08d3557`, on parent `87cd486`. |
| `se-harden2` | `7734e07` | Same non-documentation tree as `fc03f9b`, on parent `08d3557`. |
| `se-harden3` | `36d8bdf` | Continues from `fc03f9b`. |
| `openSK-based` | `0858e2c` | Migration plus build/docs in one commit on `90c9e5d`; same non-documentation tree as `cc2034c`. |
| `openSK-based-se0` | `884c885` | Same non-documentation tree as `c541f01`, on parent `cc2034c`. |
| `openSK-based-se1` | `1b6dbf4` | Same non-documentation tree as `1ab3993`, on parent `c541f01`. |
| `openSK-based-se2` | `9b4ea6e` | Continues from `1ab3993`. |
| `openSK-based-se3` | `998571e` | Continues from `9b4ea6e`. |
| `openSK-based-se4` | `e499f22` | Documentation update on `cd00fd9`; firmware includes v5, v5.1 and v5.2. |
| `openSK-based-se5` | `3ec553a` | Documentation update on `e3b6761` (OpenSK hardening v6). |
| `atecc-support` | `fb1a8cc` | Same non-documentation tree as `2853405`; `README-ATECC.md` adds a build/flash smoke procedure. |
| `atecc-se0` | `e6bc224` | Continues the older custom firmware from `2853405`. |
| `atecc-se1` | `9094ea2` | Documentation update on `126386b` (ATECC hardening v2). |
| `atecc-se2` | `7e427d0` | Documentation update on `8a81eef` (ATECC hardening v3). |
| `atecc-se3` | `10163f1` | Continues from `8a81eef`; the v4-labelled commit has no tree changes, followed by checklist and documentation updates. |
| `atecc0` | `5137e0b` | Documentation update on `7c1dfcc` (slimmed ATECC firmware v1); firmware unchanged. |
| `atecc1` | `fc61fcf` | Diverges from `atecc0` at `7c1dfcc`; firmware v1 through v6.5, with the PCB files added in the tip commit. |

## Root and basic edition

| Date | Commit | Change |
| --- | --- | --- |
| 2026-10-07 | `d460927` | Initial `Readme.md` (one line), before any firmware. |
| 2026-10-10 | `90c9e5d` | Basic edition: custom RP2040 CTAP2 firmware (Embassy; CBOR only, no CTAP1/U2F, "NMSG"). Stateless ES256 credentials: the credential ID is a nonce plus an HMAC under a master key, and the private key is re-derived on every use. The master key sits in the last 4 KiB sector of flash. FIDO HID plus a USB keyboard HID, host tests. Common base of every firmware branch. |
| 2026-10-10 | `005d8e2` | `main` tip. Same firmware tree as `90c9e5d`, on parent `d460927`; adds `README.md` (branch index) and `BRANCH-HISTORY.md`, and replaces `Readme.md`. Documentation only. |

## Line 1: custom firmware hardening (`se-harden0` .. `se-harden3`, from `90c9e5d`)

| Date | Commit | Change |
| --- | --- | --- |
| 2026-10-10 | `87cd486` | Hardening v1: strict CBOR validation (canonical, no duplicate keys, depth ≤ 4, no trailing bytes), stricter CTAP/HID parsing (8-channel limit, message timeout), crash-safe two-slot master-key store with a truncated SHA-256 integrity record, removal of the keyboard HID (`usb/hid.rs`), CI changes and expanded host tests. |
| 2026-10-10 | `d778604` | `se-harden0` tip: same firmware tree as `87cd486`, with README and security notes. |
| 2026-10-10 | `08d3557` | Hardening v2: `up=false` no longer skips the touch, reset cannot resurrect an old key, reset deadline measured from request arrival, LRU channel eviction that spares the active and assembling channels, stricter CANCEL handling, RNG health tests (`health.rs`), flash size configurable through `build.rs`, store fault-injection tests. |
| 2026-10-10 | `c105225` | `se-harden1` tip: same firmware tree as `08d3557`, with README, review and security notes. |
| 2026-10-10 | `fc03f9b` | Hardening v3: ClientPIN protocols 1 and 2, Argon2id-wrapped master key (encrypt-then-MAC), persistent PIN retry counter, key and session wiped on USB reset, suspend and disable, idle session expiry. |
| 2026-10-10 | `7734e07` | `se-harden2` tip: same firmware tree as `fc03f9b`, with README, review and security notes. |
| 2026-10-10 | `36d8bdf` | `se-harden3` tip, hardening v4: erase readback and stale-slot purge, a USB reset/suspend/disable now aborts a pending touch wait and locks the session, COSE key checks (`kty`/`crv`/`alg`), `minPINLength`, APT cutoff corrected from 410 to 311; adds `build.sh`, `guide.md` and `Cargo.lock`. |

## Line 2: OpenSK migration and hardening (`openSK-based`, `openSK-based-se0` .. `-se5`, from `90c9e5d`)

| Date | Commit | Change |
| --- | --- | --- |
| 2026-10-12 | `5994031` | Migrates to Google OpenSK: new RP2040 `env/` layer (flash store, FIDO HID, RNG, clock, user presence); deletes the custom CTAP/CBOR/CTAPHID code, the keyboard HID, the custom CI, host tests, `Embed.toml` and `memory.x`. |
| 2026-10-12 | `0858e2c` | `openSK-based` tip: a separate commit on `90c9e5d` carrying the migration plus OpenSK pinning, build script, CI, host-test runner and documentation in one commit, under the same message as `5994031`. Same non-documentation tree as `cc2034c`; README, review and security notes differ slightly. |
| 2026-10-12 | `cc2034c` | Pins OpenSK and supplies build script, CI, host-test runner and documentation, on top of `5994031`. |
| 2026-10-13 | `c541f01` | OpenSK hardening v1: patched OpenSK, PIN-wrapped Argon2id seed vault, master keys derived from the seed. |
| 2026-10-13 | `884c885` | `openSK-based-se0` tip: same firmware tree as `c541f01`, with README, review, security and guide. |
| 2026-10-13 | `1ab3993` | OpenSK hardening v2: RAM guard (XOR shares of the seed), vault update checks, USB-epoch cancellation, guard/vault tests. |
| 2026-10-13 | `1b6dbf4` | `openSK-based-se1` tip: same firmware tree as `1ab3993`, with README, review, security and guide. |
| 2026-10-14 | `9b4ea6e` | `openSK-based-se2` tip, hardening v3: SRAM-PUF helper sector; the PUF binds the PIN vault and masks the no-PIN seed. |
| 2026-10-15 | `998571e` | `openSK-based-se3` tip, hardening v4: enrolment gating, HMAC-tagged (authenticated) PUF-masked records, zeroization, `MAX_T_COST` Argon2 bound, fail-closed LED fault pattern, more USB epoch checks. |
| 2026-10-17 | `2333dec` | Hardening v5: old vault records must be erased before a migration counts as done, security vs PUF faults distinguished, tighter USB reset/response handling, no store formatting on unrelated errors. |
| 2026-10-18 | `1834807` | Hardening v5.1: two PUF helper slots with commit, store reduced to 72 KiB, `flip-link`, optional stack measurement (`stack_probe`). |
| 2026-10-18 | `2b836fd` | Hardening v5.2: interrupted setPIN reconciled on boot, retry sector recycled after a correct PIN, optional watchdog (`wdog.rs`). |
| 2026-10-24 | `cd00fd9` | Adds `stateless.md`; no firmware changes. |
| 2026-11-07 | `e499f22` | `openSK-based-se4` tip: documentation round on `cd00fd9` (README and review wording only). |
| 2026-10-28 | `e3b6761` | Hardening v6: adaptive RAM-guard refresh, stack scrubbing, `wfi` idle, SSD1306 OLED status display enabled by default (`oled` is a default feature). |
| 2026-11-07 | `3ec553a` | `openSK-based-se5` tip: documentation round on `e3b6761` (README and review wording only). |

## Line 3: ATECC608A on the custom firmware (`atecc-support`, `atecc-se0`, from `90c9e5d`)

| Date | Commit | Change |
| --- | --- | --- |
| 2026-10-10 | `2853405` | Custom firmware gains ATECC608A/B key generation and signing: single-file driver (`src/atecc.rs`), flash credential metadata, `README-ATECC.md`. |
| 2026-10-10 | `fb1a8cc` | `atecc-support` tip: same firmware tree as `2853405`; `README-ATECC.md` adds UF2 and smoke-test instructions. |
| 2026-10-10 | `e6bc224` | `atecc-se0` tip, ATECC hardening v1: eight credential slots, dual-copy (A/B) metadata with sequence number and SHA-256, discoverable assertion enumeration, safer reset, separate provisioning and locking builds. |

## Line 4: ATECC608A on OpenSK, hardening series (`atecc-se1` .. `atecc-se3`, from `e3b6761`)

| Date | Commit | Change |
| --- | --- | --- |
| 2026-11-04 | `126386b` | ATECC hardening v2 on `e3b6761`: OpenSK secure-element adapter (`se_atecc`, default feature), eight credential slots by default, chip entropy mixed into the RNG, chip-enforced signing budget (LimitedUse slots plus Counter 0), config generator and host tests. Vault, PUF and RAM guard stay on the Pico. |
| 2026-11-07 | `9094ea2` | `atecc-se1` tip: documentation round on `126386b` (README, review, security and guide). |
| 2026-11-04 | `8a81eef` | ATECC hardening v3: seven credential slots, unused attestation slot 7, optional fixed chip-side PIN gate (`se_pin`, off by default) and tooling. |
| 2026-11-07 | `7e427d0` | `atecc-se2` tip: documentation round on `8a81eef` (README, review, security and guide). |
| 2026-11-04 | `163d859` | Labelled ATECC hardening v4; tree identical to `8a81eef`. |
| 2026-11-04 | `f5739a0` | Adds `table.md` describing the chip/software split. |
| 2026-11-04 | `2abce9d` | Expands `table.md` into an implementation checklist and records open gaps. |
| 2026-11-07 | `10163f1` | `atecc-se3` tip: documentation round (README, review, security, guide, checklist). |

## Line 5: slimmed ATECC firmware (`atecc0`, `atecc1`, from `126386b`)

The maintainer reports testing every `atecc1` firmware revision (`7c1dfcc` through `fc61fcf`) on all browsers and operating systems. This is not an independently reproduced result or a per-platform/browser test matrix. `atecc0` shares its firmware with `7c1dfcc` (`5137e0b` only adds documentation). Documentation-only and PCB changes do not add new firmware. The "KiB reserved" figures below are the flash that `build.rs` keeps out of the linker's FLASH region.

| Date | Commit | Version or snapshot | Change against its parent |
| --- | --- | --- | --- |
| 2026-11-05 | `7c1dfcc` | v1 / shared with `atecc0` | Removes the hardened OpenSK patch, vault, PUF, RAM guard, watchdog, stack tools and chip PIN gate (and deletes `stateless.md`). Uses OpenSK's standard plaintext store, chip-only entropy (ChaCha20 DRBG seeded from the chip), seven credential slots and an attestation key in slot 7. LimitedUse/Counter 0 enforces the signing budget; Counter 1 rotates credential slots. |
| 2026-11-07 | `5137e0b` | `atecc0` tip | Documentation round on `7c1dfcc` (README and chip configuration notes); firmware unchanged. |
| 2026-11-06 | `f36d0f8` | v2 | Moves attestation to slot 0 and credentials to slots 1–9. Removes LimitedUse from the reference configuration, but still enforces the budget by incrementing chip Counter 0 in firmware; Counter 1 still rotates slots. |
| 2026-11-06 | `c0396d9` | v2.1 | Removes the signing budget and stops using Counter 0; Counter 1 still rotates credential slots. Adds the OLED chip identity/lock page and chip info parsing. |
| 2026-11-10 | `9d23fe3` | v2.2 | Drops Counter 1 and the eviction policy. Scans for empty slots and never overwrites populated ones; a full chip refuses new registrations via the old panicking trait path. Adds reference config output and the attestation certificate tool. |
| 2026-11-10 | `e802d5e` | v2.2.1 | Aligns the generator/reference image with the reference bytes for unused slots and factory-zero counter encoding. The firmware still uses neither counter. Also commits Python `__pycache__` files (removed again in `fd48a02`). |
| 2026-11-10 | `3646ac7` | Configuration reference | Adds `atecc608a/ATECC608A_CONFIG_DESCRIPTION.md`. No firmware changes. |
| 2026-11-11 | `112361e` | v3 | Adds the OpenSK RP-hint patch and one key per site. Saves the directory in chip data slot 13; known sites can reuse a key when the nine slots are full. |
| 2026-11-11 | `fd48a02` | v3.1 | Moves the directory to one 4 KiB Pico flash page (76 KiB reserved in total); no migration of the chip directory. A site can take over an unassigned existing key unchanged. |
| 2026-11-11 | `e195744` | v3.1.1 | Adds a single-page Pico signature tally (80 KiB total) and OLED slot/usage reporting. It is telemetry, not a signing limit. |
| 2026-11-11 | `f2be689` | v4 | Separates site directories and signing tallies by ATECC serial number; older single-chip formats are not read. OpenSK's store remains shared across chips. |
| 2026-11-11 | `8cbc79e` | v4.1 | Adds an OLED page showing how many chips the flash directory and signature-counter pages hold and how much of each page is used, with model tests for computing those figures. |
| 2026-11-12 | `5b53da3` | v4.1.9 | Two-sector copy-on-write directory, 128-bit site tags and power-cut model tests (84 KiB reserved). Adds explicit fetching of pinned OpenSK (`fetch-opensk.sh`) instead of submodule setup. Refused signatures stop the firmware (panic) rather than emit a dummy signature. |
| 2026-11-14 | `bd1eca6` | v5 | Introduces SRAM-PUF-derived AES-256-GCM sealing of store values, directories and tally (104 KiB reserved), with 1 KiB of SRAM at the bottom of RAM and no backup. Updates pinned OpenSK, adopts fallible ECDSA and temporarily uses HMAC-DRBG. |
| 2026-11-14 | `b7dbcbd` | Unnumbered follow-up to v5 | Moves the PUF to the top 4 KiB of striped SRAM; adds pair conditioning, bias gating and new helper and spill formats. Restores ChaCha20 DRBG, changes the pinned nightly (`nightly-2026-10-02` to `nightly-2026-06-03`) and commits the root lockfile. |
| 2026-11-15 | `13cbfa1` | v5.2 | Adds PUF-secret backup/restore (108 KiB reserved). The historical format relied on a public attestation key and is unsuitable for backup confidentiality. |
| 2026-11-15 | `15b3348` | v5.3 | Makes the signature tally copy-on-write across two regions (120 KiB total), without moving the helper or backup. Upgrades from the old single-region tally reset its counts. |
| 2026-11-19 | `44e8a6f` | v6 | Replaces the public-key backup format with chip HMAC backed by a random key in data slot 11. A blank slot that cannot be provisioned cannot provide a backup. |
| 2026-11-19 | `041a1b0` | v6.1 | Regenerates an unowned populated credential slot before assigning it to a new site (earlier firmware took such a key over unchanged). Introduces slot-11 rotation for a new backup, initially updating the chip key before the record is written. Its original README ends mid-sentence. |
| 2026-11-19 | `fc4f00b` | v6.1.1 | Writes and reads back the new backup record before committing the replacement chip key (`commit_backup_key`); a cut before commitment leaves the old backup usable. Corrects the host-test target selection (forces the host target) and completes the README. |
| 2026-11-19 | `7ed318c` | v6.1.5 | Refuses to erase unknown/damaged backup sectors and requires two free records before attempting rotation. Without a usable helper, a damaged backup no longer permits first-start wiping. |
| 2026-11-19 | `6f935d4` | v6.1.5.1 | Tightens interrupted-first-write recognition: only an exact prefix of the expected header (plus one partly programmed byte) with an erased tail can be reformatted under that rule. |
| 2026-11-19 | `fc61fcf` | `atecc1` tip, v6.5 | Adds boot-local OLED reporting for freshly generated keys, per-slot signatures, the last signer and slot-11 status. Recognises legacy backup sectors only by the complete old header. Adds the KiCad 8 carrier-board project (schematic, 2-layer layout, preview) and `PCB/HARDWARE.md`; documentation brought up to date. The PCB files and the firmware changes are in the same commit. |

## Reported hardware test scope

The test statements come from the READMEs of the branches themselves and are maintainer reports, not independently verified:

- `se-harden0` through `se-harden3`: built, flashed and tested on a Pico with Linux browsers only; not tested on Windows or Android. `se-harden3` also states that hardware testing was not recorded in detail.
- `openSK-based` carries the maintainer's report that it was built, flashed and tested; `openSK-based-se0` through `-se5` state they were built and tested on a Pico on Linux, Windows and Android.
- `atecc-support` and `atecc-se0`: `README-ATECC.md` states the code was not compiled or run by its author.
- `atecc-se1` .. `atecc-se3`: the secure-element mode was never compiled or run on a Pico; the tested statements apply only to the software-only `openSK-based-se5` firmware.
- `atecc0`: the README states this revision was not compiled.
- `atecc1`: the maintainer reports every firmware revision was tested on all browsers and operating systems, with no version-by-platform matrix.

Refer to each branch's own security notes for limitations; compatibility testing is not a security audit, a power-loss qualification or a substitute for testing the exact hardware configuration.
