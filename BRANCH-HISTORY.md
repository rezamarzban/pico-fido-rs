# Branch and commit history

This index records the commits reachable from the 19 named branches at the documentation baseline (`main` at `e1192fc`, `atecc1` at `7f4b47f`). The changes below describe each commit against its actual parent, not the result of treating successively numbered branch tips as Git ancestors. SHA abbreviations identify snapshots; version names and branch names are separate.

## Branch tips

| Branch | Tip | Source lineage or documentation difference |
| --- | --- | --- |
| `main` | `e1192fc` | Basic firmware plus project index; direct child of `d460927`, with the same non-documentation tree as `90c9e5d`. |
| `se-harden0` | `d778604` | Same non-documentation tree as `87cd486`. |
| `se-harden1` | `c105225` | Same non-documentation tree as `08d3557`, on parent `87cd486`. |
| `se-harden2` | `7734e07` | Same non-documentation tree as `fc03f9b`, on parent `08d3557`. |
| `se-harden3` | `36d8bdf` | Continues from `fc03f9b`. |
| `openSK-based` | `0858e2c` | Migration and build/docs in one commit; same non-documentation tree as `cc2034c`. |
| `openSK-based-se0` | `884c885` | Same non-documentation tree as `c541f01`, on parent `cc2034c`. |
| `openSK-based-se1` | `1b6dbf4` | Same non-documentation tree as `1ab3993`, on parent `c541f01`. |
| `openSK-based-se2` | `9b4ea6e` | Continues from `1ab3993`. |
| `openSK-based-se3` | `998571e` | Continues from `9b4ea6e`. |
| `openSK-based-se4` | `e499f22` | Documentation update on `cd00fd9`; firmware includes v5, v5.1 and v5.2. |
| `openSK-based-se5` | `3ec553a` | Documentation update on `e3b6761` (OpenSK hardening v6). |
| `atecc-support` | `fb1a8cc` | Same non-documentation tree as `2853405`; README adds a build/flash smoke procedure. |
| `atecc-se0` | `e6bc224` | Continues the older custom firmware from `2853405`. |
| `atecc-se1` | `9094ea2` | Documentation update on `126386b` (ATECC hardening v2). |
| `atecc-se2` | `7e427d0` | Documentation update on `8a81eef` (ATECC hardening v3). |
| `atecc-se3` | `10163f1` | Continues from `8a81eef`; the v4-labelled commit has no tree changes, followed by checklist and documentation updates. |
| `atecc0` | `5137e0b` | Documentation update on `7c1dfcc` (OpenSK ATECC support v1). |
| `atecc1` | `7f4b47f` | Diverges at `7c1dfcc`, not at `5137e0b`; the tip adds PCB assets after firmware v6.5. |

## Original firmware and custom hardening

| Commit | Change |
| --- | --- |
| `d460927` | Creates the initial `Readme.md`, before the firmware. |
| `90c9e5d`, `e1192fc` | Sibling basic editions: RP2040 custom FIDO implementation with master key in the last 4 KiB of flash, USB HID and host-test scaffolding. `e1192fc` adds the branch-index README. |
| `87cd486`, `d778604` | Hardening v1: strict CBOR checks, stricter CTAP/HID parsing, two-slot checked master-key storage and removal of keyboard HID. The branch-tip variant adds/updates README and security notes. |
| `08d3557`, `c105225` | Hardening v2: touch and reset fixes, stricter CANCEL/channel handling, RNG health checks, and configurable flash size via `build.rs`; the tip variant updates README, review and security notes. |
| `fc03f9b`, `7734e07` | Hardening v3: ClientPIN protocols 1/2, Argon2id-wrapped master key, persistent retry state and USB/idle session clearing; the tip variant updates README, review and security notes. |
| `36d8bdf` | Hardening v4: erase readback and stale slot purge, cancellation during touch waits, COSE key checks and `minPINLength`; adds `build.sh`, guide and `Cargo.lock`. |

## OpenSK migration and hardening

| Commit | Change |
| --- | --- |
| `5994031` | Replaces custom CTAP and keyboard HID with an RP2040 environment around OpenSK: persistence, RNG, clock, FIDO HID and presence. |
| `cc2034c`, `0858e2c` | Pin OpenSK and supply the build script, CI, host-test runner and documentation. `0858e2c` includes the migration itself and revises README, review, security and guide relative to `cc2034c`. |
| `c541f01`, `884c885` | OpenSK hardening v1: patched OpenSK uses a PIN-wrapped Argon2id seed vault and derived master keys; the tip variant updates README, review, security and guide. |
| `1ab3993`, `1b6dbf4` | OpenSK hardening v2: RAM guard, update checks for the vault, and USB-epoch cancellation; guard/vault tests. The tip variant also updates README, review, security and guide. |
| `9b4ea6e` | OpenSK hardening v3: SRAM-PUF helper sector; PUF binds the PIN vault and masks the no-PIN seed. |
| `998571e` | OpenSK hardening v4: enrolment gating, authenticated PUF-masked records, zeroization, Argon2 work bound, fail-closed LED status and more USB epoch checks. |
| `2333dec` | OpenSK hardening v5: require erasure of old vault records before claiming migration, distinguish security/PUF faults, tighten USB reset/response handling and stop formatting the store on unrelated errors. |
| `1834807` | OpenSK hardening v5.1: two PUF helper slots, store reduced to 72 KiB, `flip-link` and optional stack measurement. |
| `2b836fd` | OpenSK hardening v5.2: reconcile interrupted setPIN on boot, recycle the retry sector after a correct PIN and add the optional watchdog. |
| `cd00fd9` | Adds `stateless.md`; no firmware changes. |
| `e499f22` | `openSK-based-se4` documentation round: README and review wording only. |
| `e3b6761` | OpenSK hardening v6: adaptive RAM-guard refresh, stack scrubbing, `wfi` idle and optional SSD1306 OLED enabled by default. |
| `3ec553a` | `openSK-based-se5` documentation round: README and review wording only. |

## Earlier ATECC variants

| Commit | Change |
| --- | --- |
| `2853405`, `fb1a8cc` | Custom firmware adds ATECC608A/B key generation/signing with a single-file driver and flash credential metadata. The branch-tip variant expands the README with UF2 and smoke-test instructions. |
| `e6bc224` | Custom ATECC hardening v1: eight credential slots, dual-copy metadata, discoverable assertion enumeration, safer reset and separate provisioning/locking builds. |
| `126386b` | ATECC hardening v2 (from `e3b6761`): OpenSK secure-element adapter with eight credential slots by default, extra hardware entropy and a chip-enforced signing budget. The existing vault, PUF and RAM guard remain on the Pico. |
| `9094ea2` | `atecc-se1` documentation round: README, review, security and guide. |
| `8a81eef` | ATECC hardening v3: seven credential slots, unused attestation slot 7, optional fixed chip-side PIN gate (`se_pin`, off by default) and associated tooling. |
| `7e427d0` | `atecc-se2` documentation round: README, review, security and guide. |
| `163d859` | Labelled ATECC hardening v4; its tree is identical to `8a81eef`. |
| `f5739a0` | Adds `table.md` to describe the hardware/software split. |
| `2abce9d` | Expands `table.md` into an implementation checklist and records outstanding gaps. |
| `10163f1` | `atecc-se3` documentation round: README, review, security, guide and checklist. |
| `5137e0b` | `atecc0` documentation round: README and chip configuration notes; firmware remains `7c1dfcc` below. |

## atecc1 release ledger

The maintainer reports testing every `atecc1` firmware revision across all browsers and operating systems. This is not an independently reproduced result or a per-platform/browser test matrix. Documentation-only and PCB commits do not add new firmware.

| Commit | Version or snapshot | Change against its parent |
| --- | --- | --- |
| `7c1dfcc` | v1 / shared with `atecc0` | Removes the hardened OpenSK patch, vault, PUF, RAM guard and chip PIN gate. Uses OpenSK's standard plaintext store, chip-only entropy, seven credential slots and an attestation key in slot 7. LimitedUse/Counter 0 enforces the signing budget; Counter 1 rotates credential slots. |
| `f36d0f8` | v2 | Moves attestation to slot 0 and credentials to slots 1–9. Removes LimitedUse from the reference configuration, but still enforces the budget by incrementing chip Counter 0 in firmware; Counter 1 still rotates slots. |
| `c0396d9` | v2.1 | Removes the signing budget and stops using Counter 0; Counter 1 still rotates credential slots. Adds the OLED chip identity/lock page and chip info parsing. |
| `9d23fe3` | v2.2 | Drops Counter 1 and the eviction policy. Scans for empty slots and never overwrites populated ones; a full chip refuses new registrations via the old panicking trait path. Adds reference config output and the attestation certificate tool. |
| `e802d5e` | v2.2.1 | Aligns the generator/reference image with the reference bytes for unused slots and factory-zero counter encoding. The firmware still uses neither counter. |
| `3646ac7` | Configuration reference | Adds `atecc608a/ATECC608A_CONFIG_DESCRIPTION.md`. No firmware changes. |
| `112361e` | v3 | Adds the OpenSK RP-hint patch and one key per site. Saves the directory in chip slot 13; known sites can reuse a key when the nine slots are full. |
| `fd48a02` | v3.1 | Moves the directory to one 4 KiB Pico flash page (76 KiB reserved in total); no migration of the chip directory. A site can take over an unassigned existing key unchanged. |
| `e195744` | v3.1.1 | Adds a single-page Pico signature tally (80 KiB total) and OLED slot/usage reporting. It is telemetry, not a signing limit. |
| `f2be689` | v4 | Separates site directories and signing tallies by ATECC serial number; older single-chip formats are not read. OpenSK's store remains shared across chips. |
| `8cbc79e` | v4.1 | Adds OLED per-chip flash-usage reporting and model coverage for computing it. |
| `5b53da3` | v4.1.9 | Two-sector copy-on-write directory, 128-bit site tags and power-cut model tests (84 KiB reserved). Adds explicit fetching of pinned OpenSK instead of submodule setup. Refused signatures stop the firmware rather than emit a dummy signature. |
| `bd1eca6` | v5 | Introduces SRAM-PUF-derived AES-256-GCM sealing of store values, directories and tally (104 KiB reserved), with 1 KiB of SRAM at the bottom and no backup. Updates pinned OpenSK, adopts fallible ECDSA and temporarily uses HMAC-DRBG. |
| `b7dbcbd` | Unnumbered follow-up to v5 | Moves the PUF to the top 4 KiB of striped SRAM; adds pair conditioning, bias gating and a new helper and spill format. Restores ChaCha20 DRBG, changes the pinned nightly and commits the root lockfile. |
| `13cbfa1` | v5.2 | Adds PUF-secret backup/restore (108 KiB reserved). The historical format relied on a public attestation key and is unsuitable for backup confidentiality. |
| `15b3348` | v5.3 | Makes the signature tally copy-on-write across two regions (120 KiB total), without moving the helper or backup. Upgrades from the old single-region tally reset its counts. |
| `44e8a6f` | v6 | Replaces the public-key backup format with chip HMAC backed by a random key in data slot 11. A blank slot that cannot be provisioned cannot provide a backup. |
| `041a1b0` | v6.1 | Regenerates an unowned populated credential slot before assigning it to a new site. Introduces slot-11 rotation for a new backup, initially updating the chip key before the record is written. Its original README ends mid-sentence. |
| `fc4f00b` | v6.1.1 | Writes and reads back the new backup record before committing the replacement chip key; a cut before commitment leaves the old backup usable. Corrects the host-test target selection. |
| `7ed318c` | v6.1.5 | Refuses to erase unknown/damaged backup sectors and requires two free records before attempting rotation. Without a usable helper, a damaged backup no longer permits first-start wiping. |
| `6f935d4` | v6.1.5.1 | Tightens interrupted-first-write recognition: only a partial expected header with an erased tail can be reformatted under that rule. |
| `7bc048d` | v6.5 | Adds boot-local OLED reporting for freshly generated keys, per-slot signatures, the last signer and slot-11 status. Recognises legacy backup sectors only by the complete old header. |
| `7f4b47f` | PCB added | Adds KiCad 8 carrier-board project, schematic, layout, preview and hardware notes; no firmware changes from v6.5. |

## Reported hardware test scope

The existing maintainer report records the OpenSK-only branches on Linux, Windows and Android browsers, and `se-harden0` through `se-harden3` on Linux only. The maintainer reports that the ATECC branches other than `atecc1` were not built or run. Refer to the branch's own security notes for limitations; compatibility testing is not a security audit, a power-loss qualification or a substitute for testing the exact hardware configuration.
