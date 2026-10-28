# pico-fido-rs

A FIDO2 / U2F security key for the Raspberry Pi Pico (RP2040), written in Rust with Embassy. The CTAP
protocol itself is **Google's OpenSK library** (Apache-2.0); this repository is the RP2040 platform layer
around it (USB, flash store, button, RNG). This branch adds a PIN-wrapped master-key vault to the OpenSK-based firmware. **Experimental. Built and tested on a Raspberry Pi Pico (Linux, Windows, Android). Read `SECURITY.md` before relying on it.**

## Architecture
| Part | Where |
|------|-------|
| CTAP2 / CTAP1 (U2F), CTAPHID, ClientPIN, credential logic | OpenSK, `third_party/OpenSK/libraries/opensk` (git submodule; commit in `third_party/OPENSK_REV`) |
| `opensk::env::Env` for the Pico | `src/env/mod.rs` (`PicoEnv`; customization: minimum PIN length 10, batch attestation off) |
| Persistent store (credentials, metadata, PIN length) | `src/env/persist.rs` + `src/env/flash_store.rs`, on the `wasefire-store` crate (cleartext backend) |
| Hardening: master key + resident-credential encryption, PIN check (Argon2id tag, no stored PIN hash), retry counter | `src/env/harden.rs` (`HardenPersist`), `src/vault.rs`, `src/store.rs`, `src/wrap.rs`; PIN hook in `third_party/opensk-harden.patch` |
| User presence = fresh BOOTSEL press | `src/env/user_presence.rs` |
| Packet bridge between USB (async) and OpenSK (blocking) | `src/env/hid.rs` (two queues) |
| Random numbers | `src/env/rng.rs` -> `src/keys.rs` (ring oscillator + SHA-256, `src/health.rs` health tests) |
| Clock | `src/env/clock.rs` |
| USB device, LED, main loop | `src/usb/`, `src/main.rs` |

OpenSK blocks (waiting for the button, computing signatures), so it runs in thread mode. USB, the LED and the
packet pump run on a **higher-priority interrupt executor** (`SWI_IRQ_1`), so USB keeps being serviced
meanwhile. OpenSK features enabled: `ctap1` (U2F), `config_command`, `software_crypto` (RustCrypto, ES256).
What the device really reports is whatever `authenticatorGetInfo` returns (`fido2-token -I`).

## OpenSK version
The commit is pinned in **`third_party/OPENSK_REV`** (`79e85b9a72a1ad99745e0d07aec9708d2f7ad6a9`). Always build
the pinned commit: an unpinned OpenSK (for example a branch name) can change between builds. When you update the
pin, rebuild, retest on hardware and update the file.

## Flash layout
The **last 92 KiB** of flash are kept out of the linker's FLASH region (`build.rs`):
* the last **12 KiB** (`VAULT_BYTES`) are the vault: `[PIN retry counter][seed slot 0][seed slot 1]` (`src/vault.rs`);
* the **4 KiB** below it (`PUF_BYTES`) hold the SRAM-PUF helper data (`src/puf.rs`);
* the **72 KiB** below that (18 pages of 4 KiB, `STORE_PAGES`) are the OpenSK key-value store. (Older images used 19 pages and one 4 KiB PUF sector: a device flashed with them must be erased and reset, the store is re-formatted.)

With the `sram_puf` feature (default) `build.rs` also takes the first 512 bytes of RAM out of the linker's RAM: no
section, heap or stack ever touches them. The PUF samples this region at start-up and again every time the PUF secret is
reconstructed (PIN checks, set PIN, reset), so nothing may ever write to it.

`build.rs` derives everything from the single `flash_*` feature, so firmware, store and vault cannot overlap.
The store lost one page to the PUF sector, so an existing device **reformats its key-value store** on the first boot of
this version (resident credentials are lost; the seed in the vault survives and is bound to the PUF at that boot). This
layout differs from the earlier branches: **erase the whole flash before the first install** on a fresh device (a vault sector
holding old data is reported as damaged and the device refuses to work until a CTAP reset). On first boot a blank
vault gets a fresh random seed; a store area the store does not understand is erased once.

## Build
Needs the **nightly** pinned in `rust-toolchain.toml` (`nightly-2026-06-03`, the one OpenSK pins; OpenSK is
edition 2024). There is no stable firmware build. Release builds are size-optimised (`opt-level = "s"`, LTO,
stripped).

    # one-time: OpenSK as a submodule at the pinned commit (do NOT fetch its nested submodules)
    git submodule add --depth 1 https://github.com/google/OpenSK.git third_party/OpenSK
    git -C third_party/OpenSK fetch --depth 1 origin $(cat third_party/OPENSK_REV)
    git -C third_party/OpenSK checkout $(cat third_party/OPENSK_REV)
    git add .gitmodules third_party/OpenSK

    cargo build --release                       # 2 MiB board; USB serial number off (default)
    cargo build --release --no-default-features \
        --features rp2040_board,flash_4m,usb_serial   # e.g. a 4 MiB board with a USB serial number

Enable **exactly one** `flash_*` feature (`flash_2m`, `flash_4m`, `flash_8m`, `flash_16m`) and pick the size that
matches your board; do not use `--all-features`. `usb_serial` adds the flash unique ID as the USB serial number
(off by default: it lets hosts recognise the device across connections).

**Commit `Cargo.lock`.** There is none in this tree (it needs a successful build to generate); without it every build resolves
the newest crates, so the same source can produce different firmware at different times. Generate it with a successful build and
commit it; `build.sh` then builds `--locked` only.

### One-command UF2 build (`build.sh`)
`bash build.sh [-s 2|4|8|16] [-u] [-t TOOLCHAIN] [-r REPO_URL] [-b BRANCH] [-o OUT_DIR]` clones the repository,
fetches OpenSK at the pinned commit (or the submodule commit), installs the toolchain and `elf2uf2-rs`, builds with
the right `--features` (`-s` flash size in MiB, `-u` adds the USB serial number) and writes
`out/pico-fido-rs-<N>m.uf2`. Hold BOOTSEL while plugging in and copy the file to the `RPI-RP2` drive. It builds the
*committed* revision of the repository. **The default `-b` is `openSK-based-se4`** (this branch); pass `-b` to build another branch. With a committed `Cargo.lock` the script builds with `--locked` only and fails instead of resolving newer crates; without one it warns and builds unlocked. This script itself was only syntax-checked; the maintainer's Colab build
(same toolchain and features) is what was run on hardware.

## Watchdog (optional)
Build with `--features watchdog` to enable the RP2040 watchdog (8 s). Only the main thread feeds it (`src/wdog.rs`), so a hang or a
stack-overflow fault ends in a reset. It is off by default: a single blocking step longer than 8 s without feeding (Argon2, a signature, a
store compaction) would reset the device in the middle of a command, so time the longest step on your hardware first. Not built or tested.

## Stack protection and measurement
The firmware is linked with [`flip-link`](https://github.com/knurling-rs/flip-link) (`.cargo/config.toml`; `cargo install flip-link --locked`,
done by `build.sh` and CI). It puts the stack below the statics, so an overflow faults instead of overwriting the heap or the secret-guard
state. To measure the real headroom build a development image with `--features stack_probe`: it paints the unused stack at boot and logs
`stack: peak N of M bytes` (defmt) whenever the peak grows, so run PIN, makeCredential, getAssertion (resident and not) and large-blob
flows and read the log. Not measured yet.

## U2F attestation
U2F registration needs an attestation key and certificate, which this firmware does not contain. OpenSK provides
`tools/configure.py` (uses the `config_command` feature) to write them; that path was not tried here.
`use_batch_attestation` is off, so FIDO2 registrations use self attestation.

## PIN and key protection
At least **10 code points** (`default_min_pin_length` in `src/env/mod.rs`). Set it with any FIDO2 client
(`fido2-token -S`, `ykman fido access change-pin`, Chrome/Windows security-key settings).

With a PIN set, the 32-byte master seed is wrapped with **Argon2id** (64 KiB static buffer; `M_KIB` = 64, `T_COST` = 24 in
`src/wrap.rs`) and no PIN hash is stored; a wrong PIN is detected by the record's HMAC-SHA-256 tag (keys derived with Argon2id), so no separate PIN
verifier exists. The 128 bytes of OpenSK master keys
are derived on demand from the seed, which after a correct PIN lives in RAM only as XOR shares (see **RAM
guard** below) and is dropped on USB reset / suspend / unplug. Resident
credentials are encrypted under keys derived from the master. The PIN retry counter (8 tries) is the vault's.

## SRAM PUF
`src/puf.rs`. The power-up pattern of 496 reserved RAM bytes is turned into a device-bound key by a fuzzy extractor
(128-bit secret, 31x repetition code, helper data + 8-byte check in the PUF sector). The key is reconstructed on demand and never stored; it exists in RAM only while it is used, in `Zeroizing` buffers that are wiped when
their lifetime ends (including the temporary secret of the helper-data check). It is mixed into the Argon2 password (`HMAC(K_puf, PIN hash)`) and masks the seed of a no-PIN
record, so **a copy of the flash alone no longer allows offline PIN guessing or recovering the seed**. Records written
by an older build are bound automatically (no-PIN: at boot; PIN set: after the next correct PIN, one extra Argon2
run). First boot enrols the PUF (needs a power-on reset, i.e. plugging the Pico in). Every boot logs the measured
bit errors (`puf: N bit errors of 3968`): read them over RTT on your chip before trusting it. If the key cannot be
recovered (power-up pattern too noisy, RAM still charged from a quick unplug), the PIN dialog fails with a hardware
error that is **not** counted as a wrong PIN: unplug for about 10 s and retry.

**Fail closed.** With `sram_puf` the key is required. A PUF failure never results in a plain or unbound seed record or
PIN record: a blank vault is only ever initialised with a PUF-bound seed (no plain seed touches flash first), an
existing unbound record is used only once it can be bound, `set_pin` refuses without the key, and a CTAP reset is
refused (nothing touched, no reset marker) unless the PUF can be (re-)enrolled on a power-on reset. A failed binding
of an existing record also locks the device (the correct PIN is accepted as such but does not unlock; the binding is
retried on the next entry). **A blank helper sector is not treated as "new device" when the vault already holds a PUF-bound
record (or is damaged / unreadable):** the firmware then does not enrol (that would create a different PUF secret and orphan the
seed), stays locked and shows the LED fault pattern until a CTAP reset on a power-on reset re-enrols. PUF-bound records carry an
HMAC tag over the masked seed, so a wrong PUF key can never yield a wrong seed silently (records from older builds without the tag
are accepted once and re-sealed at the next boot with a working key). A migration (binding an old unbound or untagged record to the PUF) counts as done only when the older record is confirmed wiped and the new
one is durable; otherwise the device locks with the LED fault pattern and the next boot retries (with the PUF required, `vault::open`
also locks while an older record cannot be wiped). Every locked state shows the fault pattern. A pending reset that fails at boot for any reason other than the missing PUF key no longer aborts the boot: the device stays locked
(LED fault pattern), the marker stays and the next boot repeats the reset. The PUF helper has two flash slots and every PUF-bound record names its slot: a re-enrolment writes the other slot, the new record is
written, and only then the old helper is erased. A power cut anywhere in a CTAP reset therefore leaves a usable (record, helper) pair, and the
next boot erases whichever helper the record does not name. While the key is unavailable no PIN attempt is counted and the retry counter is not touched. The device stays locked and the **LED shows the fault pattern: 3 short blinks, then a pause**, until a
boot with a working key. Boot does not panic on a postponed reset. The only way out without a working PUF is a build
without `sram_puf` (`build.sh -P`), which cannot read a PUF-bound record: that case is also reported by the LED. **It does not protect against anyone who can run code on the device (BOOTSEL, SWD)**: see `SECURITY.md`.

**Consequences:** after every USB reset the PIN must be entered once before *any* credential-ID operation works,
including U2F and `uv=discouraged` assertions. Without a PIN the seed is stored unwrapped in flash (masked by the SRAM PUF when that is enabled, see below). `T_COST` is untuned:
time a PIN check on hardware (the comment in `src/wrap.rs` targets roughly 0.5 to 1 s per check; that is a target,
not a measurement). See `SECURITY.md`.

## RAM guard
`src/ram_guard.rs` (pure logic) and `src/guard.rs` (firmware singleton): the master seed is held as `N` = 8 XOR
shares (`SHARES` in `guard.rs`, 4..=16, compile-time checked) in randomly chosen, non-adjacent slots of a 2 KiB
static pool whose other slots are random decoys. Shares are re-randomised by XORing fresh masks into share 0 and
share i (a refresh itself never reconstructs the secret; key use and PIN checks do, briefly, see `SECURITY.md`).
Masks come from a ChaCha20 DRBG seeded once at boot (ROSC, flash unique ID, ADC noise, timer jitter, conditioned
pool -> SHA-256) and reseeded about once a second. Temporaries are `Zeroizing`; secret types have no `Debug`.

How the refresh uses the CPU (`guard::tick_task`, on the interrupt executor, so it also runs while the main thread
signs or waits for the button):
* **Adaptive rate:** every 0.5 ms while the device is in use (a packet, a seed store or a reveal in the last 3 s),
  every 2 ms when it holds a seed but is idle, and only a 50 ms heartbeat without a seed (nothing to protect).
* **Short critical sections:** a refresh is 7 independent pair steps, each in its own critical section (about one
  ChaCha20 block and two 32-byte XORs). USB and the other interrupts are served between the steps, and the secret is
  valid after every step. `guard_log` / the display show the longest section actually measured.
* **Just in time:** the seed is revealed only inside `reveal_seed_into` / `with_seed` into a caller `Zeroizing`
  buffer (refreshed right before and after); the derived 128-byte master is written into the caller's buffer
  (`master_into`), not returned by value.
* **Scrubbing:** after every command, on a cancel, and (32 KiB) at boot, `src/scrub.rs` overwrites the dead stack
  frames below the caller with volatile stores, to remove copies left by moves and by the hash/HMAC code. Registers
  are not touched.
* **Idle:** the main thread sleeps in `wfi` between polls (`wdog::poll_wait`) instead of spinning; the guard task's
  timer and the USB interrupts wake it. Time asleep is the idle share of the CPU load on the display.

More frequent refreshing does not by itself make the secret safer; see `SECURITY.md` for what the guard does and
does not buy, and the stress-test procedure below.

### Stress test (hardware)
Build with `--features guard_log,stack_probe` (defmt over RTT/probe) and run, each for several minutes:
1. a loop of `fido2-token`/browser registrations and assertions (with and without PIN) while a CPU-heavy host
   process runs: check that the logged `longest critical section` stays small and `latest tick ... late` stays
   below the USB frame time, and that no operation fails or times out;
2. USB reset / suspend / replug cycles during traffic (see "USB cancellation");
3. a long idle period with the seed held (the period must settle at 2000 us, the CPU load near 0 %);
4. with `--features watchdog`: the longest PIN derivation, signature and store compaction against the 8 s limit;
5. current draw of the board idle (guard at 2 ms, `wfi` sleep) and under load, compared with the old build.
Record the numbers in `REVIEW.md`; none of this has been measured yet.

## PIN entry with an IR remote (VS1838B)
Feature `ir` (on by default; `build.sh -I` leaves it out). Wiring: VS1838B **OUT -> GP15**, VCC -> 3.3 V, GND (the
same pin as the MicroPython reference). The receiver (`src/ir.rs`) is a port of its NEC decoder (same timings and
check bytes) running as an interrupt-executor task; `src/nec.rs` holds the pure helpers (host-tested).

How it is used: in the host's normal PIN dialog type the **magic PIN `0000000000` (ten zeros)**. The device then
asks for the real PIN on the remote:
* **Setting a PIN** (first use, or the new PIN of a PIN change): the OLED shows `SET PIN (IR REMOTE)`, the key count
  and one `*` per key. Press at least **8** keys, confirm with a short press of **BOOTSEL**; then repeat the same
  sequence (`STEP 2/2`) and confirm again. A different second sequence starts over.
* **Using it** (every PIN prompt of the host, also when changing the PIN): type the ten zeros in the dialog, press the
  same keys on the remote, confirm with BOOTSEL.
* **Cancel:** hold BOOTSEL for 1.5 s. 60 s without any key or button, a USB reset or a cancel from the host also end
  the entry. A cancelled or timed-out entry counts as a wrong PIN attempt (the attempt is counted before the PIN is
  looked at; it cannot be refunded without forgiving earlier failures).
* While waiting the device sends CTAPHID keepalives, so the host keeps waiting instead of timing out.

The PIN hash is `SHA-256("pico-fido-ir-pin-v1" || key count || the full 32-bit NEC codes)[..16]`: every key counts
with its whole 32-bit code, in order. **How strong that is:** a NEC code is `address, ~address, command, ~command`;
only the command byte (and the fixed address of the remote) carries information, so a key is worth about
log2(number of keys) bits, roughly 4.4 on a 21-key remote: 8 keys are about 35 bits, not 256. Use more keys if you
can (up to 32). Codes are fixed per key and IR can be seen or filmed: anyone who watches you press the keys learns the
PIN, as with a typed PIN. BOOTSEL is the physical confirmation: nobody can finish an entry from across the room with
an IR blaster. The OLED never shows the codes.

Typing `0000000000` as a normal PIN is no longer possible with this feature (it always means "use the remote").

## Status display (SSD1306 OLED)
Feature `oled` (on by default): a 128x64 SSD1306 on **I2C0, SDA = GP16, SCL = GP17, address 0x3C** (same wiring as
the MicroPython `ssd1306.py` example), 3.3 V and GND. Without a display nothing happens (the write is not
acknowledged; it is probed again every 5 s). The status is drawn from the main thread while it waits for packets
or the button, one 128-byte page per step (about 12 ms at 100 kHz), so it never blocks USB:

```
FIDO OPEN USB OK           FIDO: LOCK / OPEN / BUSY / FAULT      USB: -- / OK / SLP
PIN SET PUF OK S1          PIN set or not; SRAM PUF OFF / BLANK / BAD / NOISY / OK and helper slot
CPU 12% UP 1:23:45         CPU load estimate (1 - time asleep, minus the guard refresh), uptime
RAM 153K/264K HP 12K       RAM in use (statics incl. the 128 KiB heap + stack + PUF bytes), heap in use
STK 1.2K PK 5.0K           stack now, peak (peak needs --features stack_probe)
GRD 1990/S P500US          RAM-guard full refreshes per second, current period
CS61US LT480US P1234       longest refresh critical section, latest tick lateness, packets handled
FW214K ST12/70K W3%        firmware size, key-value store use, erase budget used
```
The display never shows secrets. It needs `GP16`/`GP17` free (the default board uses GP25 for the LED); build
with `build.sh -O`, or `--no-default-features --features rp2040_board,flash_2m,sram_puf`, to leave it out.

**Blank screen? Check in this order.**
1. **The firmware has the feature.** `cargo build` enables `oled` by default, but `build.sh` (and any build with
   `--no-default-features`) only has what it lists: since this fix `build.sh` adds `oled` unless you pass `-O`; the
   build log prints `Cargo features: ...,oled`. Rebuild and reflash an older UF2. The RTT log then shows
   `oled: display found at 0x3C` or `oled: no display answered ...`; no `oled:` line at all means it is not compiled in.
2. **Pull-ups.** MicroPython's `machine.I2C` enables the RP2040's internal pull-ups, which is why the stock example works with
   bare modules; embassy-rp does not. `oled::init` now switches them on for GP16/GP17 and runs the bus at 100 kHz
   (`I2C_HZ`; use 400_000 only with external 4.7 kOhm pull-ups). Modules with their own pull-ups are unaffected.
3. **Wiring.** SDA = GP16 (pin 21), SCL = GP17 (pin 22), 3V3 (pin 36), GND (pin 38). Swapped SDA/SCL gives the same
   "no display answered" line. A module at address `0x3D` (some have a solder jumper) needs `ADDR` in `src/oled.rs`.
4. **Start-up timing.** The module may not answer in the first milliseconds: the firmware waits 100 ms, probes once and
   retries after 0.5 s, then every 5 s, so a late display appears by itself within a few seconds.
5. **Controller.** A 1.3" module is often an SH1106 (132 columns), not an SSD1306: the picture is then shifted by 2
   columns or garbled, but not blank. The status text appears about 0.5 s after the start.
Not tested on hardware by the author of this fix: confirm with the RTT log if it is still blank.

## USB cancellation
USB reset, suspend, disable and deconfigure call `env::hid::cancel_all()`: it bumps an epoch, forgets the seed
(with a PIN set) and flushes both queues. The user-presence wait, packet waits and `send` check the epoch, so a
pending button wait ends within 5 ms with `Canceled`, a late button press or a packet of the new session cannot
complete the old operation (a packet that was dequeued just before the reset is discarded, and every operation is stamped with the epoch under
which its packet arrived, not with the epoch at the time it starts), and the cancelled operation's responses are dropped. The main loop then calls
`Ctap::cancel_in_flight()` (patch below). A signature already being computed cannot be interrupted; its result is
discarded.

## OpenSK patch
`third_party/opensk-harden.patch` (applied by `build.sh`, or manually with `patch -p1 -d third_party/OpenSK <
third_party/opensk-harden.patch`) adds `Persist::unlock_with_pin` (default: legacy behaviour), calls it in
`verify_pin_hash_enc`, and adds `Ctap::cancel_in_flight()` (drops the pending U2F touch, PIN tokens, HID state and
stateful commands, but keeps the power-up Reset window). `build.sh` replaces an older version of the patch.
Re-check it whenever `OPENSK_REV` changes.

## Tests
    sh host-test/run.sh     # OpenSK's own library unit tests (the protocol logic), run on the host
                            # + host-test/guard: ram_guard, vault (store.rs) and wrap (PIN wrap, Argon2 bounds, PUF-masked record) unit tests, and nec (IR frame checks, timing classes, PIN digest)

The earlier host tests (custom CBOR, CTAPHID, PIN, key store, python-fido2 end-to-end) tested code that no longer
exists and were removed. **Nothing in this repository tests `src/env/*`, the USB bridge or the executor split**:
they are checked on hardware only.

## Verification status (be honest about it)
Reported by the maintainer (not independently verified): this branch was built and flashed to a Raspberry Pi Pico and tested on hardware, and
the OpenSK-based firmware family (this branch included) **works on Linux, Windows and Android**. The base firmware was built with the Colab script
(`nightly-2026-06-03`, `flash_2m`, no `usb_serial`, size-optimised release profile), flashed to a Pico, and
**working on Linux, Windows and Android with all tried browsers**. This is the behaviour the earlier custom
firmware did not have on Windows and Android. The maintainer did not record the details of the hardening tests (see the list below).

Checked while preparing this tree:
* The firmware patch that created `src/env/*` and the OpenSK wiring applies cleanly, and `src/`, `build.rs` and
  `rust-toolchain.toml` here are identical to it.
* The OpenSK library alone, at the pinned commit, with `ctap1,software_crypto`, type-checks for
  `thumbv6m-none-eabi` (check only).

**Hardening status:** `HardenPersist`, the vault and the patch were first written without compiling (the first build found three errors, since fixed). The branch has since been built and run on a Pico by the maintainer. **No detailed test record exists** for: Argon2 timing and heap/RAM headroom, PIN set/change/verify, resident credentials after reboot, power loss during setPIN/reset, lock on USB reset, the RAM guard, USB cancellation and vault-update checks, and the SRAM PUF (measured bit errors per boot: see `REVIEW.md`). Treat these as working in the maintainer's use but not systematically verified.

**Not done / unknown:**
* `cargo clippy -- --deny=warnings`, `cargo fmt --check` and the CI workflow were never run on this tree.
* No documented test matrix: which sites, PIN dialogs, U2F-only sites, resident keys, reset, power loss during a
  flash write, P-256 signing time, RAM headroom (128 KiB heap), and RNG health tests on a real ring oscillator.
* `build.sh` end to end, and U2F attestation provisioning.
* USB VID/PID (`0xc0de:0xcafe`) and strings are prototype placeholders (`src/usb/mod.rs`).
