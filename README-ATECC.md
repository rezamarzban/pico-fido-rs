# pico-fido-rs + ATECC608 (keys live in the chip)

**Status: written but NOT compiled or run by the author of this change (no Rust toolchain/network was
available). Expect to fix a few compile errors and to debug the first I2C contact. Use a spare chip.**

## What changed
- Private keys are generated (`GenKey`) and used (`Nonce` + `Sign`) inside the ATECC. The RP2040 only sends a 32-byte digest.
- Own small driver `src/atecc.rs` (no `at-cryptoauth` crate, so no Embassy/defmt migration; stays on Embassy 0.6 (`embassy-executor` / `embassy-sync` 0.6, `embassy-rp` 0.2.0) / defmt 0.3).
- HMAC/master-key/software-p256 signing removed. `keys.rs` is now a flash table: index = ATECC slot (0..7).
- Max **8 credentials**, resident or not (every credential uses a slot). 9th registration -> `KEY_STORE_FULL`.
- `rk: true` in getInfo; discoverable login returns the newest matching credential (no getNextAssertion).
- Reset (CTAP 0x07) overwrites used keys in the chip and clears the table. Unlike `atecc-se0` it is **not** limited to the first 10 s after power-up, and the table entry is cleared even if overwriting the key in the chip failed.
- Credential ID = `[version=1][slot][14 random bytes from the ATECC RNG]`.

## Flash size
Fixed for a 2 MiB Pico (`memory.x`, `FLASH_SIZE`); there are no `flash_*` features.

## Wiring (ATECC608A/B, default address 0xC0 = 0x60 7-bit)
Pico GP4 = SDA, GP5 = SCL (I2C0), 3V3, GND, 4.7k pull-ups on SDA/SCL if the breakout lacks them.
Change the address in `atecc.rs` (`ADDR`) for non-default parts. TNG/Trust&Go parts are pre-locked: unusable.

## One-time provisioning (IRREVERSIBLE)
`cargo run` uses the runner `probe-rs run --chip RP2040` (`.cargo/config.toml`): an **SWD debug probe is required**, and the defmt log (RTT) is the only output.
```
cargo run --release --features provision    # watch the defmt log
```
It writes SlotConfig=0x2083 / KeyConfig=0x0033 for slots 0..7, verifies read-back, locks the config zone,
locks the data zone, then does GenKey+Sign+software-verify as a self-test ("selftest OK").
Afterwards flash the normal build (`cargo run --release`); never ship the `provision` build.
A chip that is already locked with a different layout cannot be used.

## Known risks to check on first run
1. Wake pulse: uses a write to address 0x40 (embassy-rp refuses address 0x00). If `ATECC not responding`,
   try `I2C_HZ = 50_000` in `main.rs`.
2. `embassy_rp::i2c::Async` path in `atecc.rs` (`Bus`) may need adjusting for embassy-rp 0.2.0.
3. Error-path reads clock more bytes than the chip returns; success path is unaffected.
4. Sign counter is 0, attestation "none" (as before).
5. `host-test` now only tests CTAPHID framing; the old FFI/e2e test was removed (it tested the stateless code).
6. The ATECC has no user-presence check: anyone with access to the I2C bus can request signatures; the button is
   enforced in firmware only (as documented for `atecc-se0`).

## After provisioning: normal build, UF2 flash and smoke test
The disclaimer above still applies: none of this was compiled or run by the author.

1. **Provision first** (see above); continue only when the lock steps report success.
2. **Build the normal firmware** (no `provision*` feature): `cargo build --release`. The target is set in `.cargo/config.toml`, so the ELF is `target/thumbv6m-none-eabi/release/pico-fido-rs`.
3. **Make a UF2:** `cargo install elf2uf2-rs`, then
   `elf2uf2-rs target/thumbv6m-none-eabi/release/pico-fido-rs pico-fido-atecc.uf2`
4. **Flash:** hold BOOTSEL while plugging the Pico in, copy the `.uf2` to the `RPI-RP2` drive. (With a probe, `cargo run --release` flashes the same build and shows the log.)
5. **Smoke test** on a throwaway account such as https://webauthn.io:
   - `fido2-token -L` lists the device and `fido2-token -I <device>` returns getInfo. This only proves USB works: the firmware enumerates even when the ATECC is missing or not provisioned (it then only logs an error over RTT, and credential operations fail).
   - Register and log in; touch BOOTSEL when the LED is almost solid. A successful registration is the real check that the chip answers.
   - If registration fails: check wiring and pull-ups, read the RTT log with a probe (`ATECC not responding` / `not provisioned`), and try `I2C_HZ = 50_000`.
   - Optional: register a discoverable credential, unplug and replug, log in again (flash table + chip slot).
   - Optional: register more than 8 credentials; the 9th must fail with `KEY_STORE_FULL`.
