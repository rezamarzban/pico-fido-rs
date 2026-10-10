# pico-fido-rs + ATECC608 (Option A: keys live in the chip)

**Status: written but NOT compiled or run by the author of this change (no Rust toolchain/network was
available). Expect to fix a few compile errors and to debug the first I2C contact. Use a spare chip.**

## What changed
- Private keys are generated (`GenKey`) and used (`Nonce` + `Sign`) inside the ATECC. The RP2040 only sends a 32-byte digest.
- Own small driver `src/atecc.rs` (no `at-cryptoauth` crate, so no Embassy/defmt migration; stays on Embassy 0.6 / defmt 0.3).
- HMAC/master-key/software-p256 signing removed. `keys.rs` is now a flash table: index = ATECC slot (0..7).
- Max **8 credentials**, resident or not (every credential uses a slot). 9th registration -> `KEY_STORE_FULL`.
- `rk: true` in getInfo; discoverable login returns the newest matching credential (no getNextAssertion).
- Reset (CTAP 0x07) overwrites used keys in the chip and clears the table.
- Credential ID = `[version=1][slot][14 random bytes from the ATECC RNG]`.

## Wiring (ATECC608A/B, default address 0xC0 = 0x60 7-bit)
Pico GP4 = SDA, GP5 = SCL (I2C0), 3V3, GND, 4.7k pull-ups on SDA/SCL if the breakout lacks them.
Change the address in `atecc.rs` (`ADDR`) for non-default parts. TNG/Trust&Go parts are pre-locked: unusable.

## One-time provisioning (IRREVERSIBLE)
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
