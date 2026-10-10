# pico-fido-rs + ATECC608 (keys live in the chip)

**Status: NOT compiled or run by the author (no Rust toolchain/network was available).
Expect a few compile errors and some first-contact I2C debugging. Use a spare chip.**

## Design
- Private keys are generated (`GenKey`) and used (`Nonce`+`Sign` in ONE wake session) inside the ATECC.
- Own small driver `src/atecc.rs`; stays on Embassy 0.6 / defmt 0.3.
- 8 credentials max (ATECC slots 0..7), resident or not. Credential ID = `[1][slot][14 random]`, maxCredentialIdLength = 16.
- Flash table (`keys.rs`): two copies A/B in the last 8K (memory.x), each with sequence number + SHA-256.
  A new credential is generated into a FREE slot and only then committed by writing the inactive copy,
  so a power cut never leaves flash pointing at a replaced key. Re-registering the same (RP, user.id)
  discoverable credential replaces it in the same commit; this needs one free slot.
- Discoverable login: newest first, `numberOfCredentials` + `getNextAssertion` supported.
- Reset: only accepted if received within 10 s of power-up; overwrites used keys in the chip, keeps any
  entry whose key could not be overwritten and returns an error.

## Wiring
Pico GP4 = SDA, GP5 = SCL (I2C0), 3V3, GND, pull-ups (4.7k) if the breakout has none. Default address 0x60 (`ADDR`).
Trust&Go (TNG) parts are pre-locked and unusable.

## Provisioning (two stages)
1. `cargo run --release --features provision` - checks chip identity (ATECC608, serial prefix, address, no slot lock),
   writes SlotConfig 0x2083 / KeyConfig 0x0033 for slots 0..7, reads the whole config zone back, verifies it
   and dumps it to the log. Nothing irreversible. Review the dump.
2. `cargo run --release --features provision-lock` - same checks, then LOCKS config and data zones (IRREVERSIBLE),
   verifies both locks, and self-tests GenKey+Sign with a software verify (slot 0, only on a chip it just locked).
An already fully locked chip is never touched. Afterwards flash the normal build; never ship a provision build.

## Known limitations
- Flash table hash detects corruption, not deliberate tampering; user names/IDs are plaintext in flash.
- The ATECC has no user-presence check: anyone with access to the I2C bus can request signatures.
  The button is enforced in firmware only.
- CTAPHID cancel is not processed while an ATECC command runs (a few hundred ms at most).
- Sign counter 0, attestation "none".
- Unverified on hardware: wake pulse (address 0x40; try `I2C_HZ = 50_000` if the chip does not answer),
  `embassy_rp::i2c::Async` path in `Bus`, slot/key config values, error-path read length.
- `host-test` only covers CTAPHID framing.
