# pico-fido-rs (se-harden0)

A small, software-only FIDO2 / CTAP2 security key for the Raspberry Pi Pico (RP2040), written in Rust with Embassy.
**Experimental. Read `SECURITY.md` before relying on it.**

Maintainer-reported (not independently verified): built, flashed to a Raspberry Pi Pico and tested; works in Linux browsers, not tested on Windows or Android.

This revision has no build, usage or verification notes of its own. What the other two files here say about it:
* ES256 credentials, stateless (derived from one 32-byte master key); no resident keys, no PIN, sign counter always 0,
  attestation `none`. The master key is stored in plain flash (two sectors at the end).
* Registration and reset need a fresh BOOTSEL press. A getAssertion with `options.up = false` is signed without one in
  this revision.
* `reset` is accepted only within 10 s of power-up.
* `REVIEW.md` covers review round 1 only. The round 2 fixes listed in the `se-harden1` branch's `REVIEW.md` (for
  example `up = false`, canonical CBOR map order, a reset with an unknown storage position) are not part of this
  revision.

**Build:** the `se-harden1` README's build commands do not apply here. This revision's `Cargo.toml` has only the
default feature `rp2040_board`; the `flash_*` and `usb_serial` features arrive in `se-harden1`. For tests and the
verification status see the `se-harden1` README, with the same caveat.
