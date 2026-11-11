# ATECC608A secure element

The chip does six things and nothing else. Everything else runs on the Pico.

| In the chip | Chip command | Where in the firmware |
|---|---|---|
| Credential private keys (9 slots, never readable) | - | slots 1-9 |
| Attestation private key (1 slot, created once) | - | slot 0 |
| Key generation | GenKey (create) | `se/ecdsa.rs` `random()` |
| ECDSA P-256 signing | Nonce (pass-through) + Sign (external) | `sign()` |
| Public key extraction | GenKey (public mode) | `import()` |
| Random numbers | Random | `env/rng.rs` (seed of a ChaCha20 DRBG) |

**No chip counter is used and nothing but keys is stored in the chip.** Signatures are unlimited (see "Signatures" below).
There is **one key per site**: a new site takes the first credential slot that already holds a private key and
belongs to no other site (the key is used as it is), or, if there is none, the first empty slot (public-key read
fails with status 0x0F), where GenKey creates a key. Which site owns which slot is recorded in a directory in the
**Pico's flash** (one directory per chip, told apart by the chip's unique serial number, so several chips can be used with the same key) (`src/env/dir_flash.rs`), not in the chip; later accounts at the same site find their slot there and
use no new one. Slots that belong to a site are never overwritten. For the OLED the firmware also reads
the chip's identity once (Info revision + config-zone reads: serial number, I2C address, lock bytes) and scans
the 9 credential slots once at start-up (about 0.5 s).

On the Pico: OpenSK with its standard key-value store, ClientPIN (PIN hash in flash),
SHA-256 / HMAC / AES / HKDF / ECDH in software, BOOTSEL as user presence, USB.

## Wiring
Part: ATECC608A-**SSHDA**-B = 8-lead SOIC, I2C (datasheet DS40001977B, pins seen from the top).
| ATECC608A SOIC-8 pin | Signal | Pico / RP2040-Zero |
|---|---|---|
| 5 | SDA | GP14 (I2C1 SDA) |
| 6 | SCL | GP15 (I2C1 SCL) |
| 8 | VCC | 3V3 |
| 4 | GND | GND |
| 1, 2, 3, 7 | NC | not connected |

I2C address 0x60 (config byte 0xC0), 100 kHz. Internal pull-ups are enabled; most breakouts have
their own. The SSD1306 display stays on I2C0 (GP16/GP17), so the two never share a bus. Without the
chip the firmware halts at start-up (the credential keys and the RNG seed come from it).

## Slot layout (the config image: `out/atecc608a_general_config.bin`)
* **Slot 0: attestation key** (ECC P-256, created once with `tools/make_attest_cert.py`; the firmware
  never overwrites it).
* **Slots 1-9: credential keys, one per site** (9 sites). A site that has no key yet takes the first slot that
  holds a key and belongs to no other site (used as it is); if there is none, the first slot that holds no key gets
  a new key (GenKey). **A slot that belongs to a site is never regenerated or overwritten.** Further accounts at that
  site reuse its key. A registration at a 10th site is refused (the firmware panics and restarts; unplug/replug),
  and the 9 existing keys stay. A FIDO reset does NOT clear the site list (it is in its own flash page, outside
  OpenSK's store). If the chip refuses GenKey in an empty slot, the firmware skips it (that slot is
  never used; check with `ecc-gen 8` / `ecc-gen 9` on your chip).
* Every slot 0-9: SlotConfig `81 20`, KeyConfig `13 00` = ECC P-256 private key, secret, external
  signatures only, no ECDH, no PrivWrite, **GenKey allowed** (regenerable after locking), public key
  derivable, **no LimitedUse bit**.
* **Slot 13: not used any more.** Earlier firmware kept the site directory there; this firmware neither reads nor
  writes it (the directory is in the Pico's flash: 4 KiB page below the OpenSK store, format in `src/se/dirlog.rs`).
  The slot keeps its general-config values and nothing needs to change in the chip's configuration. Old content
  stays until you overwrite it yourself.
* Slots 10-12, 14, 15: not used by this firmware; they keep the general config's values (SlotConfig `8F8F 8F8F 0000 0000 0000 8F8F`, KeyConfig `1800 1C00 3000 3C00 3C00 1C00`).
* Counters: not used by the firmware. Counter 0 / 1 fields are the factory value 0 (`FFFFFFFF 00000000`, ignored), LastKeyUse is `00` and ChipMode `00`, all as on a factory-default chip. Byte 14 (I2C_Enable, `01` in the image) and the serial are read-only on the chip.

A credential ID holds a 32-byte *handle* `[01][slot][6-byte public-key fingerprint][zeros]` inside
OpenSK's normal encrypted credential ID. `import()` rejects a handle whose slot holds a different key than the handle was made for.

**If your attestation key is not in slot 0:** the slot numbers are two constants, `ATTEST_SLOT` and
`FIRST_CRED_SLOT` in `src/se/ecdsa.rs` (and `ATTEST_SLOT` in `tools/make_attest_cert.py`). The
credential slots must never include the slot that holds the attestation key.

## Provisioning (already done for your chip; kept for a new one)
```
python3 tools/gen_atecc_config.py --slots 10 -o out   # byte-identical to out/atecc608a_general_config.bin; or --base your_read_config.bin
atecc ... write-config out/atecc608a_fido_config.bin
atecc ... lock-config                # irreversible
atecc ... lock-data                  # irreversible; GenKey stays enabled on the key slots
atecc ... ecc-gen 0 pub0.bin         # attestation key (or make_attest_cert.py does it)
python3 tools/make_attest_cert.py --out attest                     # once: certificate for slot 0
```
`--check cfg.bin` decodes any dumped config (and the shipped `out/atecc608a_general_config.bin`).

### Attestation key and certificate
`tools/make_attest_cert.py` (needs the `cryptoauthlib` and `cryptography` Python packages, the chip on
a host I2C bus) does GenKey in slot 0, has the chip sign a self-signed X.509 certificate for that
public key, and writes:
* `attest_cert.der` / `.pem`: the certificate,
* `attest_key.hex` / `.pem`: the 32-byte **handle** of the key (not a secret; it only names the slot
  and carries a fingerprint of the key that must be in it).

The token then needs the certificate and the handle once, through OpenSK's attestation material
(`config_command` feature: `tools/configure.py --certificate=attest/attest_cert.pem
--private-key=attest/attest_key.pem`). It refuses to overwrite an existing key unless you pass
`--regen`. `python3 tools/make_attest_cert.py --selftest` checks the tool without hardware.

What attestation is used for: U2F registration always; FIDO2 registration only if
`use_batch_attestation` is set to `true` in `src/env/mod.rs` (default `false`: packed
self-attestation with the credential key). Note the privacy cost of turning it on: the certificate is
unique to this device, so every site can recognise it.

## Signatures
There is no signature budget: the firmware signs as often as it is asked and does not touch Counter 0.
A chip provisioned earlier with a counter value keeps it; it is ignored. The attestation
key and the credential keys sign the same way (Nonce pass-through + Sign). The price is that nothing in
the chip limits what code on the Pico, or a probe on the I2C bus, can have signed (see SECURITY.md).
Never set LimitedUse on these slots unless you want the chip itself to count.

## Acceptance test on real hardware (do this before locking a chip you care about)
1. Sign more than 500 times through a browser/`fido2` tool: every signature works and `counter-read 0` does not change.
2. OLED, second page: serial number, revision (`00006003`) and both lock states match `atecc ... info` / `read-config`.
3. Register at 9 different sites (the OLED shows `KEYS 9/9 PRESENT` and `SITES 9/9 ASSIGNED`), then try a 10th site: it must be refused and all
   nine must still work. Register a second account at one of the 9 sites: it must succeed and `SITES` must not
   change (the site list is read from the Pico's flash; if `SITES` grows, the second account took a new slot, which
   means the directory page was not saved). With a spare chip that already has keys in some slots, check that new
   sites take those keys first and run GenKey only in the empty slots. First check on a spare chip that `ecc-pub` of an unused credential slot fails
   (the firmware relies on that to tell a free slot from a used one; if your chip answers differently, no
   registration will work: it fails safe).
4. Unplug/replug: the used-slot count must be the same (it is read from the chip).
5. After the attestation step: a U2F registration succeeds (e.g. webauthn.io with a U2F-only
   option).

## What this design does not protect
* There is no PIN or authentication in the chip. Whoever can talk to the chip on the I2C bus (code
  running on the Pico, or a probe on GP14/GP15) can ask it to sign, without limit. The
  PIN (ClientPIN) is checked by the Pico firmware only.
* The I2C bus is not encrypted.
