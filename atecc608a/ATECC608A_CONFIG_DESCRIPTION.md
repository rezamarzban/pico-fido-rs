# ATECC608A configuration: full description

Image described: `atecc608a/out/atecc608a_general_config.bin` (project `pico-fido-rs-atecc2.zip`).
It is the 128-byte **config zone** as `atecc write-config` expects it. It is produced byte for byte by
`python3 tools/gen_atecc_config.py --slots 10`.

> Bit meanings below are from the ATECC608A datasheet (DS40001977B) as I know it and from the comments in
> `tools/gen_atecc_config.py`. Verify against the datasheet before you run `lock-config`, which is irreversible.
> Not tested on real hardware.

## 1. Raw image

```
00: 0000 0000 0000 0000 0000 0000 0000 0100
10: c000 0000 8120 8120 8120 8120 8120 8120
20: 8120 8120 8120 8120 8f8f 8f8f 0000 0000
30: 0000 8f8f ffff ffff 0000 0000 ffff ffff
40: 0000 0000 0000 0000 0000 0000 0000 0000
50: 0000 0000 0000 5555 ffff 0000 0000 0000
60: 1300 1300 1300 1300 1300 1300 1300 1300
70: 1300 1300 1800 1c00 3000 3c00 3c00 1c00
```

## 2. Byte map

| Bytes | Field | Value in image | Meaning |
|---|---|---|---|
| 0-3 | SN[0:3] | `00 00 00 00` | Serial number. Read-only on the chip; ignored by write. |
| 4-7 | RevNum | `00 00 00 00` | Revision. Read-only (your chip: `00 00 60 02`). |
| 8-12 | SN[4:8] | `00` x5 | Rest of the serial. Read-only. |
| 13 | Reserved | `00` | Read-only. |
| 14 | I2C_Enable | `01` | Bit 0 = 1 means I2C mode (0 = SWI). Read-only on the chip (yours reads `3D`, bit 0 is also 1). |
| 15 | Reserved | `00` | Read-only. |
| 16 | I2C_Address | `C0` | 8-bit form of address; 7-bit address is `0x60`. |
| 17 | Reserved | `00` | |
| 18 | CountMatch | `00` | Counter-match feature off. |
| 19 | ChipMode | `00` | Factory default: bit 0 TTLenable = 0 (fixed input reference), bit 1 watchdog = 0 (about 1.3 s), clock divider default. |
| 20-51 | SlotConfig 0-15 | see section 3 | 2 bytes per slot, low byte first. |
| 52-59 | Counter 0 | `FF FF FF FF 00 00 00 00` | Valid encoding of value 0. Not used by the firmware. |
| 60-67 | Counter 1 | `FF FF FF FF 00 00 00 00` | Same. Not used. |
| 68-83 | LastKeyUse | `00` x16 | Only meaningful for LimitedUse keys. Not used. |
| 84 | UserExtra | `00` | |
| 85 | Selector | `00` | |
| 86 | LockValue | `55` | Data zone **unlocked** (`00` = locked). |
| 87 | LockConfig | `55` | Config zone **unlocked** (`00` = locked). |
| 88-89 | SlotLocked | `FF FF` | No individual slot is locked (a 0 bit would lock that slot). |
| 90-91 | ChipOptions | `00 00` | All optional protections off (defaults). |
| 92-95 | X509format | `00` x4 | Not used. |
| 96-127 | KeyConfig 0-15 | see section 4 | 2 bytes per slot, low byte first. |

## 3. SlotConfig (bytes 20-51)

| Slot | Bytes | Role in this project |
|---|---|---|
| 0 | `81 20` | **Attestation key** (ECC P-256 private key, created once) |
| 1-9 | `81 20` | **Credential keys** (ECC P-256 private keys, one per site: 9 sites) |
| 10, 11 | `8F 8F` | Unused (general-config AES / SHA / data slots) |
| 13 | `00 00` | **Site directory** (data slot, clear read/write; see section 5) |
| 12, 14 | `00 00` | Unused |
| 15 | `8F 8F` | Unused |

Decoding `81 20` (ECC private key slot):

| Bit(s) | Name | Value | Effect |
|---|---|---|---|
| byte 0 bit 0 | external signatures | 1 | Sign command with an external message digest is allowed |
| bit 1 | internal signatures | 0 | not allowed |
| bit 2 | ECDH | 0 | not allowed |
| bit 3 | WriteECDH | 0 | not applicable |
| bit 4 | NoMac | 0 | |
| bit 5 | **LimitedUse** | 0 | **Off**: signature count is not limited by the chip |
| bit 6 | EncryptRead | 0 | |
| bit 7 | IsSecret | 1 | The private key can never be read out |
| byte 1 bits 3:0 | WriteKey | 0 | |
| byte 1 bits 7:4 | WriteConfig | 2 | Bit 1 set: **GenKey allowed** (key can be generated or regenerated, also after lock). Bit 2 (PrivWrite) clear: no writing a private key in |

Slots 10-15 keep the general-config values (`8F 8F` = ReadKey 15, WriteKey 15, IsSecret; `00 00` = no
restrictions). The firmware uses only slot 13 (`00 00` plus KeyConfig `3C 00`: a data slot with no read or write
restriction, 72 bytes); the others are never touched.

## 4. KeyConfig (bytes 96-127)

| Slot | Bytes | Meaning |
|---|---|---|
| 0-9 | `13 00` | Private = 1, PubInfo = 1, KeyType = 4 (ECC P-256). Not lockable, no ReqRandom/ReqAuth |
| 10 | `18 00` | KeyType 6 (AES key), not lockable |
| 11 | `1C 00` | KeyType 7 (not ECC: SHA key / data), not lockable |
| 12 | `30 00` | KeyType 4 with Private = 0 (ECC public key slot), lockable |
| 13, 14 | `3C 00` | KeyType 7 (data), lockable |
| 15 | `1C 00` | KeyType 7 (data), not lockable |

KeyConfig bits (low byte): bit 0 Private, bit 1 PubInfo, bits 4:2 KeyType, bit 5 Lockable, bit 6 ReqRandom,
bit 7 ReqAuth. For `13`: Private = 1 (a private key), PubInfo = 1 (its public key can be derived with GenKey),
KeyType = `100` = P-256. The high byte is `00` everywhere: no AuthKey, no IntrusionDisable, no X.509 index.

## 5. What the firmware uses the chip for

| Function | Chip command | Slots |
|---|---|---|
| Create key | GenKey (private-key mode) | 0-9 |
| Read public key | GenKey (public mode) | 0-9 |
| ECDSA P-256 sign | Nonce (pass-through) + Sign (external) | 0-9 |
| Random numbers | Random | n/a |
| Site directory (which site owns which key slot) | Read / Write, 32-byte blocks in the clear | 13 |
| Chip identity for the display | Info + config-zone reads | n/a |

A credential slot is "free" when the chip has no private key there (public-key read fails). A slot that holds a
key is never regenerated. **One key per site:** the directory in slot 13 holds, for credential slots 1-9, the first
7 bytes of the SHA-256 of the site name (7 x 9 = 63 of the first 64 bytes, all zero = empty). A registration looks
the site up there; if found, that key is used again and no slot is consumed, otherwise the first free slot gets a
new key and the site is entered. No counters, no LimitedUse, no PIN or authentication in the chip.

## 6. Difference from the factory-default chip (`config.bin`)

| Item | Factory default | This image |
|---|---|---|
| ChipMode (19) | `00` | `00` (same) |
| I2C address (16) | `C0` | `C0` (same) |
| I2C_Enable (14) | `3D` (bit 0 = 1) | `01` (bit 0 = 1; read-only) |
| SlotConfig 0-3 | `83 20`, `87 20`, `8F 20`, `C4 8F` | all `81 20` |
| SlotConfig 4-5 | `8F 8F` | `81 20` |
| SlotConfig 6-7 | `9F 8F`, `AF 8F` | `81 20` |
| SlotConfig 8-9 | `00 00` | `81 20` |
| SlotConfig 10-14 | `00 00` | `8F 8F`, `8F 8F`, `00 00`, `00 00`, `00 00` |
| SlotConfig 15 | `AF 8F` | `8F 8F` |
| KeyConfig 0-2 | `33 00` | `13 00` |
| KeyConfig 3-9 | `1C 00` / `3C 00` | `13 00` (ECC private) |
| KeyConfig 10-15 | `3C 00` (10-14), `1C 00` (15) | `18`, `1C`, `30`, `3C`, `3C`, `1C` |
| Counter 0 / 1 | `FFFFFFFF 00000000` | same |
| LastKeyUse | `00` x16 | same |
| Locks | unlocked (`55 55`) | unlocked (`55 55`) |

Net effect: only the slot types differ. Factory default has three ECC private slots (0-2); this image has ten
(0-9).

## 7. Provisioning (chip must still be unlocked)

```
atecc -b <bus> -c 'write-config atecc608a_general_config.bin'
atecc -b <bus> -c 'dump-config -'     # compare with this document
atecc -b <bus> -c 'lock-config'       # IRREVERSIBLE
atecc -b <bus> -c 'lock-data'         # IRREVERSIBLE; GenKey stays enabled on key slots
python3 tools/make_attest_cert.py --out attest   # once: attestation key in slot 0 + certificate
```

Check before locking: I2C address `C0`, slots 0-9 show `81 20` / `13 00`, `LockValue` and `LockConfig` still `55`.
After `lock-config` nothing in this table can be changed.

## 8. Limits of this configuration

* Anyone who can talk to the chip on the I2C bus (code on the Pico or a probe on the bus) can ask it to sign,
  without limit; the PIN is checked by the Pico firmware only.
* The I2C bus is not encrypted.
* The private keys never leave the chip (IsSecret), but the chip does not decide who may use them.
