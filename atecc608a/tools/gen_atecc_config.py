#!/usr/bin/env python3
"""ATECC608A configuration for the FIDO key (pico-fido-rs).

  gen_atecc_config.py --slots 10 -o out/                      build a config image
  gen_atecc_config.py --slots 10 --base cfg.bin               patch your own `read-config` dump
  gen_atecc_config.py --check cfg.bin                         decode + verify a dumped config
  gen_atecc_config.py --selftest

Output is the 128-byte config zone blob that wirenboard `atecc write-config` expects (bytes 0-15
are read-only on the chip and ignored by the write).

Layout (atecc608a/out/atecc608a_general_config.bin: slots as in the general I2C config, the rest as on a factory-default chip): the first SLOTS slots are ECC P-256 private keys: secret, GenKey
allowed (also after the zones are locked), external signatures only (no ECDH, no PrivWrite), public
key derivable. Slot 0 is the attestation key, the others are credential keys. There is NO
LimitedUse bit and no signature budget: the firmware does not use the chip counters (the counter
fields hold the factory value 0 and are ignored). All other slots are left
unused (same SlotConfig / KeyConfig as the reference image), except slot 13, which the
firmware uses as the clear-readable/writable site directory (the reference image already allows that).
"""
import argparse, os, sys

CFG_LEN = 128
COUNTER_MAX = 2097151

# byte offsets in the config zone
I2C_ENABLE, I2C_ADDR, CHIP_MODE = 14, 16, 19
SLOT_CFG, COUNTER0, LAST_KEY_USE = 20, 52, 68
USER_EXTRA, SELECTOR, LOCK_VALUE, LOCK_CONFIG, SLOT_LOCKED = 84, 85, 86, 87, 88
CHIP_OPTIONS, X509, KEY_CFG = 90, 92, 96

# SlotConfig is stored low byte first. For ECC private keys (datasheet / cryptoauthlib):
#   byte 20+2i : bit7 IsSecret, bit6 EncryptRead, bit5 LimitedUse, bit4 NoMac,
#                bit3 WriteECDH, bit2 ECDH, bit1 internal signatures, bit0 external signatures
#   byte 21+2i : bits7:4 WriteConfig (bit1 = GenKey allowed, bit2 = PrivWrite encrypted), bits3:0 WriteKey
SLOT_CRED = bytes([0x80 | 0x01, 0x20])   # secret, external sign; GenKey (no LimitedUse!)
# KeyConfig, low byte first: bit0 Private, bit1 PubInfo, bits4:2 KeyType (4 = P256)
KEY_CRED = bytes([0x01 | 0x02 | (4 << 2), 0x00])  # 0x13 0x00
# Slots not used by the firmware keep the reference image's SlotConfig / KeyConfig (general config):
# slot 10, 11, 15 = 8F 8F, slots 12-14 = 00 00; KeyConfig 18, 1C, 30, 3C, 3C, 1C.
SLOT_UNUSED = bytes([0x8F, 0x8F])   # kept for compatibility (slots 10, 11, 15)
UNUSED_SLOT_CFG = {10: b"\x8f\x8f", 11: b"\x8f\x8f", 12: b"\x00\x00", 13: b"\x00\x00", 14: b"\x00\x00", 15: b"\x8f\x8f"}
UNUSED_KEY_CFG = {10: b"\x18\x00", 11: b"\x1c\x00", 12: b"\x30\x00", 13: b"\x3c\x00", 14: b"\x3c\x00", 15: b"\x1c\x00"}


# Counter 0 and Counter 1 fields as on a factory-default chip: valid encoding of the value 0 (FF FF FF FF 00 00 00 00).
COUNTER_REF = bytes.fromhex("ffffffff00000000")


def counter_bytes(value):
    """Config-zone encoding of a monotonic counter (same as cryptoauthlib write_config_counter)."""
    if not 0 <= value <= COUNTER_MAX:
        raise ValueError("counter out of range")
    lin_a = (0xFFFF >> (value % 32)) & 0xFFFF
    lin_b = (0xFFFF >> ((value - 16) % 32 if value >= 16 else 0)) & 0xFFFF
    bin_a = value // 32
    bin_b = (value - 16) // 32 if value >= 16 else 0
    return bytes([lin_a >> 8, lin_a & 255, lin_b >> 8, lin_b & 255,
                  bin_a >> 8, bin_a & 255, bin_b >> 8, bin_b & 255])


def default_base():
    c = bytearray(CFG_LEN)
    c[I2C_ENABLE] = 0x01   # bytes 0-15 are read-only on the chip; kept so the image equals the reference
    c[I2C_ADDR] = 0xC0
    c[CHIP_MODE] = 0x00    # factory default
    # LastKeyUse (68-83) stays 00 as on a factory-default chip (only used with LimitedUse keys)
    c[LOCK_VALUE] = c[LOCK_CONFIG] = 0x55
    c[SLOT_LOCKED:SLOT_LOCKED + 2] = b"\xff\xff"
    return c


def build(slots, base=None):
    if not 2 <= slots <= 16:
        raise ValueError("slots must be 2..16 (slot 0 = attestation key, the rest credentials)")
    c = bytearray(base) if base else default_base()
    if len(c) != CFG_LEN:
        raise ValueError("base config must be 128 bytes")
    for i in range(16):
        if i < slots:
            s, k = SLOT_CRED, KEY_CRED
        else:
            s, k = UNUSED_SLOT_CFG.get(i, SLOT_UNUSED), UNUSED_KEY_CFG.get(i, bytes([0x3C, 0x00]))
        c[SLOT_CFG + 2 * i:SLOT_CFG + 2 * i + 2] = s
        c[KEY_CFG + 2 * i:KEY_CFG + 2 * i + 2] = k
    # Counter 0 / 1 as on a factory-default chip (the firmware does not use them).
    c[COUNTER0:COUNTER0 + 8] = COUNTER_REF
    c[COUNTER0 + 8:COUNTER0 + 16] = COUNTER_REF
    return bytes(c)


def counter_value(b):
    """Inverse of counter_bytes (the value a config-zone counter field encodes)."""
    b = bytes(b)
    bin_a = (b[4] << 8) | b[5]
    for v in range(bin_a * 32, bin_a * 32 + 32):
        if v <= COUNTER_MAX and counter_bytes(v) == b:
            return v
    return None


def describe(c):
    out = []
    ok = True
    for i in range(16):
        s = c[SLOT_CFG + 2 * i:SLOT_CFG + 2 * i + 2]
        k = c[KEY_CFG + 2 * i:KEY_CFG + 2 * i + 2]
        priv = k[0] & 1
        ktype = (k[0] >> 2) & 7
        if priv and ktype == 4:
            flags = []
            flags.append("secret" if s[0] & 0x80 else "NOT-SECRET")
            flags.append("LIMITED-USE (do not combine with the firmware counter)" if s[0] & 0x20 else "no LimitedUse")
            flags.append("ext-sign" if s[0] & 1 else "no-ext-sign")
            flags.append("ECDH" if s[0] & 4 else "no-ECDH")
            flags.append("GenKey" if (s[1] >> 4) & 2 else "no-GenKey")
            flags.append("PrivWrite" if (s[1] >> 4) & 4 else "no-PrivWrite")
            flags.append("pubkey-derivable" if k[0] & 2 else "NO-PUBKEY")
            out.append("slot %2d: ECC P-256 private key, %s" % (i, ", ".join(flags)))
            if k != KEY_CRED or s != SLOT_CRED:
                ok = False
        else:
            out.append("slot %2d: not a private-key slot (SlotConfig %02X %02X, KeyConfig %02X %02X)" % (i, s[0], s[1], k[0], k[1]))
    out.append("Counter 0 field: %s, Counter 1 field: %s (not used by the firmware)" % (
        c[COUNTER0:COUNTER0 + 8].hex(), c[COUNTER0 + 8:COUNTER0 + 16].hex()))
    out.append("I2C_Enable byte: 0x%02X (read-only on the chip), I2C address byte: 0x%02X, ChipMode 0x%02X" % (c[I2C_ENABLE], c[I2C_ADDR], c[CHIP_MODE]))
    out.append("LockValue (data zone): %s, LockConfig (config zone): %s" % (
        "unlocked" if c[LOCK_VALUE] == 0x55 else "LOCKED", "unlocked" if c[LOCK_CONFIG] == 0x55 else "LOCKED"))
    return out, ok


def instructions(slots):
    return """Provisioning with wirenboard atecc-util (on a chip whose config zone is still UNLOCKED):
  atecc -b <bus> -c 'write-config atecc608a_fido_config.bin'
  atecc -b <bus> -c 'dump-config -'          # compare with --check output
  atecc -b <bus> -c 'lock-config'            # IRREVERSIBLE: config and slot types frozen
  atecc -b <bus> -c 'lock-data'              # IRREVERSIBLE: slots stay regenerable (GenKey enabled)
  python3 make_attest_cert.py --out attest   # ONCE: attestation key in slot 0 + its certificate
Then, ON HARDWARE, verify before relying on it (see CONFIG.md "Acceptance test").
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--slots", type=int, default=10, help="ECC private-key slots (default 10): slot 0 attestation, 1.. credentials")
    ap.add_argument("--base", help="existing 128-byte config dump to patch (atecc read-config)")
    ap.add_argument("-o", "--out", default=".", help="output directory")
    ap.add_argument("--check", metavar="CONFIG.BIN", help="decode and verify a config blob")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.check:
        c = open(a.check, "rb").read()
        if len(c) != CFG_LEN:
            sys.exit("config must be 128 bytes")
        lines, ok = describe(c)
        print("\n".join(lines))
        print("RESULT:", "matches the FIDO layout" if ok else "does NOT match the FIDO layout")
        return 0 if ok else 1
    base = open(a.base, "rb").read() if a.base else None
    c = build(a.slots, base)
    os.makedirs(a.out, exist_ok=True)
    stem = os.path.join(a.out, "atecc608a_fido_config")
    open(stem + ".bin", "wb").write(c)
    open(stem + ".hex", "w").write("\n".join(c[i:i + 16].hex(" ").upper() for i in range(0, 128, 16)) + "\n")
    lines, _ = describe(c)
    open(stem + ".txt", "w").write("\n".join(lines) + "\n\n" + instructions(a.slots))
    print("\n".join(lines))
    print()
    print(instructions(a.slots))
    print("wrote", stem + ".bin/.hex/.txt")
    return 0


def selftest():
    assert counter_bytes(0) == bytes([0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0])
    c = build(10)
    lines, ok = describe(c)
    assert ok and len(c) == 128
    ref = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "out", "atecc608a_general_config.bin")
    if os.path.exists(ref):
        assert c == open(ref, "rb").read(), "build(10) must equal the reference config image"
    assert c[SLOT_CFG:SLOT_CFG + 2] == bytes([0x81, 0x20])
    assert c[KEY_CFG:KEY_CFG + 2] == bytes([0x13, 0x00])
    assert c[SLOT_CFG + 20:SLOT_CFG + 22] == UNUSED_SLOT_CFG[10]
    assert c[COUNTER0:COUNTER0 + 16] == COUNTER_REF * 2
    print("selftest ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
