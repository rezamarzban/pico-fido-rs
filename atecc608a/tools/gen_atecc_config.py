#!/usr/bin/env python3
"""ATECC608A configuration for the FIDO key (pico-fido-rs, feature `se_atecc`).

  gen_atecc_config.py --slots 8 --budget 500 -o out/        build a config image
  gen_atecc_config.py --slots 8 --budget 500 --base cfg.bin  patch your own `read-config` dump
  gen_atecc_config.py --check cfg.bin                        decode + verify a dumped config
  gen_atecc_config.py --selftest

Output is the 128-byte config zone blob that wirenboard `atecc write-config` expects (bytes 0-15
are read-only on the chip and ignored by the write).

Every credential slot is: ECC P-256 private key, secret, GenKey allowed (also after the zones are
locked, so slots can be regenerated), external signatures only (no ECDH, no PrivWrite), public key
derivable, LimitedUse (every use bumps the chip's monotonic Counter 0).
Counter 0 is then set to 2097151 - BUDGET, so the chip refuses to sign after BUDGET signatures.
Counter 0 is shared by all LimitedUse slots: BUDGET is a total for the whole device.
"""
import argparse, os, sys

CFG_LEN = 128
COUNTER_MAX = 2097151

# byte offsets in the config zone
I2C_ADDR, CHIP_MODE = 16, 19
SLOT_CFG, COUNTER0, LAST_KEY_USE = 20, 52, 68
USER_EXTRA, SELECTOR, LOCK_VALUE, LOCK_CONFIG, SLOT_LOCKED = 84, 85, 86, 87, 88
CHIP_OPTIONS, X509, KEY_CFG = 90, 92, 96

# SlotConfig is stored low byte first. For ECC private keys (datasheet / cryptoauthlib):
#   byte 20+2i : bit7 IsSecret, bit6 EncryptRead, bit5 LimitedUse, bit4 NoMac,
#                bit3 WriteECDH, bit2 ECDH, bit1 internal signatures, bit0 external signatures
#   byte 21+2i : bits7:4 WriteConfig (bit1 = GenKey allowed, bit2 = PrivWrite encrypted), bits3:0 WriteKey
SLOT_CRED = bytes([0x80 | 0x20 | 0x01, 0x20])   # secret, limited use, external sign; GenKey
# KeyConfig, low byte first: bit0 Private, bit1 PubInfo, bits4:2 KeyType (4 = P256)
KEY_CRED = bytes([0x01 | 0x02 | (4 << 2), 0x00])  # 0x13 0x00
# unused slots: general data slot, never readable / writable by commands, no ECC
SLOT_UNUSED = bytes([0x8F, 0x8F])
KEY_UNUSED = bytes([0x3C, 0x00])


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
    c[I2C_ADDR] = 0xC0
    c[CHIP_MODE] = 0x01
    c[LAST_KEY_USE:LAST_KEY_USE + 16] = b"\xff" * 16
    c[LOCK_VALUE] = c[LOCK_CONFIG] = 0x55
    c[SLOT_LOCKED:SLOT_LOCKED + 2] = b"\xff\xff"
    return c


def build(slots, budget, base=None):
    if not 1 <= slots <= 16:
        raise ValueError("slots must be 1..16")
    if not 1 <= budget <= COUNTER_MAX:
        raise ValueError("budget must be 1..%d" % COUNTER_MAX)
    c = bytearray(base) if base else default_base()
    if len(c) != CFG_LEN:
        raise ValueError("base config must be 128 bytes")
    for i in range(16):
        s, k = (SLOT_CRED, KEY_CRED) if i < slots else (SLOT_UNUSED, KEY_UNUSED)
        c[SLOT_CFG + 2 * i:SLOT_CFG + 2 * i + 2] = s
        c[KEY_CFG + 2 * i:KEY_CFG + 2 * i + 2] = k
    # Counter 0 / 1 as they should be after counter-init (atecc write-config resets them to 0).
    c[COUNTER0:COUNTER0 + 8] = counter_bytes(COUNTER_MAX - budget)
    c[COUNTER0 + 8:COUNTER0 + 16] = counter_bytes(0)
    return bytes(c)


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
            flags.append("limited-use" if s[0] & 0x20 else "UNLIMITED")
            flags.append("ext-sign" if s[0] & 1 else "no-ext-sign")
            flags.append("ECDH" if s[0] & 4 else "no-ECDH")
            flags.append("GenKey" if (s[1] >> 4) & 2 else "no-GenKey")
            flags.append("PrivWrite" if (s[1] >> 4) & 4 else "no-PrivWrite")
            flags.append("pubkey-derivable" if k[0] & 2 else "NO-PUBKEY")
            out.append("slot %2d: ECC P-256 private key, %s" % (i, ", ".join(flags)))
            if s != SLOT_CRED or k != KEY_CRED:
                ok = False
        else:
            out.append("slot %2d: not a private-key slot (SlotConfig %02X %02X, KeyConfig %02X %02X)" % (i, s[0], s[1], k[0], k[1]))
    out.append("I2C address byte: 0x%02X, ChipMode 0x%02X" % (c[I2C_ADDR], c[CHIP_MODE]))
    out.append("LockValue (data zone): %s, LockConfig (config zone): %s" % (
        "unlocked" if c[LOCK_VALUE] == 0x55 else "LOCKED", "unlocked" if c[LOCK_CONFIG] == 0x55 else "LOCKED"))
    return out, ok


def instructions(slots, budget):
    return """Provisioning with wirenboard atecc-util (on a chip whose config zone is still UNLOCKED):
  atecc -b <bus> -c 'write-config atecc608a_fido_config.bin'
  atecc -b <bus> -c 'counter-init 0 -%d'     # write-config resets counters: set the budget AFTER it
  atecc -b <bus> -c 'counter-read 0 -r'      # must print %d (counts left)
  atecc -b <bus> -c 'dump-config -'          # compare with --check output
  atecc -b <bus> -c 'lock-config'            # IRREVERSIBLE: config, budget, slot types frozen
  atecc -b <bus> -c 'lock-data'              # IRREVERSIBLE: slots stay regenerable (GenKey enabled)
Then, ON HARDWARE, verify before relying on it (see CONFIG.md "Acceptance test").
""" % (budget, budget)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--slots", type=int, default=8, help="credential slots, 8 (default) or 16")
    ap.add_argument("--budget", type=int, help="total signatures the chip will allow (1..2097151)")
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
    if a.budget is None:
        ap.error("--budget is required")
    base = open(a.base, "rb").read() if a.base else None
    c = build(a.slots, a.budget, base)
    os.makedirs(a.out, exist_ok=True)
    stem = os.path.join(a.out, "atecc608a_fido_config")
    open(stem + ".bin", "wb").write(c)
    open(stem + ".hex", "w").write("\n".join(c[i:i + 16].hex(" ").upper() for i in range(0, 128, 16)) + "\n")
    lines, _ = describe(c)
    open(stem + ".txt", "w").write("\n".join(lines) + "\n\n" + instructions(a.slots, a.budget))
    print("\n".join(lines))
    print()
    print(instructions(a.slots, a.budget))
    print("wrote", stem + ".bin/.hex/.txt")
    return 0


def selftest():
    # counter encoding is the cryptoauthlib one: spot-check against values computed by its C code
    # (see tests/test_gen_config.py for the cross-check).
    assert counter_bytes(0) == bytes([0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0])
    c = build(8, 500)
    lines, ok = describe(c)
    assert ok and len(c) == 128
    assert c[SLOT_CFG:SLOT_CFG + 2] == bytes([0xA1, 0x20])
    assert c[KEY_CFG:KEY_CFG + 2] == bytes([0x13, 0x00])
    assert c[SLOT_CFG + 16:SLOT_CFG + 18] == SLOT_UNUSED
    print("selftest ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
