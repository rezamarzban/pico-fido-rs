#!/usr/bin/env python3
"""Computes the 32-byte PIN key to write into chip slot 11 (same as src/se/auth.rs `pin_key`).

  pin_key.py --serial 0123aabbccddeeffee --pin 1234 -o pin_key.bin
  atecc ... write-data 11 0 pin_key.bin        # before lock-data!

--serial: the chip's 9-byte serial number as hex (atecc `serial` command).
The PIN is hashed like a FIDO client does: pinHash = LEFT(SHA-256(PIN as UTF-8), 16).
"""
import argparse, hashlib, sys

def pin_key(sn: bytes, pin: str) -> bytes:
    assert len(sn) == 9
    pin_hash = hashlib.sha256(pin.encode("utf-8")).digest()[:16]
    return hashlib.sha256(b"pico-fido-rs/atecc-pin/v1" + sn + pin_hash).digest()

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--serial", required=True)
    ap.add_argument("--pin", required=True)
    ap.add_argument("-o", "--out", default="pin_key.bin")
    a = ap.parse_args()
    sn = bytes.fromhex(a.serial)
    if len(sn) != 9:
        sys.exit("serial must be 9 bytes (18 hex digits)")
    if len(a.pin) < 4:
        sys.exit("FIDO PINs are at least 4 characters")
    open(a.out, "wb").write(pin_key(sn, a.pin))
    print("wrote", a.out)

if __name__ == "__main__":
    main()
