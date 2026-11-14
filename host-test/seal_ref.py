#!/usr/bin/env python3
"""Reference implementation of src/seal.rs (and the record mapping of src/sealed_log.rs) in Python.

Used to produce the known-answer vectors asserted in host-test/se/tests/se.rs: if the Rust code and this
file ever disagree, the Rust test fails. Needs the `cryptography` package.

    python3 host-test/seal_ref.py          # prints the vectors
"""
import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE, TAG = 12, 16


def hm(key, *parts):
    return hmac.new(key, b"".join(parts), hashlib.sha256).digest()


def derive(root, domain):
    return hm(root, b"pfrs-flash-v1/", domain, b"/enc"), hm(root, b"pfrs-flash-v1/", domain, b"/siv")


def seal(root, domain, aad, plain):
    enc, siv = derive(root, domain)
    nonce = hm(siv, struct.pack("<I", len(aad)), aad, plain)[:NONCE]
    return nonce + AESGCM(enc).encrypt(nonce, plain, aad)  # ciphertext || tag


def opened(root, domain, aad, sealed):
    enc, _ = derive(root, domain)
    return AESGCM(enc).decrypt(sealed[:NONCE], sealed[NONCE:], aad)


if __name__ == "__main__":
    root = bytes(range(32))
    aad = b"pfrs/store/v1" + struct.pack("<I", 7)
    s = seal(root, b"store", aad, b"hello flash")
    assert opened(root, b"store", aad, s) == b"hello flash"
    print("store key 7, 'hello flash':", s.hex())
    rec = bytes(range(32))  # a logical 32-byte directory record
    aad = b"pfrs/dir/v1/rec" + struct.pack("<H", 3)
    s = seal(root, b"dir", aad, rec)
    print("dir record 3:", s.hex())
