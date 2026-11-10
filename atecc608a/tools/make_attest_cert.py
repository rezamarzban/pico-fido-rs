#!/usr/bin/env python3
"""One-time provisioning of the attestation key (pico-fido-rs).

  make_attest_cert.py --out attest                  create the key in the chip + its certificate
  make_attest_cert.py --out attest --bus 1          I2C bus number of the chip (default 1)
  make_attest_cert.py --out attest --regen          replace an existing attestation key
  make_attest_cert.py --selftest                    no hardware: a software "chip", checks every output

What it does, in this order (chip config + data zones must already be locked, see CONFIG.md):
  1. GenKey in the attestation slot (0). The private key is made inside the chip and never leaves it.
     If the slot already holds a key the tool stops, unless --regen is given.
  2. Builds a self-signed X.509 certificate for that public key and lets the chip sign it.
  3. Writes <out>/attest_cert.der / .pem   the certificate (what U2F / batch attestation sends)
            <out>/attest_key.hex / .pem    the 32-byte *handle* of the key, in the place where a
                                           software firmware stores the 32-byte private key

The handle is [02][slot][SHA-256(X||Y)[:6]][24 zero bytes]. It is not a secret: it only tells the
firmware which chip slot to use (and is checked against the key actually in that slot). attest_key.pem
wraps it as the "private key" of an EC key so OpenSK's tools/configure.py accepts it as a file;
the public half of that PEM is meaningless, only the 32 bytes count.

Needs the `cryptoauthlib` Python package for a real chip. The selftest and the PEM files need
`cryptography`.
"""
import argparse
import datetime
import hashlib
import os
import sys

ATTEST_SLOT = 0          # = ATTEST_SLOT in src/se/ecdsa.rs
HANDLE_ATTEST = 2        # = HANDLE_ATTEST in src/se/ecdsa.rs


# ------------------------------------------------------------------ the handle

def handle(pub, slot=ATTEST_SLOT):
    """The 32-byte handle for the key `pub` (X||Y) in `slot`. Same layout as `ecdsa::handle` in Rust."""
    if len(pub) != 64:
        raise ValueError("public key must be 64 bytes (X||Y)")
    return bytes([HANDLE_ATTEST, slot]) + hashlib.sha256(pub).digest()[:6] + bytes(24)


# ------------------------------------------------------------------ minimal DER

def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + _len(len(body)) + body


def seq(*parts):
    return tlv(0x30, b"".join(parts))


def oid(dotted):
    a = [int(x) for x in dotted.split(".")]
    body = bytearray([40 * a[0] + a[1]])
    for v in a[2:]:
        chunk = [v & 0x7F]
        v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7F))
            v >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, bytes(body))


def integer(b):
    """Positive INTEGER from big-endian bytes (minimal encoding)."""
    b = b.lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return tlv(0x02, b)


def name(country, org, cn):
    def rdn(o, tag, text):
        return tlv(0x31, seq(oid(o), tlv(tag, text.encode())))
    return seq(
        rdn("2.5.4.6", 0x13, country),                       # C  (PrintableString)
        rdn("2.5.4.10", 0x0C, org),                          # O  (UTF8String)
        rdn("2.5.4.11", 0x0C, "Authenticator Attestation"),  # OU, required by the WebAuthn packed format
        rdn("2.5.4.3", 0x0C, cn),                            # CN
    )


ECDSA_SHA256 = seq(oid("1.2.840.10045.4.3.2"))               # no parameters
AAGUID_EXT = "1.3.6.1.4.1.45724.1.1.4"


def spki(pub):
    return seq(
        seq(oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.7")),   # id-ecPublicKey, prime256v1
        tlv(0x03, b"\x00\x04" + pub),
    )


def tbs_certificate(pub, serial, country, org, cn, not_before, aaguid=None):
    exts = [seq(oid("2.5.29.19"), tlv(0x01, b"\xff"), tlv(0x04, seq()))]   # basicConstraints, critical, CA:FALSE
    if aaguid:
        exts.append(seq(oid(AAGUID_EXT), tlv(0x04, tlv(0x04, aaguid))))
    n = name(country, org, cn)
    return seq(
        tlv(0xA0, integer(b"\x02")),                          # version: v3
        integer(serial),
        ECDSA_SHA256,
        n,                                                    # issuer = subject (self-signed)
        seq(tlv(0x17, not_before.strftime("%y%m%d%H%M%SZ").encode()),
            tlv(0x18, b"99991231235959Z")),                   # "no well-defined expiration"
        n,
        spki(pub),
        tlv(0xA3, seq(*exts)),
    )


def ecdsa_der(raw):
    if len(raw) != 64:
        raise ValueError("signature must be r||s, 64 bytes")
    return seq(integer(raw[:32]), integer(raw[32:]))


def certificate(pub, sign_digest, country, org, cn, aaguid=None, now=None):
    """`sign_digest(d32) -> r||s` is the chip."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    serial = bytearray(os.urandom(16))
    serial[0] &= 0x7F
    if not any(serial):
        serial[-1] = 1
    tbs = tbs_certificate(pub, bytes(serial), country, org, cn, now, aaguid)
    sig = ecdsa_der(sign_digest(hashlib.sha256(tbs).digest()))
    return seq(tbs, ECDSA_SHA256, tlv(0x03, b"\x00" + sig))


# ------------------------------------------------------------------ chip backends

class SoftChip:
    """Stands in for the chip in --selftest: same three operations, key in software."""
    def __init__(self):
        self.key = None

    def public_key(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization as s
        if self.key is None:
            return None
        return self.key.public_key().public_bytes(s.Encoding.X962, s.PublicFormat.UncompressedPoint)[1:]

    def genkey(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.key = ec.generate_private_key(ec.SECP256R1())
        return self.public_key()

    def sign(self, digest):
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.hazmat.primitives import hashes
        der = self.key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class AteccChip:
    """The real chip through cryptoauthlib (I2C, address 0xC0 as configured by gen_atecc_config.py).
    Written against the cryptoauthlib Python API; not run against hardware by the author."""
    def __init__(self, slot, bus):
        import cryptoauthlib as c
        self.c, self.slot = c, slot
        cfg = c.cfg_ateccx08a_i2c_default()
        cfg.cfg.atcai2c.bus = bus
        cfg.cfg.atcai2c.address = 0xC0
        self._ok(c.atcab_init(cfg), "atcab_init")

    def _ok(self, status, what):
        if status != self.c.Status.ATCA_SUCCESS and status != 0:
            raise SystemExit("%s failed: %s" % (what, status))

    def public_key(self):
        pub = bytearray(64)
        st = self.c.atcab_get_pubkey(self.slot, pub)
        return bytes(pub) if st == self.c.Status.ATCA_SUCCESS or st == 0 else None

    def genkey(self):
        pub = bytearray(64)
        self._ok(self.c.atcab_genkey(self.slot, pub), "GenKey")
        return bytes(pub)

    def sign(self, digest):
        sig = bytearray(64)
        self._ok(self.c.atcab_sign(self.slot, digest, sig), "Sign")
        return bytes(sig)


# ------------------------------------------------------------------ outputs

def pem_cert(der):
    import base64
    b = base64.encodebytes(der).decode().replace("\n", "")
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----\n"


def pem_handle_key(h):
    """The 32-byte handle as the private scalar of a P-256 key (valid: first byte 0x02 < n)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization as s
    k = ec.derive_private_key(int.from_bytes(h, "big"), ec.SECP256R1())
    return k.private_bytes(s.Encoding.PEM, s.PrivateFormat.TraditionalOpenSSL, s.NoEncryption()).decode()


def provision(chip, out, country, org, cn, aaguid=None, regen=False, slot=ATTEST_SLOT):
    pub = chip.public_key()
    if pub is not None and not regen:
        raise SystemExit("slot %d already holds a key: refusing to replace it (use --regen)" % slot)
    pub = chip.genkey()
    cert = certificate(pub, chip.sign, country, org, cn, aaguid)
    h = handle(pub, slot)
    os.makedirs(out, exist_ok=True)
    files = {
        "attest_cert.der": cert,
        "attest_cert.pem": pem_cert(cert).encode(),
        "attest_key.hex": (h.hex() + "\n").encode(),
        "attest_key.pem": pem_handle_key(h).encode(),
    }
    for fn, data in files.items():
        with open(os.path.join(out, fn), "wb") as f:
            f.write(data)
    return pub, cert, h


NEXT = """Done. Now store the certificate and the handle in the token (once, over USB):
  OpenSK tools/configure.py --certificate=%(o)s/attest_cert.pem --private-key=%(o)s/attest_key.pem
If configure.py rejects the key because it does not match the certificate, send the vendor
attestation command yourself with the 32 bytes in %(o)s/attest_key.hex as the private key and
%(o)s/attest_cert.der as the certificate.
Public key: %(pub)s
Handle:     %(h)s
"""


def selftest():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    import tempfile
    chip = SoftChip()
    with tempfile.TemporaryDirectory() as d:
        aag = bytes(range(16))
        pub, der, h = provision(chip, d, "XX", "pico-fido-rs", "pico-fido-rs attestation", aaguid=aag)
        cert = x509.load_der_x509_certificate(der)
        assert cert.version == x509.Version.v3
        assert cert.issuer == cert.subject
        attrs = {a.oid.dotted_string: a.value for a in cert.subject}
        assert attrs["2.5.4.6"] == "XX" and attrs["2.5.4.11"] == "Authenticator Attestation", attrs
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical and not bc.value.ca
        ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(AAGUID_EXT))
        assert ext.value.value == b"\x04\x10" + aag
        # the self-signature verifies under the chip's public key
        cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
        nums = cert.public_key().public_numbers()
        assert nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big") == pub
        # the PEM we write is the same certificate, and the handle is what the firmware expects
        assert x509.load_pem_x509_certificate(open(os.path.join(d, "attest_cert.pem"), "rb").read()) == cert
        assert len(h) == 32 and h[:2] == bytes([2, ATTEST_SLOT]) and h[8:] == bytes(24)
        assert h[2:8] == hashlib.sha256(pub).digest()[:6]
        k = load_pem_private_key(open(os.path.join(d, "attest_key.pem"), "rb").read(), None)
        assert k.private_numbers().private_value.to_bytes(32, "big") == h
        assert open(os.path.join(d, "attest_key.hex")).read().strip() == h.hex()
        # a second run must not silently replace the key
        try:
            provision(chip, d, "XX", "o", "cn")
            raise AssertionError("second provisioning should have been refused")
        except SystemExit:
            pass
        assert chip.public_key() == pub
        provision(chip, d, "XX", "o", "cn", regen=True)
        assert chip.public_key() != pub
        # DER helpers on edge cases
        assert integer(b"\x00\x00\x80") == b"\x02\x02\x00\x80"
        assert integer(b"\x00\x00") == b"\x02\x01\x00"
        assert oid("1.2.840.10045.4.3.2") == bytes.fromhex("06082a8648ce3d040302")
        assert _len(200) == b"\x81\xc8" and _len(300) == b"\x82\x01\x2c"
    print("selftest ok")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="attest", help="output directory")
    ap.add_argument("--bus", type=int, default=1, help="I2C bus number of the chip (/dev/i2c-N)")
    ap.add_argument("--slot", type=int, default=ATTEST_SLOT, help="attestation slot (default 0, the firmware's)")
    ap.add_argument("--country", default="XX", help="subject C (2 letters)")
    ap.add_argument("--org", default="pico-fido-rs", help="subject O")
    ap.add_argument("--cn", default="pico-fido-rs attestation", help="subject CN")
    ap.add_argument("--aaguid", help="32 hex digits: adds the FIDO AAGUID extension (must equal the token's AAGUID)")
    ap.add_argument("--regen", action="store_true", help="replace an existing attestation key")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.slot != ATTEST_SLOT:
        ap.error("the firmware only uses slot %d" % ATTEST_SLOT)
    if len(a.country) != 2:
        ap.error("--country must be 2 letters")
    aaguid = bytes.fromhex(a.aaguid) if a.aaguid else None
    if aaguid is not None and len(aaguid) != 16:
        ap.error("--aaguid must be 16 bytes")
    pub, _, h = provision(AteccChip(a.slot, a.bus), a.out, a.country, a.org, a.cn, aaguid, a.regen, a.slot)
    print(NEXT % {"o": a.out, "pub": pub.hex(), "h": h.hex()})
    return 0


if __name__ == "__main__":
    sys.exit(main())
