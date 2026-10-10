import ctypes, os, hashlib
from fido2.ctap import CtapDevice, CtapError
from fido2.ctap2 import Ctap2
from fido2.cose import ES256

import glob
lib = ctypes.CDLL([f for f in glob.glob("target/**/debug/libhost.*", recursive=True) if f.endswith((".so", ".dylib", ".dll"))][0])
lib.ctap_new.restype = ctypes.c_void_p
lib.ctap_handle.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]

class Dev(CtapDevice):
    def __init__(s, master): s.c = lib.ctap_new(master); s.touches = 0; s.log = []
    @property
    def capabilities(s): return 0x04
    @classmethod
    def list_devices(cls): return iter(())
    def call(s, cmd, data=b"", event=None, on_keepalive=None):
        assert cmd == 0x10
        out = ctypes.create_string_buffer(2048)
        n = lib.ctap_handle(s.c, data, len(data), 0, out, 2048)
        if n == -1:
            s.touches += 1
            n = lib.ctap_handle(s.c, data, len(data), 1, out, 2048)
        return out.raw[:n]

def expect(code, f):
    try: f()
    except CtapError as e:
        assert e.code == code, (hex(e.code), hex(code)); return
    raise AssertionError("no error, wanted %x" % code)

dev = Dev(os.urandom(32)); ctap = Ctap2(dev)   # strict_cbor=True by default: checks canonical encoding
info = ctap.get_info(); print("getInfo:", info.versions, info.options, info.max_msg_size, info.max_cred_id_length)
cdh = hashlib.sha256(b"clientdata").digest()
rp = {"id": "example.com", "name": "Example"}; user = {"id": b"u1", "name": "alice"}
kp = [{"type": "public-key", "alg": -7}]

att = ctap.make_credential(cdh, rp, user, kp)
ad = att.auth_data; cd = ad.credential_data
print("fmt:", att.fmt, "credid len:", len(cd.credential_id), "flags:", hex(ad.flags), "counter:", ad.counter)
assert att.fmt == "none" and ad.rp_id_hash == hashlib.sha256(b"example.com").digest() and ad.flags == 0x41
cid = bytes(cd.credential_id); pub = cd.public_key; assert isinstance(pub, ES256)

cred = {"type": "public-key", "id": cid}
a = ctap.get_assertion("example.com", cdh, [cred])
pub.verify(bytes(a.auth_data) + cdh, a.signature)          # raises if signature invalid
assert a.credential["id"] == cid and a.auth_data.flags == 0x01
print("assertion signature: VALID")

# probe without touch (options.up=false) must not need touch
t = dev.touches; a2 = ctap.get_assertion("example.com", cdh, [cred], options={"up": False})
assert dev.touches == t and a2.auth_data.flags == 0
pub.verify(bytes(a2.auth_data) + cdh, a2.signature); print("up=false probe: ok, no touch")

# negative cases
expect(0x2E, lambda: ctap.get_assertion("evil.com", cdh, [cred]))                       # other RP
bad = bytearray(cid); bad[40] ^= 1
expect(0x2E, lambda: ctap.get_assertion("example.com", cdh, [{"type": "public-key", "id": bytes(bad)}]))  # tampered
expect(0x2E, lambda: ctap.get_assertion("example.com", cdh, []))                        # empty allowList
expect(0x19, lambda: ctap.make_credential(cdh, rp, user, kp, exclude_list=[cred]))      # excluded
expect(0x26, lambda: ctap.make_credential(cdh, rp, user, [{"type": "public-key", "alg": -257}]))
expect(0x2B, lambda: ctap.make_credential(cdh, rp, user, kp, options={"rk": True}))
expect(0x2B, lambda: ctap.make_credential(cdh, rp, user, kp, options={"uv": True}))
other = Dev(os.urandom(32)); expect(0x2E, lambda: Ctap2(other).get_assertion("example.com", cdh, [cred]))  # other device
# exclude list with a foreign credential id is fine
ctap.make_credential(cdh, rp, user, kp, exclude_list=[{"type": "public-key", "id": os.urandom(64)}])
# two registrations -> different keys
assert bytes(ctap.make_credential(cdh, rp, user, kp).auth_data.credential_data.credential_id) != cid
# selection + reset
ctap.selection(); ctap.reset()
expect(0x2E, lambda: ctap.get_assertion("example.com", cdh, [cred])); print("reset invalidates old credentials")
print("ALL OK, touches:", dev.touches)
