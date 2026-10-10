"""End-to-end test: python-fido2 (strict canonical CBOR) drives the Rust CTAP2 core through a C ABI.
Run via run.sh (builds the host library first). Needs: pip install fido2"""
import ctypes, glob, hashlib, os
from fido2 import cbor
from fido2.ctap import CtapDevice, CtapError
from fido2.ctap2 import Ctap2
from fido2.cose import ES256

path = [f for f in glob.glob("target/**/debug/libhost.*", recursive=True) if f.endswith((".so", ".dylib", ".dll"))][0]
lib = ctypes.CDLL(path)
lib.ctap_new.restype = ctypes.c_void_p
lib.ctap_new.argtypes = [ctypes.c_char_p]
lib.ctap_reboot.argtypes = [ctypes.c_void_p]
lib.ctap_tick.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
lib.ctap_lock.argtypes = [ctypes.c_void_p]
lib.ctap_tries_used.argtypes = [ctypes.c_void_p]; lib.ctap_tries_used.restype = ctypes.c_int
lib.ctap_handle.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_uint64, ctypes.c_char_p, ctypes.c_size_t]

class Dev(CtapDevice):
    def __init__(s, master=None):
        s.c = lib.ctap_new(master if master is not None else None); s.touches = 0; s.now = 1000
    @property
    def capabilities(s): return 0x04
    @classmethod
    def list_devices(cls): return iter(())
    def raw(s, req, cap=2048):
        out = ctypes.create_string_buffer(cap)
        n = lib.ctap_handle(s.c, req, len(req), 0, s.now, out, cap)
        if n == -1:
            s.touches += 1
            n = lib.ctap_handle(s.c, req, len(req), 1, s.now, out, cap)
        return n, out.raw[:max(n, 0)]
    def call(s, cmd, data=b"", event=None, on_keepalive=None):
        assert cmd == 0x10
        return s.raw(data)[1]
    def status(s, req): n, r = s.raw(req); return r[0] if n > 0 else n

def expect(code, f):
    try: f()
    except CtapError as e:
        assert e.code == code, (hex(e.code), hex(code)); return
    raise AssertionError("no error, wanted %x" % code)

cdh = hashlib.sha256(b"clientdata").digest()
rp = {"id": "example.com", "name": "Example"}; user = {"id": b"u1", "name": "alice"}
kp = [{"type": "public-key", "alg": -7}]

# ---------- happy path -------------------------------------------------------------------------
dev = Dev(os.urandom(32)); ctap = Ctap2(dev)
info = ctap.get_info(); print("getInfo:", info.versions, info.options, info.max_msg_size, info.max_cred_id_length)
att = ctap.make_credential(cdh, rp, user, kp)
ad = att.auth_data; cd = ad.credential_data
assert att.fmt == "none" and ad.rp_id_hash == hashlib.sha256(b"example.com").digest() and ad.flags == 0x41
cid = bytes(cd.credential_id); pub = cd.public_key; assert isinstance(pub, ES256) and len(cid) == 64
cred = {"type": "public-key", "id": cid}
a = ctap.get_assertion("example.com", cdh, [cred])
pub.verify(bytes(a.auth_data) + cdh, a.signature); assert a.credential["id"] == cid and a.auth_data.flags == 0x01
print("registration + assertion signature: VALID")
# policy (SECURITY.md): every signature needs a fresh touch, whatever the request's "up" option says
t = dev.touches; a2 = ctap.get_assertion("example.com", cdh, [cred], options={"up": False})
assert dev.touches == t + 1, "up=false must NOT skip the button press"
assert a2.auth_data.flags == 0x01; pub.verify(bytes(a2.auth_data) + cdh, a2.signature)
t = dev.touches; ctap.get_assertion("example.com", cdh, [cred], options={"up": True}); assert dev.touches == t + 1
print("up=false cannot bypass the touch requirement")

# ---------- credential / option errors ---------------------------------------------------------
expect(0x2E, lambda: ctap.get_assertion("evil.com", cdh, [cred]))
bad = bytearray(cid); bad[40] ^= 1
expect(0x2E, lambda: ctap.get_assertion("example.com", cdh, [{"type": "public-key", "id": bytes(bad)}]))
expect(0x2E, lambda: ctap.get_assertion("example.com", cdh, []))
expect(0x19, lambda: ctap.make_credential(cdh, rp, user, kp, exclude_list=[cred]))
expect(0x26, lambda: ctap.make_credential(cdh, rp, user, [{"type": "public-key", "alg": -257}]))
expect(0x2B, lambda: ctap.make_credential(cdh, rp, user, kp, options={"rk": True}))
expect(0x2B, lambda: ctap.make_credential(cdh, rp, user, kp, options={"uv": True}))
expect(0x2E, lambda: Ctap2(Dev(os.urandom(32))).get_assertion("example.com", cdh, [cred]))
ctap.make_credential(cdh, rp, user, kp, exclude_list=[{"type": "public-key", "id": os.urandom(64)}])
ctap.make_credential(cdh, rp, user, kp, exclude_list=[{"type": "other", "id": cid}])      # unknown type ignored
ctap.selection()
print("credential/option errors: ok")

# ---------- request validation (raw bytes) -----------------------------------------------------
def mc(over={}):
    m = {1: cdh, 2: rp, 3: user, 4: kp}; m.update(over)
    return b"\x01" + cbor.encode({k: v for k, v in m.items() if v is not None})
assert dev.status(mc()) == 0
def mc_missing(key):
    m = {1: cdh, 2: rp, 3: user, 4: kp}; del m[key]; return b"\x01" + cbor.encode(m)
assert dev.status(mc_missing(3)) == 0x14, "user entity is required"
assert dev.status(mc_missing(4)) == 0x14, "pubKeyCredParams is required"
assert dev.status(mc_missing(1)) == 0x14 and dev.status(mc_missing(2)) == 0x14
assert dev.status(mc({3: {"name": "x"}})) == 0x11, "user.id is required (nested member -> CBOR_UNEXPECTED_TYPE)"
assert dev.status(mc({3: {"id": b""}})) == 0x02 and dev.status(mc({3: {"id": b"x" * 65}})) == 0x02
assert dev.status(mc({4: [{"type": "public-key"}]})) == 0x11
assert dev.status(mc({5: [{"id": cid}]})) == 0x11, "descriptor without type"
assert dev.status(mc({5: [{"type": "public-key"}]})) == 0x11, "descriptor without id"
assert dev.status(mc({1: b"short"})) == 0x02
assert dev.status(mc({8: b"x" * 16, 9: 1})) == 0x35
ga = lambda o={}: b"\x02" + cbor.encode({**{1: "example.com", 2: cdh, 3: [cred]}, **o})
assert dev.status(ga()) == 0
assert dev.status(ga({3: [{"id": cid}]})) == 0x11 and dev.status(ga({3: [{"type": "public-key"}]})) == 0x11
assert dev.status(ga({5: {"uv": True}})) == 0x2B
good = mc()
assert dev.status(good + b"\x00") == 0x12, "trailing bytes"
assert dev.status(good.replace(b"\xa4\x01", b"\xa4\x18\x01", 1)) == 0x12, "non-minimal key"
assert dev.status(b"\x01\xa2\x01\x41\x00\x01\x41\x00") == 0x12, "duplicate key"
assert dev.status(b"\x01\xa1\x01\xc1\x00") == 0x12, "tag"
base = cbor.encode({1: cdh, 2: rp, 3: user, 4: kp}); assert base[0] == 0xa4
withfloat = b"\x01\xa5" + base[1:] + b"\x18\x63\xf9\x3c\x00"          # extra unknown key 99 = float16 1.0
assert dev.status(withfloat) == 0, "floats in unknown fields are ignored, not rejected"
assert dev.status(b"\x01\xa1\x01\xf9\x00\x00") == 0x11, "float where a byte string is expected"
assert dev.status(b"\x01\xa2\x02\x41\x00\x01\x41\x00") == 0x12, "map keys out of canonical order"
assert dev.status(b"\x01\xa1\x41\x00\x00") == 0x11, "byte-string map key"
assert dev.status(b"\x01\xa1\x80\x00") == 0x11, "array map key"
assert dev.status(b"\x01\xa1\x01\x81\x81\x81\x81\x00") == 0x12, "nesting depth 5"
assert dev.status(b"\x01\x80") == 0x11 and dev.status(b"\x01") == 0x12 and dev.status(b"") == 0x03
assert dev.status(b"\x04\x00") == 0x03 and dev.status(b"\x07\x00") == 0x03 and dev.status(b"\x0b\xa0") == 0x03
assert dev.status(b"\x09") == 0x01 and dev.status(b"\x08") == 0x30
assert dev.status(b"\x06") == 0x12, "clientPIN without a body"
print("request validation: ok")

# ---------- reset window + fault mode ----------------------------------------------------------
dev.now = 20_000; assert dev.status(b"\x07") == 0x30; print("reset refused after boot window")
dev.now = 5_000; t = dev.touches; assert dev.status(b"\x07") == 0 and dev.touches == t + 1
expect(0x2E, lambda: ctap.get_assertion("example.com", cdh, [cred])); print("reset inside window invalidates old credentials")

f = Dev(None); fc = Ctap2(f)                      # storage unreadable / corrupt: no key
assert fc.get_info().versions == ["FIDO_2_0"]
assert f.status(mc()) == 0x7F and f.status(ga()) == 0x7F, "fault mode must refuse, never re-key"
assert f.status(b"\x07") == 0
fc.make_credential(cdh, rp, user, kp); print("fault mode: refuses until explicit reset, then works")

# ---------- PIN (ClientPIN, python-fido2 as the platform) --------------------------------------
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
PIN = "correct horse battery"
LIFETIME = 120_000
for Proto in (PinProtocolV2, PinProtocolV1):
    dev = Dev(os.urandom(32)); ctap = Ctap2(dev); dev.now = 1000
    info = ctap.get_info(); assert info.options["clientPin"] is False and list(info.pin_uv_protocols) == [2, 1]
    att = ctap.make_credential(cdh, rp, user, kp); cred = {"type": "public-key", "id": bytes(att.auth_data.credential_data.credential_id)}
    cp = ClientPin(ctap, Proto())
    cp.set_pin(PIN)
    assert ctap.get_info().options["clientPin"] is True
    expect(0x36, lambda: ctap.make_credential(cdh, rp, user, kp))                       # PIN required now
    expect(0x36, lambda: ctap.get_assertion("example.com", cdh, [cred]))
    expect(0x31, lambda: cp.get_pin_token("wrong wrong wrong"))
    assert cp.get_pin_retries()[0] == 7 and lib.ctap_tries_used(dev.c) == 1
    token = cp.get_pin_token(PIN); assert cp.get_pin_retries()[0] == 8
    param = cp.protocol.authenticate(token, cdh); ver = cp.protocol.VERSION
    a = ctap.make_credential(cdh, rp, user, kp, pin_uv_param=param, pin_uv_protocol=ver)
    assert a.auth_data.flags == 0x45, "UV flag set after PIN"
    g = ctap.get_assertion("example.com", cdh, [cred], pin_uv_param=param, pin_uv_protocol=ver)   # credential from BEFORE the PIN
    assert g.auth_data.flags == 0x05
    bad = bytearray(param); bad[0] ^= 1
    expect(0x33, lambda: ctap.make_credential(cdh, rp, user, kp, pin_uv_param=bytes(bad), pin_uv_protocol=ver))
    # the key leaves RAM when the session ends
    lib.ctap_tick(dev.c, dev.now + LIFETIME)
    expect(0x33, lambda: ctap.make_credential(cdh, rp, user, kp, pin_uv_param=param, pin_uv_protocol=ver))
    token = cp.get_pin_token(PIN); param = cp.protocol.authenticate(token, cdh)
    lib.ctap_lock(dev.c)                                                              # USB reset / suspend
    expect(0x33, lambda: ctap.make_credential(cdh, rp, user, kp, pin_uv_param=param, pin_uv_protocol=ver))
    # change PIN
    NEW = "another long passphrase"
    expect(0x31, lambda: cp.change_pin("wrong wrong wrong", NEW))
    cp.change_pin(PIN, NEW); expect(0x31, lambda: cp.get_pin_token(PIN))
    token = cp.get_pin_token(NEW); param = cp.protocol.authenticate(token, cdh)
    ctap.get_assertion("example.com", cdh, [cred], pin_uv_param=param, pin_uv_protocol=ver)       # still the same master key
    print("PIN protocol v%d: set / token / UV / expiry / change: ok" % ver)

# lockout: 3 wrong PINs need a power cycle, 8 block the PIN for good, reset is the way out
dev = Dev(os.urandom(32)); ctap = Ctap2(dev); cp = ClientPin(ctap, PinProtocolV2()); cp.set_pin(PIN)
expect(0x31, lambda: cp.get_pin_token("wrong pin number 1")); expect(0x31, lambda: cp.get_pin_token("wrong pin number 2"))
expect(0x34, lambda: cp.get_pin_token("wrong pin number 3"))
expect(0x34, lambda: cp.get_pin_token(PIN))                                        # refused until power cycle
assert lib.ctap_tries_used(dev.c) == 3
lib.ctap_reboot(dev.c); assert cp.get_pin_retries()[0] == 5
for i in range(2): expect(0x31, lambda: cp.get_pin_token("wrong pin number x"))
expect(0x34, lambda: cp.get_pin_token("wrong pin number x")); lib.ctap_reboot(dev.c)
expect(0x31, lambda: cp.get_pin_token("wrong pin number y")); expect(0x32, lambda: cp.get_pin_token("wrong pin number y"))
lib.ctap_reboot(dev.c); expect(0x32, lambda: cp.get_pin_token(PIN)); assert cp.get_pin_retries()[0] == 0
dev.now = 5_000; assert dev.status(b"\x07") == 0                                    # factory reset
assert ctap.get_info().options["clientPin"] is False and lib.ctap_tries_used(dev.c) == 0
cp.set_pin(PIN); cp.get_pin_token(PIN)
# PIN survives a power cycle, and a short PIN is refused
lib.ctap_reboot(dev.c); assert ctap.get_info().options["clientPin"] is True; cp.get_pin_token(PIN)
d2 = Dev(os.urandom(32)); c2 = Ctap2(d2); expect(0x37, lambda: ClientPin(c2, PinProtocolV2()).set_pin("short"))
print("PIN lockout / reset / persistence: ok")

# ---------- FFI robustness ---------------------------------------------------------------------
out = ctypes.create_string_buffer(8)
assert lib.ctap_handle(None, b"\x04", 1, 0, 0, out, 8) == -2
assert lib.ctap_handle(dev.c, b"\x04", 1, 0, 0, None, 8) == -2
assert lib.ctap_handle(dev.c, b"\x04", 1, 0, 0, out, 0) == -2
assert lib.ctap_handle(dev.c, b"\x04", 1, 0, 0, out, 8) == -2, "response larger than buffer"
assert lib.ctap_handle(dev.c, None, 0, 0, 0, out, 8) == 1
print("ALL OK")
