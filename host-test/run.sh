#!/bin/sh
# Host-side tests: Rust unit tests + end-to-end test with python-fido2.
# (Builds for the host, not for the Pico; needs `pip install fido2`.)
set -e
cd "$(dirname "$0")"
HOST=$(rustc -vV | sed -n 's/^host: //p')
cargo test --lib --target "$HOST"
cargo build --target "$HOST"
# The end-to-end script drives python-fido2's ClientPin / Ctap2 API; it was written for 1.1 - 2.x.
python3 - <<'PY'
import sys
from importlib.metadata import version
v = version("fido2"); major, minor = (int(x) for x in v.split(".")[:2])
if (major, minor) < (1, 1) or major > 2:
    sys.exit("fido2 %s is untested with e2e.py (need >=1.1,<3): pip install 'fido2>=1.1,<3'" % v)
print("python-fido2", v)
PY
python3 e2e.py
