#!/bin/sh
# Host-side tests: Rust unit tests + end-to-end test with python-fido2.
# (Builds for the host, not for the Pico; needs `pip install fido2`.)
set -e
cd "$(dirname "$0")"
HOST=$(rustc -vV | sed -n 's/^host: //p')
cargo test --lib --target "$HOST"
cargo build --target "$HOST"
python3 e2e.py
