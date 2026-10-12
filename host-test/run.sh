#!/bin/sh
# Host-side tests.
#
# After the move to OpenSK the protocol logic (CTAP2/CTAP1, CBOR, PIN protocol, credential
# storage, CTAPHID) lives in the OpenSK library, so its own unit tests are the protocol test suite.
# This script runs them the same way OpenSK's run_desktop_tests.sh does. Needs third_party/OpenSK
# (see README: git submodule, or build.sh fetches it). Builds for the host, not for the Pico.
#
# NOT covered here (needs hardware, see README "Verification status"): src/env/* (flash store,
# BOOTSEL user presence, HID bridge, RNG), the USB stack and the interrupt-executor split.
set -e
cd "$(dirname "$0")/../third_party/OpenSK" || {
  echo "third_party/OpenSK is missing: git submodule update --init --depth 1 third_party/OpenSK" >&2
  exit 1
}
if [ -f ../OPENSK_REV ]; then
  want=$(tr -d '[:space:]' < ../OPENSK_REV)
  have=$(git rev-parse HEAD 2>/dev/null || true)
  [ -z "$have" ] || [ "$have" = "$want" ] || echo "warning: OpenSK is at $have, third_party/OPENSK_REV pins $want" >&2
fi
( cd libraries/opensk
  cargo test --no-default-features --features=std
  cargo test --features=std,config_command,ctap1 )
cargo test --manifest-path=libraries/cbor/Cargo.toml
