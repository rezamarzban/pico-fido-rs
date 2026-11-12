#!/bin/sh
# Host-side tests.
#
# After the move to OpenSK the protocol logic (CTAP2/CTAP1, CBOR, PIN protocol, credential
# storage, CTAPHID) lives in the OpenSK library, so its own unit tests are the protocol test suite.
# This script runs them the same way OpenSK's run_desktop_tests.sh does. Needs third_party/OpenSK
# (fetched at the pinned commit by third_party/fetch-opensk.sh, which this script runs). Builds for the host, not for the Pico.
#
# NOT covered here (needs hardware, see README "Verification status"): src/env/* (flash store,
# BOOTSEL user presence, HID bridge, RNG), the USB stack and the interrupt-executor split.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
sh "$HERE/../third_party/fetch-opensk.sh"         # OpenSK at the pinned commit (no-op if present)
sh "$HERE/../third_party/apply-opensk-patch.sh"   # the RP-hint patch (src/se/ecdsa.rs needs it)
cd "$HERE/../third_party/OpenSK" || {
  echo "third_party/OpenSK is missing: sh third_party/fetch-opensk.sh" >&2
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
# the repo-level .cargo/config.toml defaults to the Pico target: force the host target here
( cd "$HERE/se" && cargo test --target "$(rustc -vV | sed -n 's/^host: //p')" )
