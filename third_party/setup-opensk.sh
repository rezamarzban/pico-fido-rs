#!/bin/sh
# Fetches OpenSK at the commit in third_party/OPENSK_REV into third_party/OpenSK (plain clone, no
# git submodule, no nested submodules) and applies third_party/opensk-harden.patch. Idempotent.
# Used by CI, host-test/run.sh and by hand; build.sh does the same on its own.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
D="$ROOT/third_party/OpenSK"
REV=$(tr -d '[:space:]' < "$ROOT/third_party/OPENSK_REV")
URL="${OPENSK_URL:-https://github.com/google/OpenSK.git}"
if [ ! -f "$D/libraries/opensk/Cargo.toml" ]; then
  rm -rf "$D"; mkdir -p "$D"
  git -C "$D" init -q
  git -C "$D" remote add origin "$URL"
  git -C "$D" fetch -q --depth 1 origin "$REV"
  git -C "$D" checkout -q FETCH_HEAD
fi
if ! grep -q cancel_in_flight "$D/libraries/opensk/src/lib.rs"; then
  patch -p1 -d "$D" < "$ROOT/third_party/opensk-harden.patch"
fi
echo "OpenSK $(git -C "$D" rev-parse --short HEAD) ready (patched)"
