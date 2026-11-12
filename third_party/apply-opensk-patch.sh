#!/bin/sh
# Applies third_party/opensk-rp-hint.patch to third_party/OpenSK (safe to run again).
# The patch is 14 lines: it lets OpenSK tell the key generator which relying party a new key is for,
# so the firmware can keep one chip key per site (src/se/ecdsa.rs). Everything else stays upstream.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$(dirname "$HERE")"
[ -f third_party/OpenSK/libraries/opensk/src/api/rng.rs ] || { echo "error: third_party/OpenSK is missing (run: sh third_party/fetch-opensk.sh)" >&2; exit 1; }
if git apply --directory=third_party/OpenSK -R --check third_party/opensk-rp-hint.patch >/dev/null 2>&1; then
  echo "OpenSK patch: already applied"
  exit 0
fi
git apply --directory=third_party/OpenSK third_party/opensk-rp-hint.patch
grep -q set_rp_id_hash third_party/OpenSK/libraries/opensk/src/ctap/mod.rs || { echo "error: the OpenSK patch did not apply" >&2; exit 1; }
echo "OpenSK patch: applied"
