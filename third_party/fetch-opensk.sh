#!/bin/sh
# Fetches google/OpenSK at the commit pinned in third_party/OPENSK_REV into third_party/OpenSK
# (safe to run again; does nothing if the library is already there). OpenSK's own nested submodules
# (third_party/wasefire) are NOT fetched: the opensk library does not use them.
#
# This repository does not record OpenSK as a git submodule (there is no gitlink in the tree), so
# `git submodule update` / `actions/checkout` with `submodules:` cannot provide it: CI, build.sh and
# host-test/run.sh use this script instead. Environment: OPENSK_URL / OPENSK_REV override the source.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
DIR="$HERE/OpenSK"
URL="${OPENSK_URL:-https://github.com/google/OpenSK.git}"
REV="${OPENSK_REV:-$(tr -d '[:space:]' < "$HERE/OPENSK_REV" 2>/dev/null || true)}"
[ -n "$REV" ] || { echo "error: no pinned commit (third_party/OPENSK_REV, or set OPENSK_REV)" >&2; exit 1; }
if [ -f "$DIR/libraries/opensk/Cargo.toml" ]; then
  echo "OpenSK: already present ($(git -C "$DIR" log -1 --format='%h' 2>/dev/null || echo 'unknown revision'))"
  exit 0
fi
echo "Fetching OpenSK $REV from $URL"
rm -rf "$DIR"; mkdir -p "$DIR"
git -C "$DIR" init -q
git -C "$DIR" remote add origin "$URL"
git -C "$DIR" fetch -q --depth 1 origin "$REV"
git -C "$DIR" checkout -q FETCH_HEAD
[ -f "$DIR/libraries/opensk/Cargo.toml" ] || { echo "error: OpenSK is missing after the fetch" >&2; exit 1; }
echo "OpenSK: $(git -C "$DIR" log -1 --format='%h %s')"
