#!/usr/bin/env bash
# Build the pico-fido-rs firmware (UF2) from GitHub.
#
# Usage:  bash build.sh [-s 2|4|8|16] [-u] [-P] [-t TOOLCHAIN] [-r REPO_URL] [-b BRANCH] [-o OUT_DIR]
#   -s  flash size of your board in MiB (default 2; a standard Raspberry Pi Pico has 2)
#   -u  build WITH a USB serial number (off by default for privacy; adds the `usb_serial` feature)
#   -P  build WITHOUT the SRAM PUF (default: with; the `sram_puf` feature)
#   -t  Rust nightly to use (default: nightly-2026-06-03, the one OpenSK pins, then `nightly`)
#   -r  repository URL   (default https://github.com/rezamarzban/pico-fido-rs)
#   -b  branch           (default openSK-based-se3)
#   -o  output directory (default ./out)
# Environment: OPENSK_URL / OPENSK_REV override where and which OpenSK commit is fetched
#   (default: google/OpenSK at the commit in third_party/OPENSK_REV).
# Result: <OUT_DIR>/pico-fido-rs-<N>m.uf2   (hold BOOTSEL while plugging in, copy the file to the RPI-RP2 drive)
set -euo pipefail

FLASH_MB=2
SERIAL=0
PUF=1
TOOLCHAIN=""
REPO="https://github.com/rezamarzban/pico-fido-rs"
BRANCH="openSK-based-se4"
OUT_DIR="$PWD/out"
OPENSK_URL="${OPENSK_URL:-https://github.com/google/OpenSK.git}"

usage() { sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while getopts "s:uPnt:r:b:o:h" opt; do
  case "$opt" in
    s) FLASH_MB="$OPTARG" ;;
    u) SERIAL=1 ;;
    P) PUF=0 ;;
    n) SERIAL=0 ;; # kept for compatibility: no serial is the default
    t) TOOLCHAIN="$OPTARG" ;;
    r) REPO="$OPTARG" ;;
    b) BRANCH="$OPTARG" ;;
    o) OUT_DIR="$(mkdir -p "$OPTARG" && cd "$OPTARG" && pwd)" ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done
case "$FLASH_MB" in 2|4|8|16) ;; *) echo "error: -s must be 2, 4, 8 or 16 (got '$FLASH_MB')" >&2; exit 1 ;; esac

WORK="${WORK:-$PWD/work}"
SRC="$WORK/src"
mkdir -p "$OUT_DIR" "$WORK"

# ---- 1. system packages (needed to build elf2uf2-rs) -------------------------------------------
need_pkgs=0
for c in git curl pkg-config; do command -v "$c" >/dev/null 2>&1 || need_pkgs=1; done
dpkg -s libudev-dev >/dev/null 2>&1 || need_pkgs=1
if [ "$need_pkgs" = 1 ] && command -v apt-get >/dev/null 2>&1; then
  SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
  $SUDO apt-get -qq update || true
  $SUDO apt-get -qq install -y git curl ca-certificates pkg-config libudev-dev build-essential >/dev/null
fi

# ---- 2. Rust + elf2uf2-rs ----------------------------------------------------------------------
if ! command -v rustup >/dev/null 2>&1 && [ ! -f "$HOME/.cargo/env" ]; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
fi
# shellcheck disable=SC1091
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
command -v elf2uf2-rs >/dev/null 2>&1 || cargo install elf2uf2-rs --locked

# ---- 3. clone ----------------------------------------------------------------------------------
rm -rf "$SRC"
git clone --depth 1 --branch "$BRANCH" "$REPO" "$SRC"
PROJ="$(dirname "$(find "$SRC" -name Cargo.toml -not -path '*/host-test/*' -not -path '*/third_party/*' -not -path '*/target/*' | awk '{print length, $0}' | sort -n | head -1 | cut -d' ' -f2-)")"
echo "Project dir: $PROJ ($(git -C "$SRC" log -1 --format='%h %s'))"
cd "$PROJ"

grep -q "flash_${FLASH_MB}m" Cargo.toml || { echo "error: this revision has no 'flash_${FLASH_MB}m' feature in Cargo.toml" >&2; exit 1; }

# ---- 3b. OpenSK library (a path dependency under third_party/OpenSK) ----------------------------
# Do NOT fetch OpenSK's own nested submodules (third_party/wasefire): the library does not use them.
OPENSK_DIR="third_party/OpenSK"
OPENSK_LIB="$OPENSK_DIR/libraries/opensk/Cargo.toml"
OPENSK_REV="${OPENSK_REV:-$(tr -d '[:space:]' < third_party/OPENSK_REV 2>/dev/null || true)}"
if [ ! -f "$OPENSK_LIB" ]; then
  if git ls-files --stage -- "$OPENSK_DIR" | grep -q '^160000'; then
    echo "Fetching the OpenSK submodule (the commit recorded in the repository)"
    git submodule update --init --depth 1 -- "$OPENSK_DIR"
  else
    [ -n "$OPENSK_REV" ] || { echo "error: no OpenSK submodule and no pinned commit (third_party/OPENSK_REV, or set OPENSK_REV)" >&2; exit 1; }
    echo "Fetching OpenSK $OPENSK_REV from $OPENSK_URL"
    rm -rf "$OPENSK_DIR"; mkdir -p "$OPENSK_DIR"
    git -C "$OPENSK_DIR" init -q
    git -C "$OPENSK_DIR" remote add origin "$OPENSK_URL"
    git -C "$OPENSK_DIR" fetch -q --depth 1 origin "$OPENSK_REV"
    git -C "$OPENSK_DIR" checkout -q FETCH_HEAD
  fi
fi
[ -f "$OPENSK_LIB" ] || { echo "error: $OPENSK_LIB is missing after fetching OpenSK" >&2; exit 1; }
# Hardening patch (PIN hook for the master-key vault); idempotent.
if ! grep -q cancel_in_flight "$OPENSK_DIR/libraries/opensk/src/lib.rs"; then
  # An older version of this patch (PIN hook only) may already be applied: drop it first.
  if grep -q unlock_with_pin "$OPENSK_DIR/libraries/opensk/src/api/persist.rs"; then
    git -C "$OPENSK_DIR" checkout -q -- libraries || { echo "error: cannot reset the old patch in $OPENSK_DIR" >&2; exit 1; }
  fi
  patch -p1 -d "$OPENSK_DIR" < third_party/opensk-harden.patch || { echo "error: opensk-harden.patch does not apply to this OpenSK revision" >&2; exit 1; }
fi
echo "OpenSK: $(git -C "$OPENSK_DIR" log -1 --format='%h %s' 2>/dev/null || echo 'unknown revision')"

# We pick the toolchain explicitly with +<toolchain>, so ignore the one pinned in the repo.
rm -f rust-toolchain.toml rust-toolchain

# ---- 4. build with real Cargo parameters -------------------------------------------------------
# Exactly ONE flash_* feature must be active, so default features are switched off.
FEATURES="rp2040_board,flash_${FLASH_MB}m"
[ "$SERIAL" = 1 ] && FEATURES="$FEATURES,usb_serial"
[ "$PUF" = 1 ] && FEATURES="$FEATURES,sram_puf"
echo "Cargo features: $FEATURES"

# OpenSK uses edition 2024 and let-chains, so the old 2025 nightlies cannot compile it.
# NOTE: embassy-executor 0.6 / embassy-rp 0.2 may not build on a nightly this new (see README).
if [ -n "$TOOLCHAIN" ]; then CANDIDATES=("$TOOLCHAIN"); else CANDIDATES=(nightly-2026-06-03 nightly); fi

BUILT=""
for t in "${CANDIDATES[@]}"; do
  echo; echo "=== Trying $t ==="
  rustup toolchain install "$t" --profile minimal -c rust-src -c llvm-tools -t thumbv6m-none-eabi || continue
  # With a committed Cargo.lock the build must use exactly it; without one, warn and resolve.
  if [ -f Cargo.lock ]; then
    LOCK_ARGS=(--locked)
  else
    echo "warning: no Cargo.lock in the repository: dependencies are resolved now and the build is NOT reproducible" >&2
    LOCK_ARGS=()
  fi
  if cargo "+$t" build --release ${LOCK_ARGS[@]+"${LOCK_ARGS[@]}"} --no-default-features --features "$FEATURES"; then
    BUILT="$t"; break
  fi
done
[ -n "$BUILT" ] || { echo "error: all toolchains failed (see the last compiler error above)" >&2; exit 1; }
echo "BUILD OK with $BUILT"

# ---- 5. UF2 ------------------------------------------------------------------------------------
ELF="$PROJ/target/thumbv6m-none-eabi/release/pico-fido-rs"
UF2="$OUT_DIR/pico-fido-rs-${FLASH_MB}m.uf2"
elf2uf2-rs "$ELF" "$UF2"
echo "Built: $UF2 ($(stat -c %s "$UF2") bytes, ${FLASH_MB} MiB flash, features: $FEATURES)"
