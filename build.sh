#!/usr/bin/env bash
# Build the pico-fido-rs firmware (UF2) from GitHub.
#
# Usage:  bash build.sh [-s 2|4|8|16] [-n] [-t TOOLCHAIN] [-r REPO_URL] [-b BRANCH] [-o OUT_DIR]
#   -s  flash size of your board in MiB (default 2; a standard Raspberry Pi Pico has 2)
#   -n  build WITHOUT the USB serial number (privacy; drops the `usb_serial` feature)
#   -t  Rust nightly to use (default: try nightly-2025-03-05, then nightly-2025-02-15, then nightly)
#   -r  repository URL   (default https://github.com/rezamarzban/pico-fido-rs)
#   -b  branch           (default main)
#   -o  output directory (default ./out)
# Result: <OUT_DIR>/pico-fido-rs-<N>m.uf2   (hold BOOTSEL while plugging in, copy the file to the RPI-RP2 drive)
set -euo pipefail

FLASH_MB=2
SERIAL=1
TOOLCHAIN=""
REPO="https://github.com/rezamarzban/pico-fido-rs"
BRANCH="main"
OUT_DIR="$PWD/out"

usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while getopts "s:nt:r:b:o:h" opt; do
  case "$opt" in
    s) FLASH_MB="$OPTARG" ;;
    n) SERIAL=0 ;;
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
PROJ="$(dirname "$(find "$SRC" -name Cargo.toml -not -path '*/host-test/*' -not -path '*/target/*' | awk '{print length, $0}' | sort -n | head -1 | cut -d' ' -f2-)")"
echo "Project dir: $PROJ ($(git -C "$SRC" log -1 --format='%h %s'))"
cd "$PROJ"

grep -q "flash_${FLASH_MB}m" Cargo.toml || { echo "error: this revision has no 'flash_${FLASH_MB}m' feature in Cargo.toml" >&2; exit 1; }

# We pick the toolchain explicitly with +<toolchain>, so ignore the one pinned in the repo.
rm -f rust-toolchain.toml rust-toolchain

# `use defmt::*` in src/main.rs shadows the standard assert!, which breaks the compile-time
# flash-size check. Fix it (only if the repository does not already contain the fix).
if grep -q 'const _: () = assert!(' src/main.rs; then
  sed -i 's/const _: () = assert!(/const _: () = core::assert!(/' src/main.rs
  echo "Applied core::assert! fix to src/main.rs (please commit it to the repository)."
fi

# ---- 4. build with real Cargo parameters -------------------------------------------------------
# Exactly ONE flash_* feature must be active, so default features are switched off.
FEATURES="rp2040_board,flash_${FLASH_MB}m"
[ "$SERIAL" = 1 ] && FEATURES="$FEATURES,usb_serial"
echo "Cargo features: $FEATURES"

if [ -n "$TOOLCHAIN" ]; then CANDIDATES=("$TOOLCHAIN"); else CANDIDATES=(nightly-2025-03-05 nightly-2025-02-15 nightly); fi

BUILT=""
for t in "${CANDIDATES[@]}"; do
  echo; echo "=== Trying $t ==="
  rustup toolchain install "$t" --profile minimal -c rust-src -c llvm-tools -t thumbv6m-none-eabi || continue
  if cargo "+$t" build --release --locked --no-default-features --features "$FEATURES" \
     || cargo "+$t" build --release --no-default-features --features "$FEATURES"; then
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
