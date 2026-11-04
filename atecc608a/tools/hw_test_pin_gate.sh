#!/bin/sh
# Hardware experiment for an UNLOCKED ATECC608A (wirenboard atecc-util in Termux/Linux).
# It shows how YOUR chip behaves before anything is locked, so the firmware assumptions can be
# checked: (1) ReqAuth blocks signing without the PIN, (2) the PIN authorisation survives the
# Nonce that loads the digest, (3) which operations spend Counter 0.
# Usage:  BUS=10 sh hw_test_pin_gate.sh      (BUS = your I2C bus / adapter id, as for `atecc -b`)
# Needs: python3, atecc, a chip with config+data zone unlocked. It rewrites the config (no lock).
set -u
BUS="${BUS:-10}"
A="atecc -b $BUS"
T=$(mktemp -d); cd "$T" || exit 1
HERE=$(dirname "$0")
say() { printf '\n== %s\n' "$*"; }
run() { printf '+ %s\n' "$*"; "$@"; printf '  -> exit %s\n' "$?"; }

python3 "$HERE/gen_atecc_config.py" --slots 7 --budget 20 --pin-gate -o "$T" >/dev/null || exit 1
say "1. write PIN-gated config and set the budget to 20 (config zone must be unlocked)"
run $A -c "write-config $T/atecc608a_fido_config_pingate.bin"
run $A -c "counter-init 0 -20"
run $A -c "counter-read 0 -r"            # expect 20 counts left

say "2. PIN key into slot 11 (password 'test' via atecc-util's own derivation; data zone unlocked)"
printf 'test\n' > pw.txt; printf 'wrong\n' > pw_bad.txt
run $A -c "auth-make-passwd 11 pw.txt"
run $A -c "counter-read 0 -r"            # unchanged expected: 20 (a data write is not a key use)

say "3. GenKey in slot 0 WITHOUT authorisation (expect failure if GenKey honours ReqAuth)"
run $A -c "ecc-gen 0 pub0.bin"
say "3b. GenKey WITH authorisation"
run $A -c "auth-passwd 11 pw.txt" -c "ecc-gen 0 pub0.bin"
run $A -c "counter-read 0 -r"            # note: does auth cost 1? does GenKey cost 1?

say "4. public key only, WITHOUT authorisation (firmware import() relies on this working)"
run $A -c "ecc-gen-pub 0 pub0b.bin"
cmp pub0.bin pub0b.bin && echo "  same public key"

say "5. sign WITHOUT authorisation (must fail)"
echo hello > msg.txt
run $A -c "ecc-sign 0 msg.txt sig_noauth.bin"
say "5b. sign after a WRONG password (must fail, costs budget)"
run $A -c "auth-passwd 11 pw_bad.txt" -c "ecc-sign 0 msg.txt sig_bad.bin"
run $A -c "counter-read 0 -r"
say "5c. sign after the RIGHT password in the same session (must work: firmware needs this)"
run $A -c "auth-passwd 11 pw.txt" -c "ecc-sign 0 msg.txt sig_ok.bin"
run $A -c "counter-read 0 -r"            # budget cost of one authorised signature
run $A -c "ecc-verify 0 msg.txt sig_ok.bin"

say "6. exhaust: keep signing until the chip refuses (budget 20 total)"
i=0; while $A -c "auth-passwd 11 pw.txt" -c "ecc-sign 0 msg.txt s.bin" >/dev/null 2>&1; do i=$((i+1)); [ $i -gt 40 ] && break; done
echo "  authorised signatures that worked after step 5c: $i"
run $A -c "counter-read 0 -r"            # expect 0 (or 1) counts left

say "Report these results (especially steps 3, 3b, 4, 5, 5c and every counter value)."
echo "Work dir: $T   (the chip is configured but NOT locked; re-run write-config to start over)"
