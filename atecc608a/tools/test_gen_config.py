import os, subprocess, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(__file__))
import gen_atecc_config as g

C_REF = r'''
#include <stdio.h>
#include <stdint.h>
int main(int argc,char**argv){ for(int a=1;a<argc;a++){ uint32_t counter_value=strtoul(argv[a],0,10);
 uint16_t lin_a,lin_b,bin_a,bin_b; uint8_t bytes[8];
 lin_a = (uint16_t)((0xFFFFu >> (counter_value % 32u)) & 0xFFFF);
 lin_b = (uint16_t)((0xFFFFu >> ((counter_value >= 16u) ? (counter_value - 16u) % 32u : 0u)) & 0xFFFF);
 bin_a = (uint16_t)(counter_value / 32u);
 bin_b = (counter_value >= 16u) ? ((uint16_t)((counter_value - 16u) / 32u)) : 0u;
 bytes[0]=lin_a>>8;bytes[1]=lin_a&255;bytes[2]=lin_b>>8;bytes[3]=lin_b&255;
 bytes[4]=bin_a>>8;bytes[5]=bin_a&255;bytes[6]=bin_b>>8;bytes[7]=bin_b&255;
 for(int i=0;i<8;i++)printf("%02x",bytes[i]); printf("\n");} return 0;}
'''

class T(unittest.TestCase):
    def test_counter_matches_cryptoauthlib(self):
        vals = [0, 1, 15, 16, 17, 31, 32, 33, 500, 1000, 2097151 - 500, 2097151]
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "r.c")
            open(src, "w").write("#include <stdlib.h>\n" + C_REF)
            subprocess.check_call(["gcc", "-o", os.path.join(d, "r"), src])
            out = subprocess.check_output([os.path.join(d, "r")] + [str(v) for v in vals]).decode().split()
        for v, o in zip(vals, out):
            self.assertEqual(g.counter_bytes(v).hex(), o, v)

    def test_layout(self):
        c = g.build(7, 100)
        lines, ok = g.describe(c)
        self.assertTrue(ok)
        self.assertEqual(sum("ECC P-256 private key" in l for l in lines), 8)  # 7 credential + attestation
        self.assertEqual(sum("limited-use" in l for l in lines), 7)
        self.assertEqual(c[g.SLOT_CFG + 14:g.SLOT_CFG + 16], g.SLOT_ATTEST)
        self.assertEqual(c[g.COUNTER0:g.COUNTER0 + 8], g.counter_bytes(g.COUNTER_MAX - 100))

    def test_pin_gate(self):
        c = g.build(7, 100, pin_gate=True)
        lines, ok = g.describe(c)
        self.assertTrue(ok, lines)
        self.assertEqual(sum("ReqAuth(slot 11)" in l for l in lines), 7)
        self.assertTrue(any("PIN key" in l for l in lines))
        self.assertEqual(c[g.KEY_CFG + 2 * 11:g.KEY_CFG + 2 * 11 + 2], g.KEY_PIN)
        self.assertEqual(c[g.KEY_CFG:g.KEY_CFG + 2], bytes([0x93, 0x0B]))
        self.assertEqual(c[g.KEY_CFG + 14:g.KEY_CFG + 16], g.KEY_CRED)  # attestation: no PIN
        # without the flag nothing changes
        self.assertNotIn("ReqAuth", "\n".join(g.describe(g.build(7, 100))[0]))

    def test_base_is_patched_not_replaced(self):
        base = bytearray(128); base[16] = 0xB0; base[30] = 0x77
        c = g.build(8, 10, base)
        self.assertEqual(c[16], 0xB0)           # I2C address preserved
        self.assertEqual(c[g.SLOT_CFG:g.SLOT_CFG + 2], g.SLOT_CRED)

    def test_bounds(self):
        for s, b in [(0, 1), (16, 1), (7, 0), (7, g.COUNTER_MAX + 1)]:
            with self.assertRaises(ValueError):
                g.build(s, b)



class PinKey(unittest.TestCase):
    def test_matches_rust_vector(self):
        import pin_key
        sn = bytes.fromhex("0123aabbccddeeffee")
        # same constant as PIN_KEY_VECTOR in host-test/se/tests/se.rs
        self.assertEqual(pin_key.pin_key(sn, "1234").hex(),
                         "304346fdece1a73fc067c36125ff6eec55ab5745ed378e7cebba3cb3aa9485c5")


if __name__ == "__main__":
    unittest.main()
