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
        c = g.build(10)
        lines, ok = g.describe(c)
        self.assertTrue(ok)
        self.assertEqual(sum("ECC P-256 private key" in l for l in lines), 10)  # attestation + 9 credentials
        self.assertEqual(sum("LIMITED-USE" in l for l in lines), 0)
        self.assertEqual(c[g.COUNTER0:g.COUNTER0 + 16], g.COUNTER_REF * 2)
        for i in range(10, 16):
            self.assertEqual(c[g.SLOT_CFG + 2 * i:g.SLOT_CFG + 2 * i + 2], g.UNUSED_SLOT_CFG[i])

    def test_counter_roundtrip(self):
        for v in (0, 1, 15, 16, 31, 32, 500, 65535, g.COUNTER_MAX - 500, g.COUNTER_MAX):
            self.assertEqual(g.counter_value(g.counter_bytes(v)), v)

    def test_the_provisioned_chip_config(self):
        """atecc608a/out/atecc608a_general_config.bin: slots 0-9 private keys, the attached general I2C config."""
        path = os.path.join(os.path.dirname(__file__), "..", "out", "atecc608a_general_config.bin")
        c = open(path, "rb").read()
        self.assertEqual(len(c), 128)
        for i in range(10):
            self.assertEqual(c[g.SLOT_CFG + 2 * i:g.SLOT_CFG + 2 * i + 2], g.SLOT_CRED, i)
            self.assertEqual(c[g.KEY_CFG + 2 * i:g.KEY_CFG + 2 * i + 2], g.KEY_CRED, i)
        self.assertEqual(c[g.COUNTER0:g.COUNTER0 + 16], g.COUNTER_REF * 2)
        self.assertEqual(c[g.I2C_ENABLE], 1)
        self.assertEqual(c[g.I2C_ADDR], 0xC0)
        self.assertEqual(g.build(10), c)   # the generator reproduces the shipped image byte for byte

    def test_base_is_patched_not_replaced(self):
        base = bytearray(128); base[16] = 0xB0; base[30] = 0x77
        c = g.build(10, base)
        self.assertEqual(c[16], 0xB0)           # I2C address preserved
        self.assertEqual(c[g.SLOT_CFG:g.SLOT_CFG + 2], g.SLOT_CRED)

    def test_bounds(self):
        for s in (1, 17):
            with self.assertRaises(ValueError):
                g.build(s)




if __name__ == "__main__":
    unittest.main()
