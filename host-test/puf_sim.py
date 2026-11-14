"""Simulation of the SRAM-PUF fuzzy extractor of src/puf_code.rs: pair-XOR debiasing of the cells, a
63x repetition code with majority decoding, and the entropy that is left when the helper data leaks.
Run: python3 host-test/puf_sim.py   (pure python, a few seconds)"""
import os, random, math
SEC, REP = 256, 63
CODE = SEC * REP            # 16128 pair bits
CELLS = 2 * CODE            # raw cells used (of the 32768 in the 4 KiB region)

def tail(n, p, k0):
    return sum(math.comb(n, k) * p**k * (1 - p)**(n - k) for k in range(k0, n + 1))

def H(x):
    return 0 if x in (0, 1) else -(x * math.log2(x) + (1 - x) * math.log2(1 - x))

print("reliability: failure probability per boot (256 secret bits, majority of %d pair bits)" % REP)
for ber in (0.05, 0.10, 0.12, 0.15):
    pair = 2 * ber * (1 - ber)          # a pair is wrong if exactly one of its two cells flips
    p = tail(REP, pair, REP // 2 + 1)
    print(f"  raw bit-error rate {ber:.2f} -> pair {pair:.3f}: {1 - (1 - p) ** SEC:.2e}")

print("\nstrength: bits of the secret that survive the helper data (cells independent, bias known to the attacker)")
print("  raw ones | pair-stream ones | guess per secret bit | entropy left")
for raw in (0.50, 0.55, 0.60, 0.65, 0.70):
    pp = 2 * raw * (1 - raw)            # P(pair bit = 1)
    pm = tail(REP, pp, REP // 2 + 1)
    g = max(pm, 1 - pm)
    ok = "accepted" if 0.46 <= pp <= 0.54 else "REFUSED at enrolment"
    print(f"   {raw:.2f}    |     {pp:.3f}        |        {g:.3f}         | {SEC * H(g):6.1f} bits  ({ok})")

print("\nMonte Carlo (end-to-end, a few trials): enrol, then decode a noisy re-read")
def trial(ber, bias):
    r = [1 if random.random() < bias else 0 for _ in range(CELLS)]
    pairs = [r[j] ^ r[j + CELLS // 2] for j in range(CODE)]
    s = [random.getrandbits(1) for _ in range(SEC)]
    w = [pairs[k * SEC + i] ^ s[i] for k in range(REP) for i in range(SEC)]
    r2 = [v ^ (1 if random.random() < ber else 0) for v in r]
    p2 = [r2[j] ^ r2[j + CELLS // 2] for j in range(CODE)]
    x = [p2[k * SEC + i] ^ w[k * SEC + i] for k in range(REP) for i in range(SEC)]
    dec = [1 if sum(x[k * SEC + i] for k in range(REP)) > REP // 2 else 0 for i in range(SEC)]
    return dec == s
for ber, bias in ((0.05, 0.5), (0.10, 0.5), (0.10, 0.6)):
    n = 20
    print(f"  raw BER {ber:.2f}, raw bias {bias:.2f}: decoded {sum(trial(ber, bias) for _ in range(n))}/{n}")
