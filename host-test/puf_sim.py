# Simulation of the code-offset / repetition fuzzy extractor used in src/puf.rs
import os, random, hmac, hashlib, math
SEC, REP = 256, 31
CODE = SEC*REP
def bits(b): return [(b[i>>3]>>(i&7))&1 for i in range(len(b)*8)]
def tobytes(bl):
    out=bytearray(len(bl)//8)
    for i,v in enumerate(bl):
        if v: out[i>>3]|=1<<(i&7)
    return bytes(out)
def encode(s):
    sb=bits(s); c=[0]*CODE
    for k in range(REP):
        for i in range(SEC): c[k*SEC+i]=sb[i]
    return c
def decode(x):
    s=[0]*SEC
    for i in range(SEC):
        ones=sum(x[k*SEC+i] for k in range(REP))
        s[i]=1 if ones>REP//2 else 0
    return s
def trial(ber, bias=0.5):
    r=[1 if random.random()<bias else 0 for _ in range(CODE)]
    s=os.urandom(32); c=encode(s)
    w=[a^b for a,b in zip(r,c)]
    r2=[v^(1 if random.random()<ber else 0) for v in r]
    x=[a^b for a,b in zip(r2,w)]
    return tobytes(decode(x))==s
for ber in (0.05,0.10,0.15,0.20):
    n=300; ok=sum(trial(ber) for _ in range(n))
    # analytic per-boot failure probability
    p=sum(math.comb(REP,k)*ber**k*(1-ber)**(REP-k) for k in range(REP//2+1,REP+1))
    print(f"BER {ber:.2f}: sim ok {ok}/{n}; analytic fail/boot = {1-(1-p)**SEC:.2e}")
