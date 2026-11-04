**Elements (sensitive data)**

| Element | Description | Current location | Software? | Hardware (ATECC)? | Recommendation |
|---|---|---|---|---|---|
| Credential private key | P-256 key per credential | Inside ATECC | No (shouldn't) | Yes (done) | Must be hardware |
| Attestation key | Attestation signing key | Inside ATECC | No | Yes (done) | Hardware |
| PIN-key | 32-byte key for CheckMac | ATECC (slot 11) | Yes | Yes (done) | Hardware preferred |
| Seed / Master key | Root material for key derivation | On the Pico (vault) | Yes | Limited (small capacity) | Software + strong protection |
| Wrapping key | Encrypts credential IDs | Derived on the Pico | Yes | Partial (via chip AES) | Hybrid |
| PIN hash / verifier | PIN hash + retry counter | On the Pico (vault) | Yes | Partial | Software |
| Credential table (KeyStore) | Credential list + metadata | Pico flash | Yes | Impractical | Software |
| Budget counter (LimitedUse) | Limits the number of signatures | Inside ATECC | Weak emulation only | Yes | Hardware |
| Slot counter (round-robin) | Rotates through slots | Inside ATECC | Yes | Yes | Hardware |
| hmac-secret / credRandom | Material for FIDO extensions | On the Pico | Yes | Partial (via KDF) | Software or hybrid |
| TRNG | Randomness source | Mixed | Yes | Yes (chip has one) | Hybrid |

**Operations (cryptographic and security)**

| Operation | Description | Current location | Software? | Hardware (ATECC)? | Recommendation |
|---|---|---|---|---|---|
| Key generation (GenKey) | Creates a P-256 private key | Inside ATECC | Yes (but weaker) | Yes | Hardware |
| ECDSA signing | Signs a digest with the private key | Inside ATECC | Yes (but the key is exposed) | Yes | **Must be hardware** |
| Public key extraction | Reads the public key from a slot | Inside ATECC | Yes | Yes | Hardware |
| PIN verification (CheckMac) | Proves PIN knowledge without revealing it | Inside ATECC | Yes | Yes | Hardware preferred |
| Nonce + TempKey | Prepares for CheckMac/Sign | Inside ATECC | Yes | Yes | Hardware |
| AES encryption | Encrypts data | On the Pico | Yes | Yes (chip supports it) | Hybrid possible |
| HMAC | Message authentication | On the Pico | Yes | Yes | Hybrid possible |
| KDF / HKDF | Key derivation | On the Pico | Yes | Partial | Software or hybrid |
| SHA-256 | Hashing | On the Pico | Yes | Yes (limited) | Software is sufficient |
| Argon2id | Heavy PIN hashing | On the Pico | Yes | No | Software |
| User presence check | Physical button | On the Pico | n/a | n/a | Pico hardware |
| Random number generation | RNG | Mixed | Yes | Yes | Hybrid |
| RAM scrubbing | Wipes sensitive data from memory | On the Pico | Yes | n/a | Software |
| CTAP / ClientPIN logic | Full FIDO protocol | On the Pico | Yes | Impractical | Software |

**Decision summary**

- **Must stay hardware:** credential private key, ECDSA signing, GenKey, budget counter.
- **High value to move to hardware:** PIN verification (CheckMac + ReqAuth) and a changeable PIN.
- **Hybrid or software is acceptable:** seed/wrapping key, KeyStore, hmac-secret, and AES/HMAC/KDF (using the chip helps but isn't essential).
- **Should stay software:** CTAP protocol logic, Argon2id, credential table management.

The document offers two next steps: reordering this list by implementation priority, or moving straight to designing a changeable PIN.
