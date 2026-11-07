**Elements (sensitive data)**

| Element | Description | Current location | Software? | Hardware (ATECC)? | Recommendation |
|---|---|---|---|---|---|
| Credential private key | P-256 key per credential | Inside ATECC | No (shouldn't) | Yes (done) | Must be hardware |
| Attestation key | Attestation signing key | Inside ATECC | No | Yes (done) | Hardware |
| PIN-key | 32-byte key for CheckMac | ATECC (slot 11), only with `se_pin` | Yes | Partial (optional, off by default) | Hardware preferred |
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

### Checklist 

Credential keys, signing, the budget counter and the PIN gate are in the chip; the attestation key and a changeable PIN are not done.

**Legend:** ✅ done · 🟡 partial · ⬜ not done

**A. Hardware (ATECC608A)**
- ✅ Credential private keys are created in the chip (GenKey) and never leave it.
- ✅ ECDSA signing runs in the chip (Nonce pass-through + external Sign).
- ✅ Public key extraction runs in the chip.
- ✅ Signature budget: LimitedUse slots plus Counter 0, enforced by the chip. The firmware also refuses user presence when the budget reaches 0.
- ✅ Slot round-robin cursor in Counter 1, with the oldest credential evicted.
- 🟡 PIN-key (slot 11), CheckMac and Nonce/TempKey are implemented behind the optional `se_pin` feature and the `pingate` config. Both are off by default, and `CONFIG.md` says to verify them on real hardware.
- ⬜ Changeable PIN. The PIN key is fixed at provisioning, and an encrypted write (GenDig + MAC) is not implemented.
- 🟡 Attestation key: slot 7 is reserved and configured as non-limited-use, but the firmware never uses it. FIDO2 uses self-attestation and U2F attestation is not provisioned.
- ✅ TRNG: the chip's random output is XORed into the Pico RNG.

**B. Software (Pico)**
- ✅ Seed/vault, wrapping key, and hmac-secret/credRandom stay in software (`vault.rs`, `wrap.rs`).
- ✅ PIN hash is wrapped with Argon2id (64 KiB) plus HMAC.
- ✅ PIN retry counter is written to flash before the PIN is checked (8 tries).
- ✅ KeyStore and credential table live in flash.
- ✅ CTAP/ClientPIN logic comes from OpenSK.
- ✅ AES, HMAC, HKDF, SHA-256 and ECDH are software primitives (`PicoCrypto`).
- ✅ User presence needs a fresh BOOTSEL press.

**C. Software hardening that stands in for hardware**
- ✅ Retry counter is decremented before the PIN check.
- ✅ User presence is enforced for signing.
- ✅ RAM and stack scrubbing runs after each command (`scrub.rs`), plus a RAM guard.
- 🟡 Input validation: `REVIEW.md` lists fixes for map validation and FFI checks. No fuzzing or CBOR hardening beyond that is documented.

**D. Config images**
- ✅ Standard layout (generated by `gen_atecc_config.py --slots 7 -o out` as `atecc608a_fido_config.bin`; no ready-made image is in the repository): slots 0-6 are credential keys (P-256, LimitedUse, GenKey allowed) and slot 7 is the attestation key (not LimitedUse).
- ✅ The same with `--pin-gate` (`atecc608a_fido_config_pingate.bin`, generated, not stored in the repository) adds ReqAuth to credential slots 0-6 with AuthKey = slot 11. The attestation slot stays ungated.
- 🟡 Bus-level attack: I2C is not encrypted, so a bus attacker can still request signatures until the budget runs out. This is outside the software-attacker model.

**Next steps:** a changeable PIN (item A) and the attestation key are the two gaps. The hardware acceptance tests in `CONFIG.md` are still unrun.
