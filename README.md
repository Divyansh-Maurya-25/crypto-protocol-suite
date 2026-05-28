# Cryptographic Protocol Suite

> End-to-end implementation of five cryptographic systems in C — from symmetric stream ciphers through message authentication codes. Built for CIS 4634 (Trustworthy Computing Infrastructure) at USF.

[![C](https://img.shields.io/badge/C-C11-blue)](https://en.cppreference.com/w/c)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-3.x-red)](https://openssl.org)
[![LibTomCrypt](https://img.shields.io/badge/LibTomCrypt-1.18-orange)](https://github.com/libtom/libtomcrypt)
[![GMP](https://img.shields.io/badge/GMP-6.x-green)](https://gmplib.org)

---

## Modules

### 1. `symmetric-encryption/`

**ChaCha20 stream cipher** — Alice and Bob sides of a symmetric key exchange.

- Seed → ChaCha20 PRNG (LibTomCrypt) → keystream generation
- XOR encryption/decryption between parties
- Demonstrates seed-based deterministic key agreement

**Files:** `alice-1.c`, `bob-1.c`

---

### 2. `merkle-hash-tree/`

**Merkle Hash Tree** — integrity verification over a set of message blocks.

- Leaf nodes: SHA-256 hashes of each 64-byte message block
- Internal nodes: SHA-256 of concatenated child hashes
- Produces a single root hash that commits to all blocks
- Any single-block tamper is detectable in O(log n) verification steps

**Files:** `MHT.c`

---

### 3. `lamport-signatures/`

**Lamport One-Time Signature Scheme** — post-quantum-resistant digital signatures.

- `KeyGen.c` — generates 512 random 32-byte secrets; SHA-256 hashes each → public key
- `Sign.c` — reads message hash bit-by-bit; reveals one secret per bit position
- `Verify.c` — re-hashes revealed secrets and checks against public key

Each keypair is strictly single-use (revealing secrets for two messages breaks security).

**Files:** `KeyGen.c`, `Sign.c`, `Verify.c`

---

### 4. `ecdh-ecdsa-elgamal/`

**Three protocols on secp192k1** — key agreement, digital signatures, and public-key encryption.

#### ECDH + ECDSA (Alice & Bob)
- **Key generation:** SK = SHA-256(seed), PK = SK × G
- **ECDH:** Shared secret = SK_alice × PK_bob = SK_bob × PK_alice
- **ECDSA sign/verify:** OpenSSL `ECDSA_do_sign` / `ECDSA_do_verify` on SHA-256 digest

#### ElGamal Encryption
- **Encrypt:** C = k × G, D = k × PK + P_m (message encoded as EC point)
- **Decrypt:** P_m = D − SK × C = D + (−SK × C)
- Full EC point arithmetic via OpenSSL `EC_POINT_mul`, `EC_POINT_add`, `EC_POINT_invert`

**Files:** `KeyGen-1.c`, `alice-3.c`, `bob-3.c`, `Encrypt.c`, `Decrypt.c`

---

### 5. `lc-umac-rsa/`

**LC-UMAC message authentication** and **RSA homomorphic property demonstration**.

#### LC-UMAC (two implementations)
The same MAC computed two ways to verify cross-platform consistency:

- **`Intel_LCUMAC.c`** — native `__uint128_t` arithmetic (x86/x64 only)
- **`GMP_LCUMAC.c`** — GNU MP arbitrary-precision integers (portable)

**Algorithm:**

```
q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43   (128-bit prime)
For each 8-byte message block m_i with key (a_i, b_i):
term_i = (a_i × m_i + b_i) mod q
σ = Σ term_i mod q
```

Key pairs (a_i, b_i) derived from shared seed via ChaCha20 PRNG.

#### RSA Homomorphism (`GMP_CRSA.c`)
Demonstrates the multiplicative homomorphic property:

Enc(m1) × Enc(m2) mod n  =  Enc(m1 × m2 mod n)

**Files:** `Intel_LCUMAC.c`, `GMP_LCUMAC.c`, `GMP_CRSA.c`

---

## Setup

```bash
# Ubuntu/Debian
sudo apt install libssl-dev libtomcrypt-dev libgmp-dev

# Compile any module
gcc -O2 -o keygen KeyGen-1.c -lssl -lcrypto
gcc -O2 -o encrypt Encrypt.c -lssl -lcrypto
gcc -O2 -o lcumac Intel_LCUMAC.c -ltomcrypt -lgmp
```

---

## Core Concepts

| Module | Primitives | Key Idea |
|---|---|---|
| symmetric-encryption | ChaCha20, XOR | Stream cipher from shared seed |
| merkle-hash-tree | SHA-256, binary tree | Tamper-evident block commitment |
| lamport-signatures | SHA-256, one-time secrets | Post-quantum signature scheme |
| ecdh-ecdsa-elgamal | secp192k1, ECDH, ECDSA, EC-ElGamal | Asymmetric crypto on elliptic curves |
| lc-umac-rsa | 128-bit arithmetic, GMP, RSA | MAC construction + homomorphic encryption |
