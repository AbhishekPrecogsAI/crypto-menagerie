# 🦎 crypto-menagerie

**A deliberately diverse zoo of cryptographic algorithms — from broken to
post-quantum — built to exercise every part of a CBOM/QBOM scan.**

This repo is a self-contained proof-of-concept fixture for the Precogs.ai
CBOM/QBOM engine. Scanning it produces a rich Cryptographic Bill of Materials
that lights up the full feature set: algorithm discovery across languages,
risk scoring, deprecation observation, quantum-readiness, the post-quantum
migration target, certificates, TLS/SSH profiles, code signing, secret
material, and the GEN-003 dependency graph.

> Everything here is a benign demonstration. The only "secrets" are AWS's own
> published **example** keys and throwaway self-signed certs — nothing real.

---

## What's inside (algorithm coverage)

| Class | Algorithms present | Why |
|---|---|---|
| **Broken** | MD5, SHA-1, RC4, DES, DES-ECB | CRITICAL/HIGH findings, CA-004 deprecation rows |
| **Deprecated** | 3DES, Blowfish, DSA-1024, RSA-1024, SHA1withRSA, MD5withRSA | "Remove now" findings + weak-key detection |
| **Weak config** | TLS 1.0/1.1, RC4/3DES cipher suites, dh-group1-sha1, hmac-md5 | Protocol/negotiation checks |
| **Modern classical** | AES-256-GCM, ChaCha20-Poly1305, SHA-256/512, HKDF, scrypt, ECDSA P-256/P-384, Ed25519, X25519, RSA-4096 | Conformant-today baseline; asymmetric still Shor-breakable |
| **Post-quantum** | ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), SLH-DSA (FIPS 205), X25519MLKEM768 hybrid | The PQC-001 migration target |

---

## File map

| Path | Language | Demonstrates |
|---|---|---|
| `src/js/legacy_hashing.js` | JavaScript | MD5, SHA-1, RIPEMD-160, HMAC-SHA1, DES-CBC |
| `src/js/modern_crypto.js` | JavaScript | AES-256-GCM, SHA-256/512, scrypt, Ed25519, X25519 |
| `src/python/symmetric.py` | Python | DES, 3DES, RC4, Blowfish, AES-CBC, AES-GCM, ChaCha20-Poly1305 |
| `src/python/asymmetric.py` | Python | RSA-1024/4096, DSA-1024, ECDSA P-256/P-384, Ed25519, DH-2048 |
| `src/python/pqc.py` | Python | ML-KEM-768, ML-DSA-65, SLH-DSA, X25519+ML-KEM hybrid |
| `src/java/SignatureDemo.java` | Java | MD5withRSA, SHA1withRSA, SHA256withRSA, SHA384withECDSA, DESede, AES/GCM |
| `src/go/tls_server.go` | Go | Weak vs hardened TLS (X25519MLKEM768 PQC hybrid) |
| `src/go/kms.go` | Go | HKDF-SHA256, AES key-wrap, envelope encryption (KMS-style key hierarchy) |
| `src/c/legacy_crypto.c` | C | OpenSSL MD5, DES-ECB, RSA-1024 keygen (native/firmware-style) |
| `config/nginx-tls.conf` | Config | Deprecated protocols + weak ciphers alongside TLS 1.3 |
| `config/sshd_config` | Config | Weak KEX/ciphers/MACs + modern curve25519/chacha20 |
| `certs/rsa1024-sha1.pem` | Cert | 1024-bit RSA signed with SHA-1 (weak key + weak sig algo) |
| `certs/ec-p256.pem` | Cert | EC P-256 signed with SHA-256 (modern) |
| `firmware/README.md` | Docs | Code-signing manifest (ML-DSA-65 primary, SHA1withRSA legacy fallback) |
| `.env.example` | Config | AWS example keys + HMAC/JWT key references (secret detection) |
| `package.json` / `requirements.txt` / `go.mod` | Manifests | Crypto library dependencies → GEN-003 dependency graph |

---

## Feature coverage (what the scan should surface)

- **Algorithm discovery** — 5 languages (JS, Python, Java, Go, C) plus config
  and certificate parsing.
- **Risk & exploitability scoring** — MD5/RC4/DES rank CRITICAL/HIGH.
- **Deprecation observation (CA-004)** — every broken/deprecated primitive
  appears as a removal-plan row.
- **Quantum readiness** — RSA, DSA, ECDSA, DH, X25519 flagged as
  Shor-breakable (harvest-now-decrypt-later); the QBOM score reflects the mix.
- **PQC migration (PQC-001)** — ML-KEM / ML-DSA / SLH-DSA and the hybrid group
  are the "already migrated" evidence.
- **Certificates (PKI)** — a weak and a modern cert for the certificate
  inventory and expiry/weak-key checks.
- **TLS & SSH profiles** — protocol and cipher-suite negotiation inventory.
- **Code signing (CS-SVC)** — the firmware signing manifest.
- **KMS key hierarchy (KMS-003)** — the wrap/derive envelope flow.
- **Secret material** — AWS example keys and key-file references.
- **Dependency graph (GEN-003)** — the three manifests give the ref graph.

---

## Scan it

```bash
# With the Precogs CBOM engine (adjust to your CLI):
precogs-cbom scan ./crypto-menagerie --output cbom.json

# or point a Precogs project's repo source at this folder and run a scan
# from the workspace, then open the asset's Findings / Dependencies /
# Results tabs and generate a QBOM.
```

Expect: dozens of components across the risk spectrum, a populated
deprecation report, a low-but-improving quantum-readiness grade, and PQC
components proving the migration target exists.
