# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in LeanServer6, please report it responsibly.

### How to Report

1. **Email:** Send a detailed report to the project maintainer (see repository contacts)
2. **GitHub:** Use [GitHub Security Advisories](https://github.com/lean-server/LeanServer6/security/advisories/new) to report privately
3. **Do NOT** open a public issue for security vulnerabilities

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected components (TLS, HPACK, crypto, etc.)
- Potential impact assessment
- Suggested fix (if you have one)

### Response Timeline

| Phase | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 1 week |
| Fix development | Within 2 weeks (critical), 4 weeks (other) |
| Public disclosure | After fix is released |

### Scope

The following are **in scope** for security reports:

- Bugs in Lean cryptographic implementations (AES, SHA-256, X25519, RSA-PSS, HKDF)
- TLS 1.3 handshake vulnerabilities
- HPACK/QPACK compression bugs (e.g., the index double-counting bug found in v0.1)
- HTTP/2 flow control violations
- Certificate validation bypasses
- Memory safety issues in C FFI code (`src/Network.c`, `src/crypto_ffi.c`)
- Information disclosure via error messages or timing

The following are **out of scope:**

- Denial of service via network flooding (see [THREAT_MODEL.md](THREAT_MODEL.md))
- Timing side-channel attacks on pure Lean crypto (documented limitation)
- Vulnerabilities in dependencies (Lean 4 compiler, GCC/Clang, Linux kernel)

## Security Advisories

Known security issues and their fixes will be documented here:

| ID | Date | Severity | Component | Description | Fixed In |
|----|------|----------|-----------|-------------|----------|
| LSV-2025-001 | 2025-01 | Critical | HPACK | Dynamic table index double-counting in `encodeHeaderField` — cases 2 and 3 added `staticTable.size` to indices that already included it, causing COMPRESSION_ERROR for any client sending >10 unique headers | v0.2 |

## Verified Components

Components with formal proofs have a higher assurance level. See [THREAT_MODEL.md](THREAT_MODEL.md)
for the complete verification boundary.

| Component | Verified | Proof Count | Notes |
|-----------|----------|-------------|-------|
| AES-128-GCM | ✅ Functional correctness | 6 | S-Box bijectivity, round structure |
| SHA-256 | ✅ Output properties | 7 | Digest length, determinism, RFC test vectors |
| HKDF/HMAC | ✅ Output properties | 10 | Key derivation sizes, RFC test vectors |
| X25519 | ✅ Curve properties | 2 | DH commutativity, ephemeral independence |
| Nonce management | ✅ Counter monotonicity | 20 | Uniqueness, N-step, overflow |
| HPACK | ✅ Codec roundtrip | 14 | Integer encode/decode, table invariants |
| QUIC VarInt | ✅ Codec roundtrip | 11 | All 4 ranges, universal nonempty |
| TLS state machine | ✅ Refinement chain | 40 | 3-layer: Spec → Model → ServerStep |
| HTTP/2 frames | ✅ Stream FSM + flow | 11 | Window bounds, stream lifecycle |
| Certificate validation | ✅ Time + chain | 5 | Expired, not-yet-valid, self-signed |
| HTTPServer | ✅ Property proofs | 17 | Config defaults, validators, middleware |
| Network.c (FFI) | ❌ Unverified | 0 | CBMC harnesses in `cbmc/` |

## Acknowledgments

We thank security researchers who responsibly disclose vulnerabilities.
Contributors will be acknowledged here (with permission).
