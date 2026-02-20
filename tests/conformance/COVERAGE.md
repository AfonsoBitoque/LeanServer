# Conformance Test Coverage

> ROADMAP F1.5 — External conformance testing tracking

## Test Vector Sources

### Verified (✅)

| Standard | Reference | Test Cases | File |
|----------|-----------|------------|------|
| AES-128-ECB | FIPS 197 Appendix B | 1 vector | `tests/TestAES.lean` |
| AES-128-GCM | NIST SP 800-38D | TC1–TC4 (encrypt + decrypt) | `tests/TestAES.lean` |
| SHA-256 | FIPS 180-4 | 4 vectors (empty, "abc", 448-bit, 896-bit) | `tests/TestRFCVectors.lean` |
| HMAC-SHA256 | RFC 4231 §4.2–4.4 | 3 test cases | `tests/TestRFCVectors.lean` |
| HKDF-SHA256 | RFC 5869 Appendix A | TC1 + TC2 (Extract + Expand) | `tests/TestRFCVectors.lean` |
| X25519 | RFC 7748 §6.1 | Alice/Bob key pair + shared secret | `tests/TestX25519.lean` |
| HPACK Integer | RFC 7541 Appendix C.1 | 3 vectors (10/5, 1337/5, 42/8) | `tests/TestRFCVectors.lean` |
| HPACK Huffman | RFC 7541 §5.2 | Roundtrip validation | `tests/TestIntegrationReal.lean` |
| QUIC VarInt | RFC 9000 §16 | 4 vectors (1/2/4/8 byte) | `tests/TestRFCVectors.lean` |
| TLS 1.3 KeySched | RFC 8446 §7.1 | 7 checks (key sizes, determinism) | `tests/TestRFCVectors.lean` |
| HTTP/2 Frames | RFC 7540 | Serialize/parse roundtrip, stream SM | `tests/TestIntegrationReal.lean` |
| TLS Record | RFC 8446 §5 | Encrypt/decrypt roundtrip | `tests/TestIntegrationReal.lean` |

### External Tools (⏳ — requires installation)

| Tool | Tests | Install Command | Run Command |
|------|-------|-----------------|-------------|
| **h2spec** | 146 HTTP/2 conformance tests | `go install github.com/summerwind/h2spec/cmd/h2spec@latest` | `h2spec -h localhost -p 8443 -t --tls -k` |
| **tlsfuzzer** | ~300 TLS 1.3 edge case scripts | `pip install tlsfuzzer` | `python3 -m tlsfuzzer.runner -h localhost -p 8443` |

### Planned (📋)

| Standard | Reference | Priority |
|----------|-----------|----------|
| AES-256-GCM | NIST SP 800-38D | Medium |
| ChaCha20-Poly1305 | RFC 8439 | Medium |
| ECDSA P-256 | FIPS 186-4 | Low |
| RSA-PSS | RFC 8017 | Low |

## How to Run

```bash
# All conformance suites
bash tests/conformance/run_conformance.sh

# Individual suites
bash tests/conformance/run_conformance.sh --crypto   # NIST/RFC vectors
bash tests/conformance/run_conformance.sh --h2       # HTTP/2
bash tests/conformance/run_conformance.sh --tls      # TLS 1.3

# Full external conformance (requires running server)
# Terminal 1: lake run leanserver
# Terminal 2: h2spec -h localhost -p 8443 -t --tls -k
```

## CI Integration

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs the internal crypto test binaries:
- `test_aes` — AES-GCM NIST vectors
- `test_primitives` — HMAC-SHA256 + HKDF
- `test_x25519` — X25519 RFC 7748
- `test_integration_real` — Full integration (TLS + HTTP/2 + HPACK + crypto)

To add `test_rfc_vectors` to CI, add this step to the `test-pure` job:
```yaml
- name: RFC Test Vectors
  run: .lake/build/bin/test_rfc_vectors
```
