# Package Extraction Guide — Derived Lake Packages

## Current Status: LeanServerPure Library ✅

Before extracting individual packages, the monorepo now exposes a **pure Lean library**
(`LeanServerPure`) that can be imported as a Lake dependency with zero C dependencies.

### Using LeanServerPure (available now)

Add to your `lakefile.toml`:
```toml
[[require]]
name = "LeanServer"
git = "https://github.com/<user>/LeanServer6"
rev = "main"
```

Import in your Lean files:
```lean
import LeanServerPure                 -- everything (43 modules)
import LeanServer.Crypto.AES          -- or individual modules
import LeanServer.Protocol.HTTP2
import LeanServer.Proofs
```

**Included**: Core (8), Crypto without FFI (13), Protocol (9), Spec (11), Proofs (1), Concurrency (1)
**Excluded**: Crypto/FFI, Db/*, Server/HTTPServer*, Server/LoadBalancer, Web/*

---

## Future: Standalone Package Extraction

The following describes how to further extract three standalone packages from LeanServer6.


## 1. `lean-crypto` — Pure Lean Cryptographic Primitives

**Repository**: `lean-crypto`  
**Description**: First pure-Lean cryptographic library in the ecosystem.  
**Zero dependencies** — no FFI, no C code.

### Modules to extract

| Source Path | Package Module | Description |
|-------------|----------------|-------------|
| `LeanServer/Crypto/SHA256.lean` | `LeanCrypto.SHA256` | SHA-256 hash (FIPS 180-4) |
| `LeanServer/Crypto/AES.lean` | `LeanCrypto.AES` | AES-128-GCM encrypt/decrypt |
| `LeanServer/Crypto/X25519.lean` | `LeanCrypto.X25519` | Curve25519 scalar multiplication |
| `LeanServer/Crypto/RSA.lean` | `LeanCrypto.RSA` | RSA sign/verify (PKCS#1 v1.5) |
| `LeanServer/Crypto/Crypto.lean` (subset) | `LeanCrypto.HMAC` | HMAC-SHA256, HKDF-SHA256 |
| `LeanServer/Core/Base64.lean` | `LeanCrypto.Base64` | Base64 encode/decode |

### Proofs to include

From `LeanServer/Proofs.lean`:
- `sha256_deterministic`, `sha256_length_32`
- `hmac_deterministic`
- `aes_encrypt_decrypt_inverse`, `aes_deterministic`
- `x25519_deterministic`, `x25519_base_length_32`

### lakefile.toml

```toml
[package]
name = "lean-crypto"
version = "0.1.0"
leanVersion = "v4.27.0"

[[lean_lib]]
name = "LeanCrypto"
```

---

## 2. `lean-tls` — TLS 1.3 Library with Formal Proofs

**Repository**: `lean-tls`  
**Depends on**: `lean-crypto`  
**Description**: TLS 1.3 handshake + record layer with state machine proofs.

### Modules to extract

| Source Path | Package Module | Description |
|-------------|----------------|-------------|
| `LeanServer/Crypto/TLSHandshake.lean` | `LeanTLS.Handshake` | TLS 1.3 handshake flow |
| `LeanServer/Crypto/TLSKeySchedule.lean` | `LeanTLS.KeySchedule` | Key derivation (RFC 8446 §7) |
| `LeanServer/Crypto/TLSSession.lean` | `LeanTLS.Session` | Session state + encrypt/decrypt |
| `LeanServer/Crypto/CertificateManager.lean` | `LeanTLS.Certificates` | X.509 cert loading |
| `LeanServer/Crypto/X509Validation.lean` | `LeanTLS.X509Validation` | Chain validation + trust store |
| `LeanServer/Crypto/MTLSAuth.lean` | `LeanTLS.MTLS` | Mutual TLS authentication |

### Proofs to include

From `LeanServer/Proofs.lean`:
- `tls_state_machine_theorem` — State transitions enforced by types
- `tls_key_uniqueness` — Keys derived from unique random
- `tls_handshake_key_derivation_correct`
- `tls_master_secret_independent`, `tls_key_expansion_independent`
- `handshake_integrity_theorem` — Transcript hash integrity
- `client_auth_implies_cert_verified`, `mtls_mutual_auth_theorem`

### lakefile.toml

```toml
[package]
name = "lean-tls"
version = "0.1.0"
leanVersion = "v4.27.0"

[[require]]
name = "lean-crypto"
scope = "leanprover-community"
version = "0.1.0"

[[lean_lib]]
name = "LeanTLS"
```

---

## 3. `lean-http` — HTTP Protocol Library

**Repository**: `lean-http`  
**Depends on**: `lean-crypto` (for WebSocket SHA-1 handshake)  
**Description**: HTTP/1.1 parser, HTTP/2 framing + HPACK, WebSocket.

### Modules to extract

| Source Path | Package Module | Description |
|-------------|----------------|-------------|
| `LeanServer/Protocol/HTTP2.lean` | `LeanHTTP.HTTP2` | HTTP/2 framing (RFC 7540) |
| `LeanServer/Protocol/HPACK.lean` | `LeanHTTP.HPACK` | HPACK header compression (RFC 7541) |
| `LeanServer/Protocol/WebSocket.lean` | `LeanHTTP.WebSocket` | WebSocket framing (RFC 6455) |
| `LeanServer/Protocol/WebSocketOverHTTP2.lean` | `LeanHTTP.WS2` | WebSocket over HTTP/2 (RFC 8441) |
| `LeanServer/Protocol/WSCompression.lean` | `LeanHTTP.WSCompression` | permessage-deflate |
| `LeanServer/Protocol/GRPC.lean` | `LeanHTTP.GRPC` | gRPC over HTTP/2 |
| `LeanServer/Core/Basic.lean` (subset) | `LeanHTTP.Types` | HTTP request/response types |

### Proofs to include

From `LeanServer/Proofs.lean`:
- `http2_stream_id_odd` — Client streams are always odd
- `hpack_integer_encode_decode_inverse`
- `websocket_frame_mask_involution`

### lakefile.toml

```toml
[package]
name = "lean-http"
version = "0.1.0"
leanVersion = "v4.27.0"

[[require]]
name = "lean-crypto"
scope = "leanprover-community"
version = "0.1.0"

[[lean_lib]]
name = "LeanHTTP"
```

---

## Extraction Checklist

For each package:

1. [ ] Create new repository
2. [ ] Copy relevant modules, adjusting imports
3. [ ] Run `lake build` — zero errors
4. [ ] Copy relevant proofs — zero sorry, zero axiom
5. [ ] Add README.md with usage examples
6. [ ] Add LICENSE (Apache 2.0 or MIT)
7. [ ] Tag v0.1.0 and publish to Lake registry
