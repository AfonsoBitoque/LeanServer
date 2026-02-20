# Architecture

> Visual map of the LeanServer module structure.
> **81 Lean library files · ~33K LOC · 935 theorems · 0 sorry · 4 C FFI files · ~1 007 LOC C**

---

## Layer Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Web Layer                               │
│  WebApplication · WebApplicationSimple · SampleWebApp · Tests   │
├─────────────────────────────────────────────────────────────────┤
│                      Server Layer                               │
│  HTTPServer (monolith) · Concurrency · LoadBalancer             │
│  ┌───────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │  Middleware    │  │ Observability│  │  Deployment          │ │
│  │ CORS,Compress │  │ Metrics,     │  │ BlueGreen, Canary,   │ │
│  │ ContentNeg,   │  │ Tracing,     │  │ ConfigReload,        │ │
│  │ RequestId,    │  │ HealthCheck, │  │ GracefulShutdown     │ │
│  │ Timeout       │  │ Benchmark    │  │                      │ │
│  └───────────────┘  └──────────────┘  └──────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                     Protocol Layer                              │
│  HTTP2 · HTTP3 · QUIC · HPACK · WebSocket · gRPC               │
│  WebSocketOverHTTP2 · WebSocketCompression · QUICRetry          │
├─────────────────────────────────────────────────────────────────┤
│                      Crypto Layer                               │
│  AES · SHA256 · X25519 · RSA · TLS 1.3 · X509                  │
│  SideChannel (CT model) · MutualTLS · CryptoFFI (OpenSSL)      │
├─────────────────────────────────────────────────────────────────┤
│                       Core Layer                                │
│  Basic · Base64 · BufferPool · Logger · ParserCombinators       │
│  SafeAccess · ServerError                                       │
├─────────────────────────────────────────────────────────────────┤
│  Database Layer          │  Verification Layer                  │
│  Database · PostgreSQL   │  Proofs · Spec (TLS 3-layer          │
│  MySQL · SQLite (FFI)    │  refinement) · CompositionProofs     │
├──────────────────────────┴──────────────────────────────────────┤
│                      C FFI Layer                                │
│  Network.c (sockets/epoll) · Network_simple.c (OpenSSL)        │
│  sqlite_ffi.c · test_ffi.c (stubs)                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Import / Dependency Graph

```
Core (Basic, Logger, ServerError, ParserCombinators, SafeAccess, BufferPool, Base64)
  │
  ├──▶ Crypto (AES, Crypto/SHA256, X25519, RSA, SideChannel, MutualTLS, X509, CryptoFFI)
  │       │
  │       ├──▶ Protocol (HPACK, HTTP2, HTTP3, QUIC, WebSocket, gRPC, QUICRetry, ...)
  │       │       │
  │       │       ├──▶ Server.Concurrency, Server.LoadBalancer
  │       │       │       │
  │       │       │       └──▶ Server.HTTPServer  (monolith — TLS+HTTP/2+QUIC loops)
  │       │       │               │
  │       │       │               ├──▶ Server.HTTPServer/* (re-export modules)
  │       │       │               ├──▶ Middleware/* (CORS, Compression, Timeout, ...)
  │       │       │               ├──▶ Observability/* (Metrics, Tracing, HealthCheck)
  │       │       │               └──▶ Deployment/* (BlueGreen, Canary, GracefulShutdown)
  │       │       │
  │       │       └──▶ Web (WebApplication, SampleWebApp)
  │       │
  │       └──▶ Spec (TLSSpec → TLSModel → TLSRefinement, TLSStateMachineProofs, ...)
  │
  ├──▶ Db (Database, PostgreSQL, MySQL, SQLite)
  │
  └──▶ Proofs (85+ formal proofs importing Core + Crypto + Protocol)
```

---

## Module Reference

### Core (`LeanServer/Core/`)
8 files · ~1,380 LOC

| Module | Purpose |
|--------|---------|
| `Basic` | Foundational types, config parsing, HTTP request/response |
| `Base64` | Base64 encode/decode |
| `BufferPool` | Fixed-size reusable buffer tiers (16B–16KB) to reduce GC pressure |
| `ByteSlice` | Zero-copy byte array slicing with bounds proofs |
| `Logger` | Structured JSON logging with severity levels and request IDs |
| `ParserCombinators` | Verified parser combinators with bounds/progress/determinism proofs |
| `SafeAccess` | Bounds-checked byte array access |
| `ServerError` | Unified error type hierarchy |

### Crypto (`LeanServer/Crypto/`)
14 files · ~5,110 LOC

| Module | Purpose |
|--------|---------|
| `AES` | AES-128/256, key expansion, AES-GCM AEAD |
| `CertificateManager` | X.509 certificate loading and management |
| `Crypto` | SHA-256, HMAC, HKDF, hex utilities, TLS 1.3 key schedule |
| `FFI` | Native OpenSSL bindings (100–2000× faster) |
| `MTLSAuth` | Client certificate authentication (RFC 8446 §4.3.2) |
| `NonceManager` | Nonce generation and replay protection |
| `RSA` | RSA PKCS#1 v1.5 signing/verification |
| `SHA256` | Pure-Lean SHA-256 implementation (FIPS 180-4) |
| `SideChannel` | Secret type, constant-time comparison, zeroization proofs |
| `TLSHandshake` | TLS 1.3 handshake flow (ClientHello/ServerHello) |
| `TLSKeySchedule` | HKDF-Expand-Label, handshake/application key derivation |
| `TLSSession` | TLS session state, encrypt/decrypt record layer |
| `X25519` | Curve25519 ECDH (Montgomery ladder) |
| `X509Validation` | X.509 certificate chain validation, ASN.1 DER parsing |

### Protocol (`LeanServer/Protocol/`)
9 files · ~5,020 LOC

| Module | Purpose |
|--------|---------|
| `HPACK` | HPACK header compression (RFC 7541) — Huffman, dynamic table |
| `HTTP2` | HTTP/2 frames, stream state machine, flow control (RFC 7540) |
| `HTTP3` | HTTP/3 over QUIC (RFC 9114) |
| `QUIC` | QUIC transport — packets, loss detection, congestion, migration (RFC 9000) |
| `QUICRetry` | Retry token generation and address validation |
| `WebSocket` | WebSocket frames, masking, handshake (RFC 6455) |
| `WebSocketOverHTTP2` | RFC 8441 tunneling |
| `WebSocketCompression` | permessage-deflate (RFC 7692) |
| `GRPC` | gRPC message framing and service definitions |

### Server (`LeanServer/Server/`)
29 files · ~11,760 LOC

The server is organized into five sub-groups:

**Runtime:** `HTTPServer` (5,653 LOC monolith — TLS handshake loop, epoll accept, HTTP/2 frames, QUIC UDP, request routing), `Concurrency` (green threads, task pool, backoff retry), `LoadBalancer` (round robin, least connections, IP hash), `Production` (production config, connection pooling, rate limiting, session management)

**HTTPServer Sub-modules** (`HTTPServer/`): `ConnectionPool`, `DistributedRateLimiter`, `H2Handler`, `QPACK`, `QUICHandler`, `RateLimiter`, `Router`, `ServerConfig`, `TLSHandler`, `Tracing`

**Middleware:** `CORS`, `ResponseCompression`, `ContentNegotiation`, `RequestId`, `Timeout`, `CircuitBreaker`

**Observability:** `Metrics` (Prometheus), `DistributedTracing` (OpenTelemetry), `HealthCheck`, `Benchmark`, `Spec` (server specification)

**Deployment:** `BlueGreenDeployment`, `CanaryDeployment`, `ConfigReload`, `GracefulShutdown`

### Database (`LeanServer/Db/`)
4 files · ~1,140 LOC

| Module | Purpose |
|--------|---------|
| `Database` | Type-safe query builder, connection pool interface (stub) |
| `PostgreSQL` | PostgreSQL driver interface (stub) |
| `MySQL` | MySQL driver interface (stub) |
| `SQLite` | SQLite FFI driver — 5 C functions, SQL injection prevention proofs |

### Web (`LeanServer/Web/`)
5 files · ~1,350 LOC

| Module | Purpose |
|--------|---------|
| `Framework` | Web framework DSL — rate limiting, middleware, template engine |
| `WebApplication` | Full web framework — routing, middleware composition, database integration |
| `WebApplicationSimple` | Minimal routing without DB dependencies |
| `SampleWebApp` | Demo REST API |
| `WebAppTests` | Framework tests |

### Verification (`LeanServer/Proofs.lean`)
1 file · ~1,650 LOC — 85+ formal proofs organized as:

- **Sanity checks** (34): Constant/default value verification via `rfl`, `native_decide`
- **Structural properties** (26): Type invariants, protocol structure via `cases`, `simp`, `omega`
- **Protocol correctness** (25): Codec roundtrips, parser safety, memory invariants

### Formal Specification (`LeanServer/Spec/`)
11 files · ~5,450 LOC · 633 theorems — seL4-inspired 3-layer refinement:

1. **TLSSpec** — Abstract TLS 1.3 state machine (pure propositions)
2. **TLSModel** — Executable deterministic `step` function
3. **TLSRefinement** — Bridge proving implementation refines model
4. **ServerStep** — Server-side state transitions and step functions
5. **TLSStateMachineProofs** — Safety: no skip handshake, keys established
6. **ProtocolInvariants** — RFC invariants (HPACK table, flow control, packet numbers)
7. **UniversalCodecProofs** — ∀-quantified codec roundtrips
8. **CompositionProofs** — End-to-end pipeline correctness
9. **AdvancedProofs** — Advanced security properties (forward secrecy, key independence)
10. **AdvancedProofs2** — Additional protocol composition proofs
11. **AdvancedProofs3** — Extended verification coverage

---

## C FFI Layer (`src/`)

| File | LOC | Bindings |
|------|-----|----------|
| `Network.c` | 430 | TCP/UDP sockets, `epoll`, `accept4`, `bind`, `listen`, signals |
| `crypto_ffi.c` | 365 | OpenSSL: SHA-256, HMAC-SHA256, AES-128-GCM, X25519 |
| `sqlite_ffi.c` | 162 | SQLite3: open, exec, close, changes, last_insert_rowid |
| `db_stubs.c` | 50 | Stub FFI for database drivers |

All C code compiles in **stub mode** (without external libraries) for CI.
Real functionality enabled with `-DLEANSERVER_USE_SQLITE`, linking `-lsqlite3`.

---

## Build Targets

| Target | Root | Description |
|--------|------|-------------|
| `leanserver` | `Main` | Main HTTPS server executable |
| `webserver` | `app.WebServerMainSimple` | Simple web server |
| `realhttps` | `app.RealHTTPServer` | Real HTTPS server |
| `webapptests` | `LeanServer.Web.WebAppTests` | Web framework tests |
| 11 test targets | `tests.*` | Unit, integration, property, RFC vector tests |
| 5 fuzz targets | `fuzz.*` | TLS, HTTP/2, QUIC, WebSocket, extended fuzzers |

---

## Key Design Decisions

1. **Pure Lean crypto** — All cryptographic algorithms (AES, SHA-256, X25519) implemented in pure Lean for verification. Optional OpenSSL FFI for production speed.

2. **Minimal C FFI** — 63 `@[extern]` bindings. Socket I/O and SQLite use C; everything else is pure Lean.

3. **Dependent types for safety** — Invalid protocol states are unrepresentable (e.g., TLS state machine transitions encoded as type constraints).

4. **Three-layer refinement** — Spec → Model → Implementation with proofs at each level, inspired by seL4.

5. **No sorry** — All 935 theorems are fully proved. `native_decide` used only for concrete value checks.
