# 📚 LeanServer API Reference (Auto-Generated)

> This document is automatically generated from source code docstrings.
> Do not edit manually — run `./scripts/gen_api_docs.sh > docs/API_GENERATED.md`.

## Table of Contents

- [LeanServer.Core.Base64](#leanservercore-base64)
- [LeanServer.Core.Basic](#leanservercore-basic)
- [LeanServer.Core.Logger](#leanservercore-logger)
- [LeanServer.Core.SafeAccess](#leanservercore-safeaccess)
- [LeanServer.Core.ServerError](#leanservercore-servererror)
- [LeanServer.Crypto.AES](#leanservercrypto-aes)
- [LeanServer.Crypto.CertificateManager](#leanservercrypto-certificatemanager)
- [LeanServer.Crypto.Crypto](#leanservercrypto-crypto)
- [LeanServer.Crypto.MTLSAuth](#leanservercrypto-mtlsauth)
- [LeanServer.Crypto.RSA](#leanservercrypto-rsa)
- [LeanServer.Crypto.SHA256](#leanservercrypto-sha256)
- [LeanServer.Crypto.TLSHandshake](#leanservercrypto-tlshandshake)
- [LeanServer.Crypto.TLSKeySchedule](#leanservercrypto-tlskeyschedule)
- [LeanServer.Crypto.TLSSession](#leanservercrypto-tlssession)
- [LeanServer.Crypto.X25519](#leanservercrypto-x25519)
- [LeanServer.Db.Database](#leanserverdb-database)
- [LeanServer.Db.MySQL](#leanserverdb-mysql)
- [LeanServer.Db.PostgreSQL](#leanserverdb-postgresql)
- [LeanServer.Proofs](#leanserverproofs)
- [LeanServer.Protocol.GRPC](#leanserverprotocol-grpc)
- [LeanServer.Protocol.HPACK](#leanserverprotocol-hpack)
- [LeanServer.Protocol.HTTP2](#leanserverprotocol-http2)
- [LeanServer.Protocol.HTTP3](#leanserverprotocol-http3)
- [LeanServer.Protocol.QUIC](#leanserverprotocol-quic)
- [LeanServer.Protocol.QUICRetry](#leanserverprotocol-quicretry)
- [LeanServer.Protocol.WSCompression](#leanserverprotocol-wscompression)
- [LeanServer.Protocol.WebSocket](#leanserverprotocol-websocket)
- [LeanServer.Protocol.WebSocketOverHTTP2](#leanserverprotocol-websocketoverhttp2)
- [LeanServer.Server.Benchmark](#leanserverserver-benchmark)
- [LeanServer.Server.Concurrency](#leanserverserver-concurrency)
- [LeanServer.Server.ConfigReload](#leanserverserver-configreload)
- [LeanServer.Server.GracefulShutdown](#leanserverserver-gracefulshutdown)
- [LeanServer.Server.HTTPServer](#leanserverserver-httpserver)
- [LeanServer.Server.HTTPServer.ConnectionPool](#leanserverserver-httpserver-connectionpool)
- [LeanServer.Server.HTTPServer.H2Handler](#leanserverserver-httpserver-h2handler)
- [LeanServer.Server.HTTPServer.QPACK](#leanserverserver-httpserver-qpack)
- [LeanServer.Server.HTTPServer.QUICHandler](#leanserverserver-httpserver-quichandler)
- [LeanServer.Server.HTTPServer.RateLimiter](#leanserverserver-httpserver-ratelimiter)
- [LeanServer.Server.HTTPServer.Router](#leanserverserver-httpserver-router)
- [LeanServer.Server.HTTPServer.ServerConfig](#leanserverserver-httpserver-serverconfig)
- [LeanServer.Server.HTTPServer.TLSHandler](#leanserverserver-httpserver-tlshandler)
- [LeanServer.Server.HTTPServer.Tracing](#leanserverserver-httpserver-tracing)
- [LeanServer.Server.LoadBalancer](#leanserverserver-loadbalancer)
- [LeanServer.Server.Metrics](#leanserverserver-metrics)
- [LeanServer.Server.Production](#leanserverserver-production)
- [LeanServer.Server.Timeout](#leanserverserver-timeout)
- [LeanServer.Web.SampleWebApp](#leanserverweb-samplewebapp)
- [LeanServer.Web.WebAppTests](#leanserverweb-webapptests)
- [LeanServer.Web.WebApplication](#leanserverweb-webapplication)
- [LeanServer.Web.WebApplicationSimple](#leanserverweb-webapplicationsimple)

---

## LeanServer.Core.Base64

**Lines:** 31

**Imports:**
```lean
import LeanServer.Core.Basic
```

### Functions

- `b64Index` (line 5)
- `decode` (line 14)

**Docstrings:** 1

---

## LeanServer.Core.Basic

```
/-!
  # Basic Utilities
  Foundational types, constant-time operations, and HTTP request/response structures.
  Imported by nearly every module in LeanServer.
-/
```

**Lines:** 134

### Structures

- `structure Port` (line 48)
- `structure HTTPRequest` (line 62)
- `structure HTTPResponse` (line 68)
- `structure Route` (line 73)

### Inductive Types

- `inductive ConnectionState` (line 53)

### Functions

- `constantTimeEqual` (line 19)
- `constantTimeSelect` (line 29)
- `readConfigFile` (line 35)
- `ValidPort` (line 46)
- `closeConnection` (line 59)
- `routes` (line 78)
- `handleRequest` (line 84)
- `parseHTTPRequest` (line 91)
- `serializeHTTPResponse` (line 118)

### Theorems

- `handleRequestTotal` (line 126)
- `parseQuota` (line 130)

**Docstrings:** 2

---

## LeanServer.Core.Logger

```
/-!
  # Structured Logging System
  Provides structured, JSON-compatible logging with timestamps, log levels,
  request IDs, and component tagging.

  ## Features
  - Log levels: ERROR, WARN, INFO, DEBUG, TRACE
  - Structured JSON output (optional)
  - Monotonic timestamps
  - Request/correlation ID tracking
  - Component tagging
  - Configurable minimum log level

  ## Usage
  ```lean
  let logger ← Logger.create .INFO
  logger.info "Server" "Listening on port 4433"
  logger.error "TLS" "Handshake failed" (some reqId)
  logger.withContext "HTTP2" reqId (fun log => do
    log .INFO "Processing stream 5"
```

**Lines:** 213

### Structures

- `structure LogEntry` (line 54)
- `structure LoggerConfig` (line 88)
- `structure Logger` (line 94)
- `structure ScopedLogger` (line 169)

### Inductive Types

- `inductive LogLevel` (line 28)
- `inductive LogFormat` (line 83)

### Functions

- `LogLevel.priority` (line 42)
- `LogLevel.parse` (line 47)
- `LogEntry.toText` (line 64)
- `LogEntry.toJSON` (line 74)
- `Logger.create` (line 99)
- `Logger.log` (line 115)
- `Logger.fatal` (line 123)
- `Logger.error` (line 128)
- `Logger.warn` (line 133)
- `Logger.info` (line 138)
- `Logger.debug` (line 143)
- `Logger.trace` (line 148)
- `generateRequestId` (line 161)
- `Logger.scoped` (line 176)
- `ScopedLogger.log` (line 180)
- `ScopedLogger.error` (line 184)
- `ScopedLogger.warn` (line 185)
- `ScopedLogger.info` (line 186)
- `ScopedLogger.debug` (line 187)
- `ScopedLogger.trace` (line 188)
- `getLogger` (line 200)
- `configureLogger` (line 203)
- `glog` (line 208)

**Docstrings:** 28

---

## LeanServer.Core.SafeAccess

```
/-!
  # Safe Byte Access
  Provides bounds-checked byte array access for network protocol parsing.
  Prevents panic!/crash from out-of-bounds `get!` when processing untrusted network data.

  ## Usage
  ```lean
  -- Instead of: let b := data.get! offset
  -- Use:        let b ← safeGet data offset |>.toIO "context"
  -- Or:         match safeGet data offset with | some b => ... | none => ...
  ```
-/
```

**Lines:** 74

### Functions

- `Option.toIO` (line 69)

**Docstrings:** 8

---

## LeanServer.Core.ServerError

```
/-!
  # Server Error Types
  Unified error handling for LeanServer.
  All server components should use `ServerError` instead of raw strings.

  ## Usage
  ```lean
  def myFunction : IO (Except ServerError α) := do
    ...
    return Except.error (.network .connectionReset "peer reset connection")
  ```
-/
```

**Lines:** 190

### Inductive Types

- `inductive NetworkErrorKind` (line 17)
- `inductive TLSErrorKind` (line 30)
- `inductive ProtocolErrorKind` (line 42)
- `inductive QUICErrorKind` (line 55)
- `inductive ConfigErrorKind` (line 66)
- `inductive ServerError` (line 74)

### Functions

- `ServerError.category` (line 149)
- `ServerError.message` (line 160)
- `ServerError.isRetryable` (line 171)
- `ServerError.fromIO` (line 183)

**Docstrings:** 11

---

## LeanServer.Crypto.AES

```
/-- AES S-Box table -/
def sBox : ByteArray := ByteArray.mk #[
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

```

**Lines:** 664

**Imports:**
```lean
import LeanServer.Core.Basic
```

### Functions

- `sBox` (line 6)
- `rCon` (line 26)
- `subByte` (line 32)
- `xtime` (line 37)
- `mul` (line 43)
- `subBytes` (line 58)
- `shiftRows` (line 62)
- `shiftRowsColMajor` (line 118)
- `mixColumns` (line 127)
- `addRoundKey` (line 164)
- `expandKey` (line 170)
- `encryptBlock` (line 195)
- `xorBytes` (line 218)
- `getBit` (line 266)
- `shiftRightBlock` (line 272)
- `gfMul` (line 281)
- `inc32` (line 296)
- `ghash` (line 315)
- `aesGCMEncrypt` (line 347)
- `aesGCMDecrypt` (line 385)
- `expandKey256` (line 434)
- `aes256EncryptBlock` (line 465)
- `aes256GCMEncrypt` (line 488)
- `aes256GCMDecrypt` (line 525)
- `subBytesSIMD` (line 581)
- `shiftRowsSIMD` (line 586)
- `mixColumnsSIMD` (line 591)
- `addRoundKeySIMD` (line 616)
- `encryptBlockSIMD` (line 620)

**Docstrings:** 27

---

## LeanServer.Crypto.CertificateManager

```
/-!
  # Certificate Manager — Re-export Module
  Focused import path for X.509 certificate operations.

  ## Key Functions
  - `loadCertificateChain` — Load PEM certificate chain from file
  - `buildCertificateChain` — Build TLS certificate chain message
  - `buildCertificateChainWithOCSP` — Certificate chain with OCSP stapling
  - `buildCertificateChainWithSCT` — Certificate chain with SCT
  - `loadOCSPResponse` — Load OCSP response from file
  - `loadSCTList` — Load SCT list from file
  - `loadCertificateDER` — Load DER certificate
  - `loadPrivateKey` — Load PEM private key
  - `sign` / `verify` — RSA signing/verification

  ## Usage
  ```lean
  import LeanServer.Crypto.CertificateManager
  let chain ← LeanServer.loadCertificateChain "cert.pem"
  ```
```

**Lines:** 52

**Imports:**
```lean
import LeanServer.Crypto.Crypto
```

**Docstrings:** 6

---

## LeanServer.Crypto.Crypto

**Lines:** 2072

**Imports:**
```lean
import LeanServer.Crypto.X25519
import Init.Data.Array
import LeanServer.Crypto.AES
import LeanServer.Core.Base64
import LeanServer.Crypto.RSA
```

### Structures

- `structure Key (t : KeyType)` (line 83)
- `structure Certificate` (line 87)
- `structure X509Certificate` (line 91)
- `structure TLSSession (state : TLSState)` (line 106)
- `structure HandshakeKeys` (line 368)
- `structure ClientHello` (line 712)
- `structure ServerHello` (line 725)
- `structure ClientExtensions` (line 755)
- `structure PSKEntry` (line 1082)
- `structure PSKCache` (line 1093)
- `structure ApplicationKeys` (line 1319)
- `structure TLSSessionTLS` (line 1328)
- `structure SessionTicket` (line 1693)
- `structure AntiReplayEntry` (line 1839)
- `structure AntiReplayWindow` (line 1844)
- `structure QUICStreamFrame` (line 1860)
- `structure TicketKey` (line 1959)
- `structure TicketKeyManager` (line 1965)

### Inductive Types

- `inductive KeyType` (line 78)
- `inductive TLSState` (line 99)

### Functions

- `hashLen` (line 15)
- `aesKeyLen` (line 18)
- `aesGCMIvLen` (line 21)
- `hmacBlockSize` (line 24)
- `tlsAES128GCMSHA256` (line 27)
- `x25519GroupId` (line 30)
- `rsaPSSRSAeSHA256` (line 33)
- `defaultTicketLifetimeSec` (line 36)
- `defaultMaxEarlyData` (line 39)
- `pskCacheMaxSize` (line 42)
- `encodeUInt16BE` (line 49)
- `encodeUInt24BE` (line 53)
- `zeroBytes` (line 57)
- `loadPEMFile` (line 62)
- `bytesToUInt32` (line 110)
- `hexChar` (line 114)
- `bytesToHex` (line 118)
- `hex` (line 128)
- `uint32ToBytes` (line 131)
- `sha256_pad` (line 138)
- `sha256_h0` (line 165)
- `sha256_k` (line 170)
- `rotr` (line 181)
- `sigma0` (line 185)
- `sigma1` (line 189)
- `sigma0_small` (line 193)
- `sigma1_small` (line 197)
- `ch` (line 201)
- `maj` (line 205)
- `sha256_process_block` (line 209)
- `sha256_real` (line 264)
- `sha256` (line 278)
- `xorArray` (line 286)
- `hmac_sha256` (line 291)
- `hkdf_extract` (line 310)
- `encodeHkdfLabel` (line 316)
- `hkdfExpandLabel` (line 361)
- `deriveSecret` (line 365)
- `deriveHandshakeKeysWithLabels` (line 384)
- `deriveHandshakeKeys` (line 415)

### Theorems

- `tls_session_state_well_defined` (line 2064)
- `key_has_data` (line 2071)

**Docstrings:** 130

---

## LeanServer.Crypto.MTLSAuth

**Lines:** 418

**Imports:**
```lean
import LeanServer.Crypto.Crypto
import LeanServer.Crypto.RSA
import LeanServer.Crypto.CertificateManager
import LeanServer.Core.Base64
```

### Structures

- `structure MTLSConfig` (line 44)
- `structure ClientCertificateMsg` (line 146)
- `structure CertificateVerifyMsg` (line 209)
- `structure MTLSState` (line 307)

### Inductive Types

- `inductive MTLSResult` (line 51)

### Functions

- `tlsClientHello` (line 67)
- `tlsServerHello` (line 68)
- `tlsEncryptedExtensions` (line 69)
- `tlsCertificate` (line 70)
- `tlsCertificateRequest` (line 71)
- `tlsCertificateVerify` (line 72)
- `tlsFinished` (line 73)
- `supportedClientSignatureAlgorithms` (line 81)
- `buildCertificateRequest` (line 97)
- `parseClientCertificate` (line 166)
- `parseCertificateVerify` (line 222)
- `buildClientCertVerifyContent` (line 240)
- `verifyClientCertificateVerify` (line 255)
- `validateClientCertChain` (line 278)
- `MTLSState.init` (line 316)
- `MTLSState.processClientCert` (line 320)
- `MTLSState.processClientCertVerify` (line 347)
- `MTLSState.isComplete` (line 360)
- `MTLSState.summary` (line 370)
- `loadCACertificate` (line 385)

### Theorems

- `mtls_disabled_always_complete` (line 414)

**Docstrings:** 20

---

## LeanServer.Crypto.RSA

**Lines:** 175

**Imports:**
```lean
import LeanServer.Core.Basic
```

### Functions

- `i2osp` (line 19)
- `os2ip` (line 27)
- `rsaep` (line 31)
- `mgf1` (line 36)
- `xorBytes` (line 47)
- `emsa_pss_encode` (line 53)
- `rsassa_pss_sign` (line 86)
- `emsa_pss_verify` (line 101)
- `rsassa_pss_verify` (line 152)

**Docstrings:** 10

---

## LeanServer.Crypto.SHA256

```
/-!
  # SHA-256, HMAC-SHA256, HKDF — Re-export Module
  This module provides a clean import path for hash primitives.
  The implementations live in `Crypto.lean`; this module re-exports them
  and adds focused documentation.

  ## Functions
  - `sha256` — SHA-256 hash (FIPS 180-4)
  - `hmac_sha256` — HMAC-SHA256 (RFC 2104)
  - `hkdf_extract` — HKDF-Extract (RFC 5869)
  - `hkdfExpandLabel` — HKDF-Expand-Label (RFC 8446 §7.1)
  - `deriveSecret` — Derive-Secret (RFC 8446 §7.1)

  ## Usage
  ```lean
  import LeanServer.Crypto.SHA256
  let hash := LeanServer.sha256 data
  let mac  := LeanServer.hmac_sha256 key msg
  ```
-/
```

**Lines:** 47

**Imports:**
```lean
import LeanServer.Crypto.Crypto
```

### Functions

- `outputLen` (line 42)
- `blockSize` (line 45)

**Docstrings:** 6

---

## LeanServer.Crypto.TLSHandshake

```
/-!
  # TLS Handshake — Re-export Module
  Focused import path for TLS 1.3 handshake message construction and parsing.

  ## Key Functions
  - `parseClientHello` — Parse ClientHello from raw bytes
  - `generateServerHello` — Build ServerHello message
  - `buildFlight2` — Build Flight 2 (EncryptedExtensions + Certificate + Finished)
  - `buildFlight2PSK` — Build Flight 2 for PSK resumption
  - `initiateHandshake` — Full handshake initiation
  - `buildHelloRetryRequest` — HelloRetryRequest message

  ## Usage
  ```lean
  import LeanServer.Crypto.TLSHandshake
  match LeanServer.parseClientHello data with
  | some ch => -- process ClientHello
  | none => -- invalid
  ```
-/
```

**Lines:** 63

**Imports:**
```lean
import LeanServer.Crypto.Crypto
```

**Docstrings:** 9

---

## LeanServer.Crypto.TLSKeySchedule

```
/-!
  # TLS Key Schedule — Re-export Module
  Provides focused imports for TLS 1.3 key derivation functions.

  ## Key Functions
  - `deriveHandshakeKeys` — Derive client/server handshake keys from shared secret
  - `deriveQUICHandshakeKeys` — Derive QUIC-specific handshake keys (RFC 9001)
  - `deriveApplicationKeys` — Derive application traffic keys
  - `deriveTLSApplicationKeys` — Derive TLS-specific application keys
  - `deriveNextTrafficSecret` — Key update (RFC 8446 §7.2)
  - `getNonce` — Compute per-record nonce from IV and sequence number

  ## Usage
  ```lean
  import LeanServer.Crypto.TLSKeySchedule
  let keys := LeanServer.deriveHandshakeKeys sharedSecret helloHash
  ```
-/
```

**Lines:** 40

**Imports:**
```lean
import LeanServer.Crypto.Crypto
```

**Docstrings:** 4

---

## LeanServer.Crypto.TLSSession

```
/-!
  # TLS Session Management — Re-export Module
  Focused import path for TLS session lifecycle: tickets, PSK cache,
  anti-replay, record encryption/decryption.

  ## Key Types
  - `TLSSessionTLS` — Full TLS session state
  - `PSKCache` / `PSKEntry` — Pre-Shared Key cache
  - `AntiReplayWindow` — 0-RTT anti-replay protection
  - `SessionTicket` — NewSessionTicket message
  - `TicketKeyManager` — Ticket key rotation

  ## Key Functions
  - `encryptTLS13Record` / `decryptTLS13Record` — Record-layer encryption
  - `encryptAppData` — Application data encryption
  - `transitionToAppData` — Transition session from handshake to data state
  - `buildNewSessionTicket` — Build NewSessionTicket message
  - `encryptSessionTicket` / `decryptSessionTicket` — Ticket encryption

  ## Usage
```

**Lines:** 56

**Imports:**
```lean
import LeanServer.Crypto.Crypto
```

**Docstrings:** 6

---

## LeanServer.Crypto.X25519

```
/-- Field P = 2^255 - 19 -/
def P : Nat := (2^255) - 19

def A24 : Nat := 121665

/-- Addition mod P -/
def add (a b : Nat) : Nat := (a + b) % P

/-- Subtraction mod P -/
def sub (a b : Nat) : Nat := 
  if a >= b then (a - b) % P 
  else (a + P - b) % P

/-- Multiplication mod P -/
def mul (a b : Nat) : Nat := (a * b) % P

/-- Inverse mod P using Fermat's Little Theorem (a^(P-2) mod P) -/
partial def modPow (b e m : Nat) : Nat :=
  match e with
  | 0 => 1
```

**Lines:** 107

### Functions

- `P` (line 4)
- `A24` (line 6)
- `add` (line 9)
- `sub` (line 12)
- `mul` (line 17)
- `inv` (line 29)
- `scalarMultNat` (line 32)
- `clamp` (line 86)
- `scalarmult` (line 95)
- `scalarmult_base` (line 102)

**Docstrings:** 11

---

## LeanServer.Db.Database

**Lines:** 447

**Imports:**
```lean
import LeanServer.Core.Basic
```

### Structures

- `structure DatabaseConfig` (line 23)
- `structure DatabaseConnection` (line 52)
- `structure QueryResult` (line 73)
- `structure DatabaseTransaction` (line 86)
- `structure ConnectionPool` (line 115)
- `structure TableSchema` (line 261)
- `structure ColumnSchema` (line 265)
- `structure QueryBuilder` (line 296)
- `structure Migration` (line 339)
- `structure MigrationState` (line 353)
- `structure DatabaseManager (α : Type) [DatabaseDriver α]` (line 367)

### Inductive Types

- `inductive DatabaseType : Type` (line 14)
- `inductive ConnectionStatus : Type` (line 44)
- `inductive DatabaseError : Type` (line 100)
- `inductive ColumnType : Type` (line 272)

### Functions

- `DatabaseConnection.isConnected` (line 59)
- `initConnectionPool` (line 165)
- `getConnectionFromPool'` (line 174)
- `getConnectionFromPool` (line 218)
- `returnConnectionToPool` (line 232)
- `closeConnectionPool` (line 243)
- `closeConnectionPoolLegacy` (line 251)
- `QueryBuilder.buildSelect` (line 315)
- `initDatabaseManager` (line 375)
- `executeQueryWithPool` (line 386)
- `escapeSqlString` (line 408)
- `buildParameterizedQuery` (line 424)
- `getDatabaseStats` (line 441)

./scripts/gen_api_docs.sh: line 153: [: 0
0: integer expected
---

## LeanServer.Db.MySQL

**Lines:** 236

**Imports:**
```lean
import LeanServer.Db.Database
```

### Structures

- `structure MYSQL` (line 14)
- `structure MYSQL_RES` (line 21)
- `structure MYSQL_ROW` (line 28)
- `structure MySQLDriver` (line 111)

### Functions

- `mysqlConnect` (line 79)
- `mysqlResultToQueryResult` (line 92)
- `leanTypeToMySQLType` (line 208)
- `generateCreateTableMySQL` (line 220)
- `generateMySQLMigrationSQL` (line 233)

./scripts/gen_api_docs.sh: line 153: [: 0
0: integer expected
---

## LeanServer.Db.PostgreSQL

**Lines:** 270

**Imports:**
```lean
import LeanServer.Db.Database
```

### Structures

- `structure PGconn` (line 14)
- `structure PGresult` (line 21)
- `structure PostgreSQLDriver` (line 138)

### Inductive Types

- `inductive ExecStatusType : Type` (line 28)

### Functions

- `buildConnectionString` (line 85)
- `pgStatusToDatabaseError` (line 89)
- `pgExecStatusToResult` (line 96)
- `leanTypeToPostgresType` (line 242)
- `generateCreateTableSQL` (line 254)
- `generatePostgresMigrationSQL` (line 267)

./scripts/gen_api_docs.sh: line 153: [: 0
0: integer expected
---

## LeanServer.Proofs

**Lines:** 952

**Imports:**
```lean
import LeanServer.Core.Basic
import LeanServer.Crypto.Crypto
import LeanServer.Crypto.AES
import LeanServer.Protocol.HTTP2
import LeanServer.Protocol.QUIC
import LeanServer.Protocol.HTTP3
import LeanServer.Crypto.RSA
import LeanServer.Crypto.X25519
import Std.Tactic.BVDecide
```

### Theorems

- `sha256_deterministic` (line 43)
- `hmac_deterministic` (line 53)
- `http2_initial_window_size` (line 90)
- `http2_initial_no_streams` (line 97)
- `http2_default_max_frame_size` (line 105)
- `http2_default_max_concurrent_streams` (line 112)
- `http2_client_stream_ids_odd` (line 120)
- `http2_server_stream_ids_even` (line 130)
- `http2_valid_client_stream_id_correct` (line 140)
- `http2_stream_zero_invalid` (line 154)
- `http2_default_stream_state` (line 161)
- `quic_cid_8_bytes_valid` (line 177)
- `quic_cid_min_valid` (line 185)
- `quic_drain_period_positive` (line 194)
- `quic_client_bidi_stream_id` (line 202)
- `quic_server_bidi_stream_id` (line 212)
- `quic_client_uni_stream_id` (line 222)
- `quic_server_uni_stream_id` (line 232)
- `quic_initial_state_idle` (line 241)
- `quic_state_beq_refl` (line 248)

**Docstrings:** 90

---

## LeanServer.Protocol.GRPC

**Lines:** 314

**Imports:**
```lean
import LeanServer.Core.Basic
import LeanServer.Protocol.HTTP2
import LeanServer.Protocol.HPACK
```

### Structures

- `structure GRPCMessage` (line 86)
- `structure GRPCMethod` (line 99)
- `structure GRPCRequest` (line 114)
- `structure GRPCResponse` (line 127)
- `structure GRPCServiceRegistry` (line 145)
- `structure GRPCServer` (line 279)

### Inductive Types

- `inductive GRPCMessageType` (line 11)
- `inductive GRPCStatus` (line 24)

### Functions

- `GRPCStatus.toCode` (line 65)
- `createGRPCServiceRegistry` (line 154)
- `registerGRPCHandler` (line 159)
- `findGRPCHandler` (line 164)
- `encodeGRPCMessage` (line 168)
- `decodeGRPCMessage` (line 186)
- `parseGRPCMethod` (line 206)
- `createGRPCResponseHeaders` (line 220)
- `processGRPCRequest` (line 228)
- `createGRPCServer` (line 290)
- `registerGRPCService` (line 298)
- `startGRPCServer` (line 304)
- `stopGRPCServer` (line 311)

./scripts/gen_api_docs.sh: line 153: [: 0
0: integer expected
---

## LeanServer.Protocol.HPACK

**Lines:** 563

**Imports:**
```lean
import LeanServer.Core.Basic
```

### Structures

- `structure HeaderField` (line 9)
- `structure DynamicTable` (line 83)
- `structure HPACKEncoder` (line 131)
- `structure HPACKDecoder` (line 136)

### Functions

- `staticTable` (line 18)
- `initDynamicTable` (line 90)
- `headerFieldSize` (line 97)
- `addToDynamicTable` (line 104)
- `initHPACKEncoder` (line 141)
- `initHPACKDecoder` (line 146)
- `findInStaticTable` (line 151)
- `findNameInStaticTable` (line 161)
- `findInDynamicTable` (line 172)
- `findNameInDynamicTable` (line 182)
- `encodeInteger` (line 192)
- `huffmanEncode` (line 284)
- `encodeString` (line 313)
- `huffmanDecode` (line 320)
- `encodeHeaderField` (line 353)
- `encodeHeaderList` (line 381)
- `decodeInteger` (line 391)
- `decodeString` (line 413)
- `getHeaderFromTable` (line 440)
- `decodeHeaderField` (line 451)
- `decodeHeaderList` (line 541)
- `encodeHeadersPublic` (line 557)

**Docstrings:** 2

---

## LeanServer.Protocol.HTTP2

**Lines:** 1406

**Imports:**
```lean
import LeanServer.Core.Basic
import LeanServer.Crypto.Crypto
import LeanServer.Protocol.HPACK
```

### Structures

- `structure FrameHeader where` (line 83)
- `structure HTTP2Frame where` (line 91)
- `structure HTTP2Setting where` (line 158)
- `structure HTTP2Stream where` (line 178)
- `structure HTTP2Connection where` (line 185)
- `structure HttpRequest where` (line 671)
- `structure HttpResponse where` (line 688)
- `structure PushResource where` (line 1019)
- `structure HTTP2ConnectionWithPush where` (line 1028)
- `structure Priority where` (line 1117)
- `structure HTTP2StreamWithPriority where` (line 1171)
- `structure PriorityQueue where` (line 1177)
- `structure EnhancedFlowControl where` (line 1206)
- `structure ConnectionHealth where` (line 1253)
- `structure HTTP2ConnectionWithHealth where` (line 1263)
- `structure HTTP2Request where` (line 1300)
- `structure HTTP2Response where` (line 1317)
- `structure HTTP2Server where` (line 1332)
- `structure QUICStream where` (line 1378)
- `structure HTTP3Frame where` (line 1393)

### Inductive Types

- `inductive FrameType where` (line 27)
- `inductive ErrorCode where` (line 96)
- `inductive SettingId where` (line 130)
- `inductive StreamState where` (line 167)
- `inductive FlowControlError where` (line 494)
- `inductive PushState where` (line 1011)
- `inductive FlowControlPolicy where` (line 1199)
- `inductive QUICPacketType where` (line 1369)
- `inductive HTTP3FrameType where` (line 1385)

### Functions

- `h2DefaultHeaderTableSize` (line 15)
- `h2DefaultInitialWindowSize` (line 18)
- `h2DefaultMaxFrameSize` (line 21)
- `h2MaxWindowSize` (line 24)
- `FrameType.toByte` (line 54)
- `FrameType.fromByte` (line 68)
- `ErrorCode.toUInt32` (line 113)
- `SettingId.toUInt16` (line 139)
- `SettingId.fromUInt16` (line 147)
- `defaultHTTP2Settings` (line 196)
- `initHTTP2Connection` (line 206)
- `parseFrameHeader` (line 217)
- `serializeFrameHeader` (line 239)
- `parseHTTP2Frame` (line 255)
- `createHTTP2Frame` (line 267)
- `serializeHTTP2Frame` (line 277)
- `parseHTTP2Frames` (line 281)
- `parseSettingsPayload` (line 299)
- `serializeSettingsPayload` (line 314)
- `createSettingsFrame` (line 333)
- `createSettingsAckFrame` (line 339)
- `parseWindowUpdatePayload` (line 345)
- `serializeWindowUpdatePayload` (line 354)
- `createWindowUpdateFrame` (line 364)
- `updateConnectionWindow` (line 371)
- `updateStreamWindow` (line 377)
- `canSendDataOnConnection` (line 383)
- `canSendDataOnStream` (line 387)
- `consumeConnectionWindow` (line 391)
- `consumeStreamWindow` (line 396)
- `findStream` (line 401)
- `updateStream` (line 405)
- `removeStream` (line 412)
- `processConnectionWindowUpdate` (line 416)
- `processStreamWindowUpdate` (line 420)
- `processWindowUpdateFrame` (line 446)
- `canSendData` (line 466)
- `consumeWindows` (line 474)
- `createConnectionWindowUpdate` (line 484)
- `createStreamWindowUpdate` (line 488)

**Docstrings:** 11

---

## LeanServer.Protocol.HTTP3

**Lines:** 418

**Imports:**
```lean
import LeanServer.Core.Basic
import LeanServer.Crypto.Crypto
import LeanServer.Protocol.HPACK
import LeanServer.Protocol.QUIC
```

### Structures

- `structure HTTP3Settings` (line 17)
- `structure H3Frame` (line 78)
- `structure H3Stream` (line 97)
- `structure H3Connection` (line 117)
- `structure H3ServerState` (line 145)

### Inductive Types

- `inductive H3FrameType : Type` (line 38)
- `inductive H3StreamState : Type` (line 86)

### Functions

- `H3FrameType.toUInt64` (line 53)
- `H3FrameType.fromUInt64` (line 65)
- `encodeH3Frame` (line 164)
- `decodeH3Frame` (line 170)
- `initH3Server` (line 184)
- `createH3Connection` (line 192)
- `addH3Connection` (line 205)
- `removeH3Connection` (line 213)
- `findH3Connection` (line 217)
- `updateH3Connection` (line 221)
- `createH3Stream` (line 227)
- `addH3Stream` (line 236)
- `findH3Stream` (line 240)
- `updateH3Stream` (line 244)
- `addH3StreamToConnection` (line 250)
- `createH3DataFrame` (line 254)
- `createH3HeadersFrame` (line 260)
- `createH3SettingsFrame` (line 277)
- `createH3GoAwayFrame` (line 288)
- `parseH3Frame` (line 294)
- `processH3FrameForConnection` (line 303)
- `processH3Frame` (line 355)
- `findH3ConnectionByQUIC` (line 377)
- `parseH3FramesFromStream` (line 381)
- `sendH3FrameOverQUIC` (line 394)
- `processH3StreamData` (line 403)
- `getH3ServerStats` (line 413)

./scripts/gen_api_docs.sh: line 153: [: 0
0: integer expected
---

## LeanServer.Protocol.QUIC

**Lines:** 943

**Imports:**
```lean
import LeanServer.Core.Basic
import LeanServer.Crypto.Crypto
```

### Structures

- `structure QUICConnectionID` (line 37)
- `structure QUICVersion` (line 52)
- `structure QUICPacketNumber` (line 67)
- `structure QUICFrame` (line 177)
- `structure QUICPacketHeader` (line 191)
- `structure QUICPacket` (line 213)
- `structure SentPacketEntry` (line 256)
- `structure FlowControlState` (line 265)
- `structure CongestionState` (line 278)
- `structure QUICStreamState` (line 304)
- `structure QUICConnection` (line 317)
- `structure QUICServerState` (line 436)

### Inductive Types

- `inductive QUICPacketType_ : Type` (line 13)
- `inductive QUICFrameType : Type` (line 75)
- `inductive QUICConnectionState : Type` (line 229)
- `inductive QUICStreamStatus` (line 296)

### Functions

- `QUICPacketType_.toByte` (line 25)
- `QUICConnectionID.length` (line 45)
- `QUIC_VERSION_1` (line 57)
- `QUICVersion.isSupported` (line 60)
- `QUICFrameType.toByte` (line 128)
- `QUICFrameType.fromByte` (line 152)
- `initQUICServer` (line 453)
- `createQUICConnection` (line 460)
- `addQUICConnection` (line 475)
- `findQUICConnection` (line 482)
- `updateQUICConnection` (line 486)
- `encodeVarInt` (line 496)
- `encodeQUICVarInt` (line 521)
- `createQUICPingFrame` (line 524)
- `createQUICPaddingFrame` (line 530)
- `createQUICCryptoFrame` (line 536)
- `createQUICStreamFrame` (line 542)
- `encodeAckRanges` (line 548)
- `createQUICAckFrame` (line 568)
- `createQUICConnectionCloseFrame` (line 574)
- `createQUICMaxDataFrame` (line 580)
- `decodeVarInt` (line 590)
- `encodeQUICCryptoFrame` (line 632)
- `decodeQUICCryptoFrame` (line 639)
- `encodeQUICStreamFrame` (line 652)
- `decodeQUICStreamFrame` (line 661)
- `parseQUICFrame` (line 682)
- `createQUICPacket` (line 695)
- `createQUICInitialPacket` (line 716)
- `createQUICHandshakePacket` (line 740)
- `processQUICInitialPacket` (line 766)
- `processQUICHandshakePacket` (line 788)
- `processQUICOneRTTPacket` (line 813)
- `processQUICPacket` (line 853)
- `generateQUICConnectionID` (line 865)
- `isValidQUICConnectionID` (line 870)
- `QUICConnectionState.toString` (line 874)
- `QUICPacketType_.toString` (line 883)
- `cleanupQUICConnections` (line 896)
- `getQUICServerStats` (line 901)

**Docstrings:** 5

---

## LeanServer.Protocol.QUICRetry

```
/-!
# QUIC Retry Token Validation (R16)

Implements QUIC Retry packet generation and token validation per RFC 9000 §8.1.

## Address Validation via Retry
When a server receives an Initial packet from an unvalidated address, it MAY
send a Retry packet containing a token. The client must re-send its Initial
with that token, proving it controls the source address.

## Token Format (opaque to the client)
```
[4 bytes: timestamp (seconds since epoch)]
[16 bytes: client IP hash (HMAC-SHA256 truncated)]
[8 bytes: original DCID length + data]
[32 bytes: HMAC-SHA256 integrity tag over the above]
```

## Retry Integrity Tag
RFC 9001 §5.8: The Retry packet uses a fixed key and nonce for AEAD
```

**Lines:** 205

**Imports:**
```lean
import LeanServer.Protocol.QUIC
import LeanServer.Crypto.Crypto
```

### Inductive Types

- `inductive RetryTokenResult` (line 87)

### Functions

- `retryTokenLifetimeSec` (line 40)
- `generateRetryToken` (line 75)
- `validateRetryToken` (line 104)
- `buildRetryPseudoPacket` (line 155)
- `createRetryPacket` (line 162)
- `shouldSendRetry` (line 194)

**Docstrings:** 14

---

## LeanServer.Protocol.WSCompression

```
/-!
# WebSocket Per-Message Compression (R17)

Implements the permessage-deflate extension per RFC 7692.

## Overview
The permessage-deflate extension compresses WebSocket message payloads using
the DEFLATE algorithm (RFC 1951). This module provides:
- Extension negotiation (parsing `Sec-WebSocket-Extensions` header)
- Pure Lean DEFLATE compression/decompression (simplified LZ77 + fixed Huffman)
- Integration with the existing `WebSocketFrame` type (via `rsv1` flag)

## Compression Parameters (RFC 7692 §7)
- `server_no_context_takeover` — reset compressor state between messages
- `client_no_context_takeover` — reset decompressor state between messages
- `server_max_window_bits` — server's LZ77 window size (8-15, default 15)
- `client_max_window_bits` — client's LZ77 window size (8-15, default 15)

## Limitations
- This is a simplified implementation using fixed Huffman codes only
```

**Lines:** 250

**Imports:**
```lean
import LeanServer.Protocol.WebSocket
```

### Structures

- `structure DeflateConfig` (line 33)
- `structure WSCompressionState` (line 166)
- `structure WSCompressionStats` (line 238)

### Inductive Types

- `inductive DeflateBlockType` (line 88)

### Functions

- `parseDeflateOffer` (line 42)
- `buildDeflateResponse` (line 75)
- `deflateStored` (line 97)
- `inflateStored` (line 126)
- `WSCompressionState.create` (line 176)
- `compressWSMessage` (line 181)
- `decompressWSMessage` (line 212)
- `negotiateWSCompression` (line 229)
- `WSCompressionState.stats` (line 245)

**Docstrings:** 13

---

## LeanServer.Protocol.WebSocket

**Lines:** 502

**Imports:**
```lean
import LeanServer.Protocol.HTTP2
import LeanServer.Crypto.Crypto
```

### Structures

- `structure WebSocketFrame` (line 23)
- `structure WebSocketConnection` (line 61)

### Inductive Types

- `inductive WebSocketFrameType` (line 13)
- `inductive WebSocketState` (line 35)
- `inductive WebSocketCloseCode : UInt16 → Type` (line 43)
- `inductive WebSocketMessage` (line 73)

### Functions

- `initWebSocketConnection` (line 82)
- `sha1` (line 98)
- `base64Chars` (line 174)
- `base64Encode` (line 176)
- `generateWebSocketAcceptKey` (line 207)
- `createWebSocketHandshakeResponse` (line 218)
- `unmaskPayload` (line 240)
- `isControlFrame` (line 256)
- `parseWebSocketFrame` (line 262)
- `createWebSocketFrame` (line 343)
- `serializeWebSocketFrame` (line 356)
- `createTextMessage` (line 403)
- `createBinaryMessage` (line 407)
- `createPingFrame` (line 411)
- `createPongFrame` (line 415)
- `createCloseFrame` (line 419)
- `processWebSocketFrame` (line 427)
- `isValidWebSocketUpgrade` (line 491)

./scripts/gen_api_docs.sh: line 153: [: 0
0: integer expected
---

## LeanServer.Protocol.WebSocketOverHTTP2

**Lines:** 104

**Imports:**
```lean
import LeanServer.Protocol.HTTP2
import LeanServer.Protocol.WebSocket
```

### Structures

- `structure HTTP2ConnectionWithWebSocket` (line 10)

### Functions

- `initHTTP2ConnectionWithWebSocket` (line 16)
- `isWebSocketUpgradeRequest` (line 23)
- `createErrorResponse` (line 27)
- `processWebSocketUpgrade` (line 35)
- `processWebSocketData` (line 47)
- `sendWebSocketMessage` (line 74)
- `getWebSocketConnectionState` (line 92)

./scripts/gen_api_docs.sh: line 153: [: 0
0: integer expected
---

## LeanServer.Server.Benchmark

**Lines:** 350

**Imports:**
```lean
import LeanServer.Crypto.Crypto
import LeanServer.Crypto.AES
import LeanServer.Crypto.X25519
import LeanServer.Server.HTTPServer
import LeanServer.Protocol.HPACK
import LeanServer.Protocol.HTTP2
```

### Structures

- `structure BenchmarkResult` (line 39)
- `structure BenchmarkSuite` (line 80)

### Functions

- `runBenchmark` (line 52)
- `runPureBenchmark` (line 66)
- `benchSHA256` (line 127)
- `benchHMACSHA256` (line 132)
- `benchAESKeyExpansion` (line 137)
- `benchAESEncryptBlock` (line 142)
- `benchAESGCMSmall` (line 149)
- `benchAESGCMMedium` (line 154)
- `benchAESGCMLarge` (line 159)
- `benchX25519` (line 164)
- `benchHKDFExtract` (line 175)
- `benchHKDFExpand` (line 182)
- `cryptoBenchmarks` (line 189)
- `benchHPACKEncode` (line 232)
- `benchHPACKDecode` (line 237)
- `benchHPACKRoundtrip` (line 244)
- `hpackBenchmarks` (line 251)
- `benchHTTPParse` (line 281)
- `benchHTTP2FrameParse` (line 286)
- `httpBenchmarks` (line 292)
- `benchTLSKeySchedule` (line 305)
- `keyDerivBenchmarks` (line 316)
- `runAllBenchmarks` (line 325)

**Docstrings:** 34

---

## LeanServer.Server.Concurrency

```
/-!
  # Concurrency — Thread Pool via pthreads FFI
  Provides basic threading support for concurrent connection handling.

  ## Architecture
  The server uses a "thread-per-connection" model via `spawnThread`:
  1. Main thread calls `accept` in a loop
  2. Each accepted connection is dispatched to a new detached pthread
  3. The thread runs the connection handler and exits when done
  4. Active thread count is tracked atomically in C

  ## Thread Safety
  - Each thread gets its own Lean runtime initialization
  - Shared state (PSK cache, rate limiter, etc.) uses `IO.Ref` with `Std.Mutex`
  - Thread count is tracked with a C-level mutex

  ## Key Functions
  - `spawnThread` — Spawn a detached thread running an IO action
  - `getActiveThreadCount` — Get number of active worker threads
  - `withThreadLimit` — Run action only if thread limit not reached
```

**Lines:** 84

### Structures

- `structure ThreadPoolStats` (line 74)

### Functions

- `maxConcurrentConnections` (line 55)
- `spawnConnectionThread` (line 59)
- `getThreadPoolStats` (line 80)

**Docstrings:** 8

---

## LeanServer.Server.ConfigReload

```
/-!
# Hot-Reload Configuration (R18)

Supports reloading `server.config` at runtime without restarting the server.
Uses a polling-based approach (no SIGHUP needed — works cross-platform).

## Mechanism
1. A background task polls the config file's modification time every N seconds
2. If the file has changed, it is re-parsed and a `ConfigUpdate` is emitted
3. Safely-mutable settings (log level, rate limits, timeouts) are applied live
4. Immutable settings (port, TLS) are logged as warnings (require restart)

## Thread Safety
Config updates are applied through an `IO.Ref` holding the current config,
so all reader threads see a consistent snapshot.
-/
```

**Lines:** 193

**Imports:**
```lean
import LeanServer.Server.HTTPServer
```

### Structures

- `structure MutableConfig` (line 27)
- `structure ConfigDiff` (line 44)
- `structure ConfigReloadState` (line 68)
- `structure ConfigReloadStats` (line 182)

### Functions

- `MutableConfig.fromServerConfig` (line 36)
- `diffMutableConfig` (line 49)
- `getLiveConfig` (line 81)
- `setLiveConfig` (line 85)
- `checkConfigModified` (line 90)
- `reloadConfig` (line 104)
- `startConfigWatcher` (line 142)
- `forceConfigReload` (line 169)
- `getConfigReloadStats` (line 189)

**Docstrings:** 14

---

## LeanServer.Server.GracefulShutdown

```
/-!
# Graceful Shutdown Module (R19)

Provides a structured graceful shutdown sequence that integrates with
`Concurrency.lean` (thread tracking) and `Timeout.lean` (connection sweeping).

## Shutdown Phases
1. **Signal received** → stop accepting new connections
2. **Drain** → finish in-flight requests (configurable timeout)
3. **Force close** → terminate remaining connections
4. **Cleanup** → release resources, flush logs

## Integration
The main server loop in `HTTPServer.lean` already handles SIGINT/SIGTERM via FFI.
This module adds a reusable `ShutdownCoordinator` that can be shared across
the TCP accept loop and QUIC UDP loop.
-/
```

**Lines:** 182

**Imports:**
```lean
import LeanServer.Server.HTTPServer
import LeanServer.Server.Concurrency
import LeanServer.Server.Timeout
```

### Structures

- `structure ShutdownConfig` (line 41)
- `structure ShutdownState` (line 55)
- `structure ShutdownCoordinator` (line 63)
- `structure ShutdownSummary` (line 164)

### Inductive Types

- `inductive ShutdownPhase` (line 26)

### Functions

- `ShutdownCoordinator.create` (line 78)
- `ShutdownCoordinator.isDraining` (line 83)
- `ShutdownCoordinator.beginDrain` (line 88)
- `ShutdownCoordinator.updateConnectionCount` (line 97)
- `ShutdownCoordinator.poll` (line 103)
- `ShutdownCoordinator.runShutdown` (line 132)
- `ShutdownCoordinator.summary` (line 172)

**Docstrings:** 14

---

## LeanServer.Server.HTTPServer

**Lines:** 4951

**Imports:**
```lean
import LeanServer
import LeanServer.Protocol.HTTP2
import LeanServer.Protocol.WebSocketOverHTTP2
import LeanServer.Protocol.QUIC
import LeanServer.Protocol.HTTP3
import LeanServer.Protocol.GRPC
import Init.System.IO
import Lean
import Std.Sync.Mutex
import Std.Data.HashMap
```

### Structures

- `structure HTTPServerState` (line 206)
- `structure ServerConfig` (line 217)
- `structure RateBucket` (line 366)
- `structure RateLimiterConfig` (line 372)
- `structure TCPPoolEntry` (line 428)
- `structure TCPConnectionPool` (line 435)
- `structure HTTPRequest` (line 512)
- `structure HTTPResponse` (line 547)
- `structure Middleware` (line 554)
- `structure TraceContext` (line 630)
- `structure H2Origin` (line 777)
- `structure H2StreamInfo` (line 806)
- `structure H2ConnectionState` (line 891)

### Inductive Types

- `inductive ServerLogLevel` (line 76)

### Functions

- `tlsContentHandshake` (line 23)
- `tlsContentAppData` (line 26)
- `tlsContentAlert` (line 29)
- `tlsContentCCS` (line 32)
- `defaultServerPort` (line 35)
- `maxRequestBodySize` (line 38)
- `quicMSS` (line 41)
- `quicInitialCwnd` (line 44)
- `quicIdleTimeoutMs` (line 47)
- `quicDrainMultiplier` (line 50)
- `udpRecvBufSize` (line 53)
- `udpSocketTimeoutMs` (line 56)
- `rateLimiterStaleTTL` (line 59)
- `ticketKeyRotationMs` (line 62)
- `pskLifetimeMs` (line 65)
- `flushStdout` (line 68)
- `parseServerLogLevel` (line 92)
- `wsInit` (line 98)
- `wsCleanup` (line 100)
- `monoTimeMs` (line 159)
- `isValidHttpRequest` (line 174)
- `isHttp2Preface` (line 186)
- `sendHttp2Preface` (line 193)
- `sendErrorResponse` (line 200)
- `parseConfigFile` (line 231)
- `loadServerConfig` (line 262)
- `getServerSecret` (line 281)
- `getServerConfig` (line 291)
- `serverLog` (line 295)
- `checkAntiReplay` (line 313)
- `getTicketKeyManager` (line 335)
- `maybeRotateTicketKey` (line 352)
- `checkRateLimit` (line 380)
- `incrementConnections` (line 415)
- `decrementConnections` (line 419)
- `poolAdmit` (line 444)
- `poolRelease` (line 456)
- `getPoolStats` (line 461)
- `initHTTPServer` (line 466)
- `handleH3Request` (line 481)

**Docstrings:** 110

---

## LeanServer.Server.HTTPServer.ConnectionPool

```
/-!
  # Connection Pool — Re-export Module
  TCP connection pool for connection reuse and management.

  ## Key Types
  - `TCPPoolEntry` — Individual pool entry
  - `TCPConnectionPool` — Pool state

  ## Key Functions
  - `poolAdmit` — Add a connection to the pool
  - `poolRelease` — Release a connection from the pool
  - `getPoolStats` — Get pool statistics (total, active, idle)
  - `incrementConnections` / `decrementConnections` — Connection counter
-/
```

**Lines:** 40

**Imports:**
```lean
import LeanServer.Server.HTTPServer
```

**Docstrings:** 5

---

## LeanServer.Server.HTTPServer.H2Handler

**Lines:** 25

**Imports:**
```lean
import LeanServer.Server.HTTPServer
```

### Functions

- `available` (line 23)

**Docstrings:** 1

---

## LeanServer.Server.HTTPServer.QPACK

```
/-!
  # QPACK Encoder/Decoder — Re-export Module
  HTTP/3 QPACK header compression (RFC 9204).

  ## Key Functions
  - `encodeQPACKResponseHeaders` — Encode response headers with QPACK
  - `encodeQPACKSimple` — Simple QPACK encoding for common responses
  - `qpackDynamicTableLookup` — Dynamic table lookup
  - `qpackDynamicTableInsert` — Insert into dynamic table
  - `encodeQPACKEncoderInsertStaticRef` — Encoder stream: insert with static ref
  - `encodeQPACKEncoderInsertLiteral` — Encoder stream: insert literal
  - `encodeQPACKSectionAck` — Section acknowledgment
-/
```

**Lines:** 38

**Imports:**
```lean
import LeanServer.Server.HTTPServer
```

**Docstrings:** 4

---

## LeanServer.Server.HTTPServer.QUICHandler

**Lines:** 27

**Imports:**
```lean
import LeanServer.Server.HTTPServer
```

### Functions

- `available` (line 25)

**Docstrings:** 1

---

## LeanServer.Server.HTTPServer.RateLimiter

```
/-!
  # Rate Limiter — Re-export Module
  Token bucket rate limiting per IP address.

  ## Key Types
  - `RateBucket` — Per-IP token bucket state
  - `RateLimiterConfig` — Rate limiting configuration

  ## Key Functions
  - `checkRateLimit` — Check if request from IP is allowed
-/
```

**Lines:** 21

**Imports:**
```lean
import LeanServer.Server.HTTPServer
```

**Docstrings:** 1

---

## LeanServer.Server.HTTPServer.Router

```
/-!
  # HTTP Router — Re-export Module
  HTTP request routing, middleware, and static file serving.

  ## Key Types
  - `HTTPRequest` — Parsed HTTP request
  - `HTTPResponse` — HTTP response
  - `Middleware` — Request/Response middleware

  ## Key Functions
  - `routeRequest` — Route a request to a handler
  - `applyMiddleware` — Apply middleware chain
  - `serveStaticFile` — Serve static files from disk
  - `sendErrorResponse` — Send error response
  - `parseHTTPRequest` — Parse raw HTTP request

  ## Built-in Middleware
  - `corsMiddleware` — CORS headers
  - `securityHeadersMiddleware` — Security headers
  - `serverTimingMiddleware` — Server-Timing header
```

**Lines:** 49

**Imports:**
```lean
import LeanServer.Server.HTTPServer
```

**Docstrings:** 5

---

## LeanServer.Server.HTTPServer.ServerConfig

```
/-!
  # Server Configuration — Re-export Module
  Clean import path for server configuration, constants, and runtime state.

  ## Key Types
  - `ServerConfig` — Parsed server configuration
  - `ServerLogLevel` — Log level enum
  - `HTTPServerState` — Server runtime state

  ## Key Functions
  - `loadServerConfig` — Load config from file
  - `parseConfigFile` — Parse config content
  - `serverLog` — Log with level filtering
  - `getServerConfig` — Get current config
  - `getServerSecret` — Get runtime server secret
-/
```

**Lines:** 40

**Imports:**
```lean
import LeanServer.Server.HTTPServer
```

### Functions

- `contentHandshake` (line 35)
- `contentAppData` (line 36)
- `contentAlert` (line 37)
- `contentCCS` (line 38)

**Docstrings:** 4

---

## LeanServer.Server.HTTPServer.TLSHandler

**Lines:** 24

**Imports:**
```lean
import LeanServer.Server.HTTPServer
```

### Functions

- `available` (line 22)

**Docstrings:** 1

---

## LeanServer.Server.HTTPServer.Tracing

```
/-!
  # Distributed Tracing — Re-export Module
  W3C Trace Context propagation and request correlation.

  ## Key Types
  - `TraceContext` — W3C traceparent components

  ## Key Functions
  - `newTraceContext` — Create or propagate trace context
  - `findTraceparent` — Find traceparent header
  - `addTracingHeaders` — Add tracing headers to response
  - `generateHexId` — Generate hex identifier
  - `logRequest` — Log a completed request with timing
-/
```

**Lines:** 40

**Imports:**
```lean
import LeanServer.Server.HTTPServer
```

**Docstrings:** 5

---

## LeanServer.Server.LoadBalancer

**Lines:** 176

**Imports:**
```lean
import LeanServer.Core.Basic
import LeanServer.Protocol.HTTP2
```

### Structures

- `structure BackendServer` (line 10)
- `structure LoadBalancerState` (line 44)

### Inductive Types

- `inductive LoadBalancingAlgorithm` (line 30)

### Functions

- `createLoadBalancer` (line 59)
- `addBackend` (line 67)
- `getHealthyBackends` (line 72)
- `selectBackendRoundRobin` (line 76)
- `selectBackendLeastConnections` (line 87)
- `selectBackendIPHash` (line 100)
- `selectBackendWeightedRoundRobin` (line 125)
- `selectBackend` (line 160)
- `getLoadBalancerStats` (line 171)

./scripts/gen_api_docs.sh: line 153: [: 0
0: integer expected
---

## LeanServer.Server.Metrics

```
/-!
# Prometheus Metrics Exporter (R22)

Exposes server metrics in Prometheus exposition format (text/plain; version=0.0.4).

## Metrics Exported
- `leanserver_requests_total` — Counter: total HTTP requests by method/status
- `leanserver_connections_active` — Gauge: current active connections
- `leanserver_connections_total` — Counter: total connections accepted
- `leanserver_bytes_sent_total` — Counter: total bytes sent
- `leanserver_bytes_received_total` — Counter: total bytes received
- `leanserver_errors_total` — Counter: total errors by category
- `leanserver_threads_active` — Gauge: active worker threads
- `leanserver_threads_max` — Gauge: max concurrent threads allowed
- `leanserver_tls_handshakes_total` — Counter: TLS handshakes completed
- `leanserver_quic_connections_active` — Gauge: active QUIC connections
- `leanserver_uptime_seconds` — Gauge: server uptime
- `leanserver_build_info` — Info: version and build metadata

## Endpoint
```

**Lines:** 254

**Imports:**
```lean
import LeanServer.Server.HTTPServer
import LeanServer.Server.Concurrency
```

### Structures

- `structure MetricLabel` (line 50)
- `structure MetricSample` (line 56)
- `structure MetricFamily` (line 63)
- `structure MetricsState` (line 75)

### Inductive Types

- `inductive MetricType` (line 35)

### Functions

- `initMetrics` (line 103)
- `recordRequest` (line 108)
- `recordBytes` (line 119)
- `recordError` (line 126)
- `recordConnection` (line 134)
- `recordTLSHandshake` (line 143)
- `generatePrometheusMetrics` (line 180)
- `metricsHTTPResponse` (line 246)

**Docstrings:** 20

---

## LeanServer.Server.Production

**Lines:** 918

**Imports:**
```lean
import LeanServer
import LeanServer.Protocol.HTTP2
import LeanServer.Protocol.HTTP3
import LeanServer.Protocol.WebSocketOverHTTP2
```

### Structures

- `structure ServerConfig where` (line 30)
- `structure ConnectionPoolEntry where` (line 53)
- `structure ConnectionPool where` (line 66)
- `structure ConnectionPoolStats where` (line 83)
- `structure RateLimitEntry where` (line 102)
- `structure RateLimitConfig where` (line 117)
- `structure RateLimiter where` (line 132)
- `structure SessionData where` (line 147)
- `structure SessionEntry where` (line 154)
- `structure SessionConfig where` (line 171)
- `structure SessionManager where` (line 186)
- `structure LogEntry where` (line 506)
- `structure Logger where` (line 521)
- `structure ServerMetrics where` (line 534)
- `structure ProductionServerState where` (line 553)

### Inductive Types

- `inductive LogLevel` (line 12)

### Functions

- `createConnectionPool` (line 199)
- `getCurrentTimestamp` (line 208)
- `isConnectionExpired` (line 214)
- `borrowConnection` (line 218)
- `returnConnection` (line 256)
- `cleanupExpiredConnections` (line 277)
- `getPoolStats` (line 287)
- `checkRateLimit` (line 299)
- `cleanupRateLimiter` (line 358)
- `getRateLimiterStats` (line 371)
- `generateSessionId` (line 379)
- `createSession` (line 384)
- `getSession` (line 412)
- `updateSessionData` (line 443)
- `getSessionData` (line 468)
- `deleteSession` (line 480)
- `cleanupExpiredSessions` (line 489)
- `getSessionManagerStats` (line 499)
- `createLogger` (line 576)
- `shouldLog` (line 583)
- `formatLogEntry` (line 595)
- `logMessage` (line 604)
- `displayRecentLogs` (line 631)
- `initProductionServer` (line 670)
- `parseLogLevel` (line 674)
- `extractValue` (line 683)
- `parseConfigLine` (line 693)
- `parseBool` (line 703)
- `parseNat` (line 709)
- `loadConfigFromContent` (line 715)
- `loadConfigFromFile` (line 738)
- `initProductionServerFromFile` (line 751)
- `logServerEvent` (line 756)
- `updateMetrics` (line 761)
- `getMetricsResponse` (line 774)
- `handleHealthCheck` (line 802)
- `createSessionForServer` (line 816)
- `updateSessionDataForServer` (line 821)
- `getSessionDataForServer` (line 826)
- `cleanupExpiredSessionsForServer` (line 831)

**Docstrings:** 2

---

## LeanServer.Server.Timeout

```
/-!
  # Connection Timeout Management
  Handles connection lifecycle timeouts with proper resource cleanup.

  ## Features
  - Configurable timeouts per connection phase (handshake, request, keep-alive, idle)
  - Automatic resource cleanup on timeout
  - Integration with the concurrency model (thread-safe timeout tracking)
  - QUIC idle timeout (RFC 9000 §10.1)
  - HTTP/2 SETTINGS_TIMEOUT handling

  ## Timeout Phases
  1. **Handshake timeout** — Time allowed for TLS handshake completion (5s default)
  2. **Request timeout** — Time allowed to receive a complete HTTP request (30s default)
  3. **Keep-alive timeout** — Time between requests on a persistent connection (60s default)
  4. **Idle timeout** — Overall connection idle timeout (120s default)
  5. **QUIC idle timeout** — Per RFC 9000 §10.1 (30s default)
-/
```

**Lines:** 175

**Imports:**
```lean
import LeanServer.Server.HTTPServer
```

### Structures

- `structure TimeoutConfig` (line 42)
- `structure ConnectionTimeout` (line 55)

### Inductive Types

- `inductive ConnectionPhase` (line 25)
- `inductive TimeoutStatus` (line 101)

### Functions

- `defaultTimeoutConfig` (line 52)
- `ConnectionTimeout.create` (line 64)
- `ConnectionTimeout.setPhase` (line 68)
- `ConnectionTimeout.touch` (line 72)
- `ConnectionTimeout.currentTimeoutMs` (line 76)
- `ConnectionTimeout.isExpired` (line 85)
- `ConnectionTimeout.isIdle` (line 90)
- `ConnectionTimeout.remainingMs` (line 95)
- `ConnectionTimeout.check` (line 114)
- `registerTimeout` (line 127)
- `updateTimeout` (line 132)
- `unregisterTimeout` (line 139)
- `sweepExpiredConnections` (line 145)
- `cleanupTimedOutConnection` (line 154)
- `withTimeout` (line 164)

**Docstrings:** 20

---

## LeanServer.Web.SampleWebApp

**Lines:** 115

**Imports:**
```lean
import LeanServer.Web.WebApplicationSimple
```

### Structures

- `structure User` (line 10)

### Functions

- `userToJson` (line 18)
- `createUserTableHandler` (line 30)
- `getUsersHandler` (line 35)
- `getUserByIdHandler` (line 39)
- `createUserHandler` (line 46)
- `updateUserHandler` (line 52)
- `deleteUserHandler` (line 58)
- `healthCheckHandler` (line 64)
- `rootHandler` (line 68)
- `createSampleWebApp` (line 92)
- `main` (line 108)

./scripts/gen_api_docs.sh: line 153: [: 0
0: integer expected
---

## LeanServer.Web.WebAppTests

**Lines:** 148

**Imports:**
```lean
import LeanServer.Web.SampleWebApp
```

### Functions

- `stringContains` (line 9)
- `extractJsonField` (line 13)
- `testWebApplication` (line 27)
- `testResponseBuilders` (line 41)
- `testUserJsonConversion` (line 64)
- `testJsonFieldExtraction` (line 84)
- `testRouteHandling` (line 104)
- `main` (line 139)

**Docstrings:** 2

---

## LeanServer.Web.WebApplication

**Lines:** 290

**Imports:**
```lean
import LeanServer.Db.Database
import LeanServer.Db.PostgreSQL
import LeanServer.Db.MySQL
import LeanServer.Protocol.HTTP2
import LeanServer.Server.HTTPServer
```

### Structures

- `structure WebAppConfig` (line 14)
- `structure RequestContext` (line 22)
- `structure WebAppResponseBuilder` (line 29)
- `structure WebAppState` (line 39)

### Functions

- `initWebApp` (line 47)
- `addWebAppRoute` (line 72)
- `addWebAppMiddleware` (line 77)
- `createWebAppResponse` (line 81)
- `webAppJsonResponse` (line 93)
- `webAppHtmlResponse` (line 97)
- `webAppErrorResponse` (line 101)
- `webAppDatabaseMiddleware` (line 105)
- `webAppSessionMiddleware` (line 109)
- `processWebAppMiddleware` (line 119)
- `handleWebAppRequest` (line 133)
- `webAppResponseToHttpResponse` (line 159)
- `executePgQuery` (line 170)
- `executeMySqlQuery` (line 182)
- `queryResultToJson` (line 194)
- `startWebApp` (line 204)
- `get` (line 234)
- `post` (line 239)
- `put` (line 244)
- `delete` (line 249)
- `patch` (line 254)
- `use` (line 259)
- `WebAppResponseBuilder.withStatus` (line 264)
- `WebApp.jsonResponse` (line 268)
- `WebApp.htmlResponse` (line 272)
- `WebApp.errorResponse` (line 276)
- `defaultWebAppConfig` (line 280)
- `webApp` (line 286)

**Docstrings:** 13

---

## LeanServer.Web.WebApplicationSimple

**Lines:** 111

**Imports:**
```lean
import LeanServer.Db.Database
import LeanServer.Db.PostgreSQL
import LeanServer.Db.MySQL
import LeanServer.Protocol.HTTP2
import LeanServer.Server.HTTPServer
```

### Structures

- `structure ResponseBuilder` (line 14)
- `structure WebApplication` (line 24)

### Functions

- `initWebApplication` (line 28)
- `addRoute` (line 34)
- `createResponse` (line 38)
- `jsonResponse` (line 50)
- `htmlResponse` (line 54)
- `errorResponse` (line 58)
- `handleWebRequest` (line 62)
- `responseBuilderToHttpResponse` (line 74)
- `executeSelectQuery` (line 89)
- `executeMutation` (line 94)
- `startWebApplication` (line 101)

./scripts/gen_api_docs.sh: line 153: [: 0
0: integer expected
---

## Summary Statistics

./scripts/gen_api_docs.sh: line 184: 0
0: arithmetic syntax error in expression (error token is "0")
| Metric | Count |
|--------|-------|
| Modules | 50 |
| Total lines | 31 |
| Function definitions | 2 |
| Theorems | 0 |
| Structures | 0 |
| Docstrings | 0 |

> Generated on 2026-02-15 16:11:23 UTC
