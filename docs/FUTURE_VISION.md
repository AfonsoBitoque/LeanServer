# Future Vision

Design notes for planned features beyond the current implementation.

---

## F8.2 — io_uring (Linux 5.10+)

### Motivation
The current server uses `epoll` for I/O multiplexing. Each `send`/`recv` is a
separate syscall. `io_uring` allows **batching multiple I/O operations into a
single syscall**, reducing context-switch overhead by 2–4× at high connection
counts (>10K concurrent).

### Planned Architecture

```
┌─────────────────────────────────────┐
│          Lean IO Layer              │
│  sendBatch : List (Fd × ByteArray) │
│  recvBatch : List Fd → IO Results  │
├─────────────────────────────────────┤
│        io_uring FFI (3 calls)       │
│  io_uring_setup(entries, params)    │
│  io_uring_enter(fd, to_submit, ...) │
│  io_uring_register(fd, opcode, ...) │
├─────────────────────────────────────┤
│       Linux Kernel (5.10+)          │
│  Submission Queue → Completion Queue│
└─────────────────────────────────────┘
```

### FFI Surface (Minimal)
Only 3 C functions needed:

```c
// io_uring_ffi.c (~80 LOC estimated)
LEAN_EXPORT lean_obj_res lean_io_uring_setup(uint32_t entries, lean_obj_arg w);
LEAN_EXPORT lean_obj_res lean_io_uring_submit(uint64_t ring, lean_obj_arg ops, lean_obj_arg w);
LEAN_EXPORT lean_obj_res lean_io_uring_wait(uint64_t ring, uint32_t min_complete, lean_obj_arg w);
```

### Lean-Side Types

```lean
structure IoUringOp where
  fd     : UInt64
  opcode : UInt8    -- 0=READ, 1=WRITE, 2=ACCEPT
  buf    : ByteArray
  offset : UInt64

structure IoUringResult where
  fd     : UInt64
  result : Int32    -- bytes transferred or error
```

### Performance Targets
- ≥50K req/s (vs ~20K with epoll) at 10K concurrent connections
- ≤2 syscalls per batch of 64 operations (vs 64 with epoll)

### Prerequisites
- Linux 5.10+ (Ubuntu 22.04+, RHEL 9+)
- liburing-dev for compilation
- Graceful fallback to epoll on older kernels

---

## F8.3 — WebAssembly Target ✅

### Status: Implemented
The WASM project is available at:
https://github.com/AfonsoBitoque/LeanServerWASM

### What was built
- **WasmAPI.lean** — `@[export]` wrappers for 18 pure functions (SHA-256,
  HMAC, HKDF, AES-128-GCM, X25519, HPACK, HTTP/2, TLS 1.3 key derivation)
- **wasm_glue.c** — C bridge between Emscripten and Lean 4 runtime
- **lean_server_wasm.js** — High-level JavaScript API with typed methods
- **build_wasm.sh** — Automated Lean → C → WASM pipeline
- **dist/index.html** — Interactive demo page (SHA-256, AES-GCM, X25519 DH,
  TLS 1.3 key derivation, Huffman codec)

### Prerequisite: Pure Library ✅
The `LeanServerPure` library (43 modules, zero C dependencies) is now available.
This provides the pure-Lean subset needed for WASM compilation.
See `LeanServerPure.lean` and `lakefile.toml` for details.

### Motivation
Lean 4 compiles to C, which can be compiled to WebAssembly via Emscripten.
This would enable **verified TLS in the browser** — the first formally verified
JavaScript-interoperable TLS implementation.

### Approach

```
Lean 4 → C (lean --emit=c) → Emscripten → WASM
```

### Challenges
1. **No POSIX sockets in WASM** — need WebSocket/Fetch API bridges
2. **No filesystem** — in-memory key/cert storage
3. **Memory model** — Lean's GC must work within WASM linear memory
4. **Code size** — full server is ~2MB C; need tree-shaking for browser

### Viable Subset for WASM
- Pure crypto: SHA-256, AES-GCM, X25519, HKDF ✅ (no FFI needed)
- TLS 1.3 handshake ✅ (pure Lean)
- HPACK encoder/decoder ✅ (pure Lean)
- HTTP/2 frame parser ✅ (pure Lean)

### Use Cases
- In-browser TLS verification tool
- Verified HPACK encoder for HTTP/2 testing
- Client-side crypto library with formal guarantees

---

## F8.4 — Formal RFC Specification

### Motivation
RFC documents are written in English prose, which is inherently ambiguous.
Our Lean types already encode protocol semantics precisely. We can extract
a **machine-checked specification** that maps 1:1 to RFC sections.

### Current Coverage

| RFC | Coverage | Lean Module |
|-----|----------|-------------|
| RFC 8446 (TLS 1.3) | §4 State Machine, §7 Key Schedule | `Spec/TLSSpec.lean`, `Crypto/Crypto.lean` |
| RFC 7541 (HPACK) | §5-§7 Encoding/Decoding | `Protocol/HPACK.lean` |
| RFC 7540 (HTTP/2) | §4-§6 Frames, Streams, Flow Control | `Protocol/HTTP2.lean` |
| RFC 9000 (QUIC) | §12-§17 Packets, Loss, Congestion | `Protocol/QUIC.lean` |
| RFC 6455 (WebSocket) | §5 Framing | `Protocol/WebSocket.lean` |

### Approach
Each `structure`/`inductive` type = a protocol definition.
Each `theorem` = a verified property.

Example mapping:

```
RFC 8446 §4.1.3 "Server Hello"
  → inductive TLSHandshakeType | serverHello
  → structure ServerHello (version, cipherSuite, extensions)
  → theorem serverHello_version_valid: ...

RFC 9000 §10.3 "Connection Migration"
  → inductive MigrationStatus | notStarted | validating | validated | failed
  → def initiatePathValidation: ...
  → theorem migration_requires_validation: ...
```

### Long-Term Vision
Submit to IETF as an Internet-Draft companion document:
"Machine-Checked Specification of TLS 1.3 in Lean 4"

This would be the first formally verified companion to an RFC,
providing unambiguous reference for implementors.
