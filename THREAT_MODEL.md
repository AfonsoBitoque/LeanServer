# LeanServer6 — Threat Model & Verification Assumptions

> This document defines what LeanServer6's formal proofs guarantee, what they assume,
> and what attacks are explicitly out of scope. Following best practices from
> [seL4](https://sel4.systems/Verification/assumptions.html) and
> [HACL*](https://hacl-star.github.io/).

---

## What the Proofs Guarantee

LeanServer6's 174+ verified theorems (0 `sorry`, 0 `axiom`) provide the following guarantees:

### Codec Correctness
- **HPACK integer encoding/decoding** — roundtrip properties for header compression
- **Huffman encode/decode** — RFC 7541 Appendix B compliance
- **Base64 encode/decode** — RFC 4648 roundtrip correctness
- **HTTP/2 frame serialization** — frame headers serialize/parse correctly
- **QUIC VarInt encoding** — variable-length integer encoding is valid

### Cryptographic Properties
- **AES S-Box bijectivity** — SubBytes is invertible (no information loss)
- **ShiftRows/MixColumns invertibility** — AES round operations are reversible
- **HKDF output length** — derived key material has correct size
- **SHA-256 digest length** — output is always 32 bytes
- **X25519 scalar multiplication** — correct curve arithmetic

### Protocol Invariants
- **TLS state machine** — well-defined states, no undefined transitions
- **HTTP/2 flow control** — window sizes are non-negative after valid WINDOW_UPDATE
- **QUIC packet numbers** — monotonically increasing
- **Certificate chain** — validated chains are non-empty

### Parser Safety
- **Total functions** — parsers with fuel parameter are guaranteed to terminate
- **Bounds checking** — array accesses are within bounds (where proven)

---

## What the Proofs Do NOT Guarantee (Assumptions)

The following are **assumed correct** and are outside the verification boundary:

### 1. Lean 4 Compiler Correctness
The Lean 4 compiler translates Lean source to C code, which is then compiled by
GCC/Clang to machine code. **Neither translation step is formally verified.**
This is analogous to:
- CompCert assuming the assembler and linker are correct
- seL4 assuming the C compiler (which they later verified with CompCert)

**Impact:** A compiler bug could introduce behavior not present in the verified Lean source.

### 2. C Compiler Correctness (GCC/Clang)
The C FFI code (`src/Network.c`, `src/crypto_ffi.c`) is compiled by GCC/Clang.
These compilers are not formally verified (unlike CompCert).

**Impact:** Compiler optimizations could introduce undefined behavior or
miscompile the FFI layer.

### 3. C FFI Code Correctness
`Network.c` (~530 lines) contains syscall wrappers that are **outside the Lean
proof boundary**. These functions handle:
- Socket creation, binding, listening, accepting
- Data send/recv with retry logic
- epoll event loop primitives
- pthread creation and thread counting
- Signal handling (SIGINT/SIGTERM/SIGHUP)

**Impact:** Memory safety bugs in C code (buffer overflows, use-after-free) are
not detected by Lean's type system.

**Mitigation planned:** CBMC bounded model checking for all C functions (Roadmap F7.5).

### 4. Hardware Correctness
We assume:
- The CPU executes instructions as specified by its ISA
- Memory operates correctly (no bit flips without ECC)
- The random number generator provides cryptographically secure entropy

### 5. Operating System Correctness
We assume the Linux kernel:
- Implements POSIX syscalls correctly (socket, bind, listen, accept, recv, send, epoll)
- Provides correct process isolation
- Delivers signals reliably

### 6. Lean Runtime Correctness
We assume the Lean 4 runtime system:
- Manages reference counting correctly
- Implements `IO.asTask` (green threads) correctly
- Does not introduce data races in concurrent operations

---

## Attacks Explicitly OUT OF SCOPE

### Timing Side-Channel Attacks
Lean 4's garbage collector introduces non-deterministic pauses. Reference counting
operations depend on data structure sizes. **We cannot guarantee constant-time
execution at the instruction level.**

Our proofs verify absence of data-dependent branching at the Lean source level,
but this does NOT extend to the compiled binary.

**For production cryptography:** Use the OpenSSL FFI backend
(`-DLEANSERVER_USE_OPENSSL`), which provides constant-time guarantees at the
assembly level.

### Cache Side-Channel Attacks
AES table lookups in Lean create data-dependent memory access patterns that
could leak key material through cache timing.

**Mitigation:** Pure Lean crypto is intended for correctness verification,
not for environments where cache attacks are in the threat model.

### Physical Attacks
- Fault injection (voltage glitching, electromagnetic pulses)
- Cold boot attacks (reading DRAM after power loss)
- Hardware implants

These require physical access and are outside our scope.

### Supply Chain Attacks
- Compromised Lean toolchain (elan, lake, leanc)
- Compromised C toolchain (GCC, Clang, system libraries)
- Compromised dependencies in `lake-manifest.json`

### Denial of Service (Volumetric)
Network-level DDoS (SYN floods, UDP amplification) requires network-level
mitigation (firewalls, CDNs), not application-level defense.

The server does implement:
- Connection limits (`max_connections` in `server.config`)
- Per-IP rate limiting
- Graceful shutdown on SIGTERM

But these are best-effort, not formally verified.

### Protocol-Level DoS
- Slowloris attacks (slow HTTP headers)
- HTTP/2 SETTINGS flood
- HPACK bomb (oversized dynamic table)

These are partially mitigated by timeouts and limits but not formally proven to be safe.

---

## Verification Boundary Diagram

```
┌─────────────────────────────────────────────────────┐
│                  VERIFIED (Lean 4)                   │
│                                                     │
│  ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌─────────┐ │
│  │  HPACK   │ │   TLS    │ │  HTTP/2 │ │  Crypto │ │
│  │ encode/  │ │  state   │ │ frames  │ │ AES/SHA │ │
│  │ decode   │ │ machine  │ │ parse/  │ │ X25519  │ │
│  │ roundtrip│ │ proofs   │ │ serial  │ │ proofs  │ │
│  └─────────┘ └──────────┘ └─────────┘ └─────────┘ │
│                                                     │
├─────────────────────────────────────────────────────┤
│              UNVERIFIED BOUNDARY                    │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────────┐  ┌───────────┐  ┌──────────────┐ │
│  │  Network.c   │  │ Lean 4    │  │  GCC/Clang   │ │
│  │  (syscalls)  │  │ compiler  │  │  (C → binary)│ │
│  └──────────────┘  └───────────┘  └──────────────┘ │
│                                                     │
│  ┌──────────────┐  ┌───────────┐  ┌──────────────┐ │
│  │ Linux kernel │  │ Hardware  │  │  Lean runtime│ │
│  │ (POSIX)      │  │ (CPU/RAM) │  │  (GC, tasks) │ │
│  └──────────────┘  └───────────┘  └──────────────┘ │
│                                                     │
│               ASSUMED CORRECT                       │
└─────────────────────────────────────────────────────┘
```

---

## Comparison with Reference Projects

| Assumption | seL4 | miTLS | HACL* | LeanServer6 |
|-----------|------|-------|-------|-------------|
| Compiler correctness | Verified (CompCert) | Verified (KaRaMeL→C) | Verified (Low*→C) | **Assumed** |
| Hardware correctness | Assumed | Assumed | Assumed | Assumed |
| OS correctness | N/A (is the OS) | Assumed | Assumed | Assumed |
| Side-channel freedom | Out of scope | Partial | **Verified** | Out of scope |
| Memory safety (C) | Verified | Verified | Verified | **Planned** (CBMC) |

---

## Responsible Disclosure

See [SECURITY.md](SECURITY.md) for vulnerability reporting procedures.
