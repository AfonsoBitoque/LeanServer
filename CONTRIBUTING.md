# Contributing to LeanServer6

Thank you for your interest in contributing to LeanServer6! This document provides
guidelines for contributing code, proofs, tests, and documentation.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Standards](#code-standards)
- [Writing Proofs](#writing-proofs)
- [Pull Request Process](#pull-request-process)
- [Project Structure](#project-structure)

---

## Getting Started

### Prerequisites

- **Lean 4** v4.27.0+ (install via [elan](https://github.com/leanprover/elan))
- **GCC** or **Clang** (for C FFI compilation)
- **OpenSSL** (optional, for TLS certificate generation and OpenSSL backend)

### Build

```bash
git clone https://github.com/lean-server/LeanServer6.git
cd LeanServer6
lake build
```

### Run Tests

```bash
lake build test && .lake/build/bin/test
```

### Generate Test Certificates

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

---

## Development Setup

### Recommended Editor

VS Code with the [Lean 4 extension](https://marketplace.visualstudio.com/items?itemName=leanprover.lean4).

### Verify Your Setup

```bash
lake build leanserver  # Should complete with 0 errors
```

---

## Code Standards

### Pure Lean First

**Our core principle: maximize pure Lean, minimize C FFI.**

- All protocol logic, crypto algorithms, parsers, and middleware MUST be in pure Lean
- C code is ONLY for POSIX syscalls that cannot be expressed in Lean (socket, epoll, etc.)
- If you add C code, justify why it cannot be done in Lean

### Naming Conventions

| Entity | Convention | Example |
|--------|-----------|---------|
| Types/structures | PascalCase | `HTTP2Frame`, `TLSState` |
| Functions | camelCase | `encodeHeaderField`, `parseHTTP2Frame` |
| Theorems | snake_case with descriptive names | `hpack_integer_roundtrip`, `aes_sbox_bijective` |
| Modules | PascalCase | `LeanServer.Protocol.HPACK` |
| Constants | camelCase | `defaultMaxFrameSize`, `initialWindowSize` |

### Documentation

- All public functions MUST have a docstring (`/-- ... -/`)
- Complex algorithms should reference the relevant RFC section
- Example: `/-- Encode an integer using HPACK integer representation (RFC 7541 §5.1) -/`

### No `sorry`

The project maintains **zero `sorry`** in production code. CI will reject any PR
that introduces `sorry`.

### Minimal `partial def`

- `partial def` is only acceptable for genuinely infinite I/O loops
  (server accept loop, WebSocket message loop, etc.)
- Parsers and codec functions MUST be total (use fuel parameter if needed)
- Current limit: ≤ 4 `partial def` in the entire codebase

### `native_decide` Usage

- Acceptable for verifying large constant tables (AES S-Box, Huffman table)
- Prefer `simp`, `omega`, or structural induction for algorithmic properties
- Document WHY `native_decide` is necessary in a comment

---

## Writing Proofs

### Proof Categories

We organize proofs into these categories:

1. **Roundtrip proofs** — `encode(decode(x)) = x` for codecs
2. **State machine proofs** — impossible transitions, progress properties
3. **Invariant proofs** — protocol invariants (flow control, table sizes)
4. **Safety proofs** — bounds checking, non-negative values, termination
5. **Compositional proofs** — module interactions preserve properties

### Proof Style Guide

```lean
/-- HPACK integer encoding roundtrip: decode(encode(v)) = v for all valid inputs.
    Reference: RFC 7541 §5.1 -/
theorem hpack_integer_roundtrip (v : Nat) (prefix : Nat)
    (hv : v < 2^28) (hp : prefix > 0 ∧ prefix ≤ 8) :
  decodeInteger (encodeInteger v prefix 0x00) 0 prefix = some (v, _) := by
  -- Step 1: unfold the encoder
  simp [encodeInteger]
  -- Step 2: case split on whether v fits in prefix bits
  ...
```

### Proof Naming Convention

```
<module>_<property>_<qualifier>
```

Examples:
- `hpack_integer_roundtrip`
- `aes_sbox_bijective`
- `tls_no_skip_handshake`
- `h2_flow_control_nonneg`

### Where to Put Proofs

- Module-specific proofs go in the module file (e.g., HPACK proofs in `HPACK.lean`)
- Cross-module or aggregate proofs go in `LeanServer/Proofs.lean`
- Specification-layer proofs go in `LeanServer/Spec/` (when created)

---

## Pull Request Process

### Before Submitting

1. **Build passes:** `lake build` with 0 errors
2. **No `sorry`:** `grep -r "sorry" LeanServer/` returns empty
3. **No new `axiom`:** `grep -r "axiom" LeanServer/ --include="*.lean"` returns empty
4. **Tests pass:** All existing tests still pass
5. **Proofs complete:** Any new functions in critical paths have associated proofs

### PR Description Template

```markdown
## What

Brief description of the change.

## Why

Motivation — which roadmap item (F0.1, F2.3, etc.) does this address?

## Proofs

- [ ] New proofs added (list them)
- [ ] Existing proofs still pass
- [ ] `sorry` count: 0
- [ ] `partial def` count: ≤ 4

## Testing

- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing done (describe)
```

### Review Criteria

- Does the code follow pure Lean principles?
- Are proofs meaningful (not just `native_decide` on specific values)?
- Is the C FFI surface minimized?
- Are RFCs referenced where applicable?
- Is the change documented?

---

## Project Structure

```
LeanServer6/
├── LeanServer/           # Main library
│   ├── Protocol/         # Protocol implementations (HPACK, GRPC, WebSocket)
│   ├── Server/           # Server components (HTTPServer, middleware, framework)
│   ├── Core/             # Core utilities (BufferPool, basic types)
│   ├── Crypto.lean       # TLS 1.3, SHA-256, HMAC, HKDF
│   ├── AES.lean          # AES-128-GCM
│   ├── X25519.lean       # Curve25519 key exchange
│   ├── RSA.lean          # RSA-PSS signatures
│   ├── HPACK.lean        # HTTP/2 header compression
│   ├── Proofs.lean       # Cross-module formal proofs
│   └── ...
├── src/                  # C FFI (MUST stay minimal)
│   ├── Network.c         # POSIX syscall wrappers
│   └── crypto_ffi.c      # Optional OpenSSL backend
├── tests/                # Test files
├── docs/                 # Documentation
├── THREAT_MODEL.md       # Security assumptions
├── SECURITY.md           # Vulnerability reporting
├── ROADMAP_FINAL.md      # Development roadmap
└── CONTRIBUTING.md       # This file
```

---

## Questions?

Open a GitHub issue with the `question` label, or check existing documentation
in the `docs/` directory.

Thank you for helping make LeanServer6 better! 🚀
