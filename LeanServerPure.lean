-- LeanServerPure — Pure Lean Library (Zero C Dependencies)
--
-- This root module exports the pure-Lean subset of LeanServer suitable for:
--   • Importing as a Lake dependency in other projects
--   • Compiling to WebAssembly (F8.3)
--   • Using verified crypto, protocols, and proofs without any C/FFI toolchain
--
-- Zero @[extern] functions are *called* at compile time. The only `@[extern]`
-- in this subset is `secureZero` in SideChannel.lean (opaque, IO-only, never
-- evaluated during elaboration). All proofs and pure functions work without
-- linking any C code.
--
-- What's included:
--   Core      : Types, encoding, logging, parsers, error handling (8 modules)
--   Crypto    : SHA-256, AES-128/256-GCM, X25519, RSA, TLS 1.3, HMAC, HKDF,
--               certificates, mTLS, nonce management, side-channel model (13 modules)
--   Protocol  : HTTP/2, HTTP/3, HPACK, QUIC, WebSocket, gRPC, WSCompression (9 modules)
--   Proofs    : 169 concrete test-vector theorems (1 module)
--   Spec      : Formal specifications, refinement proofs, invariants (11 modules)
--   Server    : Pure concurrency primitives (1 module)
--
-- What's NOT included (requires C FFI or system IO):
--   Crypto/FFI.lean        — OpenSSL FFI bindings (optional performance backend)
--   Db/*                   — Database drivers (MySQL, PostgreSQL, SQLite FFI)
--   Server/HTTPServer*     — Full HTTPS server (epoll, sockets, networking)
--   Server/LoadBalancer    — Load balancer (socket FFI)
--   Server/Production,Metrics,etc. — Server middleware (depends on HTTPServer)
--   Web/*                  — Web applications (depends on HTTPServer)
--
-- Usage from another project:
--   In your lakefile.toml:
--     [[require]]
--     name = "LeanServer"
--     git = "https://github.com/AfonsoBitoque/LeanServer"
--     rev = "main"
--
--   In your .lean files:
--     import LeanServerPure              -- import everything
--     import LeanServer.Crypto.AES       -- or individual modules
--     import LeanServer.Protocol.HTTP2

-- ── Core ──────────────────────────────────────────────────
import LeanServer.Core.Basic
import LeanServer.Core.Base64
import LeanServer.Core.BufferPool
import LeanServer.Core.ByteSlice
import LeanServer.Core.Logger
import LeanServer.Core.ParserCombinators
import LeanServer.Core.SafeAccess
import LeanServer.Core.ServerError

-- ── Crypto (pure — no FFI.lean) ───────────────────────────
import LeanServer.Crypto.AES
import LeanServer.Crypto.CertificateManager
import LeanServer.Crypto.Crypto
import LeanServer.Crypto.MTLSAuth
import LeanServer.Crypto.NonceManager
import LeanServer.Crypto.RSA
import LeanServer.Crypto.SHA256
import LeanServer.Crypto.SideChannel
import LeanServer.Crypto.TLSHandshake
import LeanServer.Crypto.TLSKeySchedule
import LeanServer.Crypto.TLSSession
import LeanServer.Crypto.X25519
import LeanServer.Crypto.X509Validation

-- ── Protocols (all pure) ──────────────────────────────────
import LeanServer.Protocol.GRPC
import LeanServer.Protocol.HPACK
import LeanServer.Protocol.HTTP2
import LeanServer.Protocol.HTTP3
import LeanServer.Protocol.QUIC
import LeanServer.Protocol.QUICRetry
import LeanServer.Protocol.WebSocket
import LeanServer.Protocol.WebSocketOverHTTP2
import LeanServer.Protocol.WSCompression

-- ── Server (pure subset) ──────────────────────────────────
import LeanServer.Server.Concurrency

-- ── Proofs ────────────────────────────────────────────────
import LeanServer.Proofs

-- ── Spec (Formal Verification) ────────────────────────────
import LeanServer.Spec.TLSSpec
import LeanServer.Spec.TLSModel
import LeanServer.Spec.TLSRefinement
import LeanServer.Spec.ServerStep
import LeanServer.Spec.UniversalCodecProofs
import LeanServer.Spec.TLSStateMachineProofs
import LeanServer.Spec.ProtocolInvariants
import LeanServer.Spec.CompositionProofs
import LeanServer.Spec.AdvancedProofs
import LeanServer.Spec.AdvancedProofs2
import LeanServer.Spec.AdvancedProofs3
