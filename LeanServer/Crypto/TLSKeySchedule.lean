import LeanServer.Crypto.Crypto

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

namespace LeanServer.TLSKeySchedule

/-- Derive handshake keys with TLS labels -/
@[inline] def deriveHandshake (sharedSecret helloHash : ByteArray) : LeanServer.HandshakeKeys :=
  LeanServer.deriveHandshakeKeys sharedSecret helloHash

/-- Derive handshake keys with QUIC labels -/
@[inline] def deriveQUICHandshake (sharedSecret helloHash : ByteArray) : LeanServer.HandshakeKeys :=
  LeanServer.deriveQUICHandshakeKeys sharedSecret helloHash

/-- Derive application traffic keys -/
@[inline] def deriveApplication (handshakeSecret helloHash : ByteArray) : LeanServer.ApplicationKeys :=
  LeanServer.deriveApplicationKeys handshakeSecret helloHash

/-- Derive next-generation traffic secret (key update) -/
@[inline] def nextTrafficSecret (currentSecret : ByteArray) : ByteArray :=
  LeanServer.deriveNextTrafficSecret currentSecret

end LeanServer.TLSKeySchedule
