import LeanServer.Crypto.Crypto

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

namespace LeanServer.SHA256

/-- SHA-256 hash — re-export for focused import -/
@[inline] def hash (msg : ByteArray) : ByteArray := LeanServer.sha256 msg

/-- HMAC-SHA256 — re-export for focused import -/
@[inline] def hmac (key : ByteArray) (msg : ByteArray) : ByteArray :=
  LeanServer.hmac_sha256 key msg

/-- HKDF-Extract — re-export -/
@[inline] def extract (salt : ByteArray) (ikm : ByteArray) : ByteArray :=
  LeanServer.hkdf_extract salt ikm

/-- HKDF-Expand-Label — re-export -/
@[inline] def expandLabel (secret : ByteArray) (label : String) (context : ByteArray) (len : UInt16) : ByteArray :=
  LeanServer.hkdfExpandLabel secret label context len

/-- SHA-256 output length in bytes -/
def outputLen : Nat := 32

/-- HMAC-SHA256 block size in bytes -/
def blockSize : Nat := 64

end LeanServer.SHA256
