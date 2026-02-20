import LeanServer.Crypto.Crypto
import LeanServer.Crypto.AES
import LeanServer.Crypto.X25519

/-!
  # Native Crypto FFI Bindings
  High-performance crypto operations via OpenSSL.

  These functions are semantically equivalent to the pure-Lean implementations
  in `LeanServer.Crypto.Crypto`, `LeanServer.Crypto.AES`, and
  `LeanServer.Crypto.X25519`, but run 100–2000× faster via native code.

  Usage is controlled by `CryptoBackend`: set `crypto_backend=native` in
  `server.config` to enable FFI, or `crypto_backend=lean` for the verified
  pure-Lean fallback (default).
-/

namespace LeanServer.CryptoFFI

-- ==========================================
-- Native FFI Declarations (OpenSSL)
-- ==========================================

/-- SHA-256 via OpenSSL. Returns 32 bytes. -/
@[extern "lean_crypto_sha256"]
opaque nativeSHA256 : @& ByteArray → ByteArray

/-- HMAC-SHA256 via OpenSSL. Returns 32 bytes. -/
@[extern "lean_crypto_hmac_sha256"]
opaque nativeHMACSHA256 : @& ByteArray → @& ByteArray → ByteArray

/-- AES-128-GCM Encrypt via OpenSSL.
    Parameters: key(16), iv(12), aad, plaintext.
    Returns: (ciphertext, tag(16)). -/
@[extern "lean_crypto_aes128_gcm_encrypt"]
opaque nativeAES128GCMEncrypt : @& ByteArray → @& ByteArray →
                                 @& ByteArray → @& ByteArray →
                                 ByteArray × ByteArray

/-- AES-128-GCM Decrypt via OpenSSL.
    Parameters: key(16), iv(12), aad, ciphertextWithTag.
    Returns: some plaintext on success, none on auth failure. -/
@[extern "lean_crypto_aes128_gcm_decrypt"]
opaque nativeAES128GCMDecrypt : @& ByteArray → @& ByteArray →
                                 @& ByteArray → @& ByteArray →
                                 Option ByteArray

/-- X25519 scalar multiplication via OpenSSL.
    Parameters: scalar(32), point(32).
    Returns: shared secret(32). -/
@[extern "lean_crypto_x25519"]
opaque nativeX25519 : @& ByteArray → @& ByteArray → ByteArray

/-- X25519 base-point multiplication via OpenSSL.
    Parameters: scalar(32).
    Returns: public key(32). -/
@[extern "lean_crypto_x25519_base"]
opaque nativeX25519Base : @& ByteArray → ByteArray

/-- Cryptographically secure random bytes via OpenSSL RAND_bytes. -/
@[extern "lean_crypto_random_bytes"]
opaque nativeRandomBytes : @& Nat → IO ByteArray

-- ==========================================
-- Backend Selection
-- ==========================================

/-- Crypto backend selection. -/
inductive CryptoBackend where
  | native  : CryptoBackend  -- OpenSSL FFI (fast)
  | lean    : CryptoBackend  -- Pure Lean (verified, slow)
  deriving Repr, BEq, Inhabited

/-- Global crypto backend setting. Default: lean (safe fallback). -/
initialize cryptoBackendRef : IO.Ref CryptoBackend ← IO.mkRef .lean

/-- Set the global crypto backend. -/
def setCryptoBackend (backend : CryptoBackend) : IO Unit :=
  cryptoBackendRef.set backend

/-- Get the current crypto backend. -/
def getCryptoBackend : IO CryptoBackend :=
  cryptoBackendRef.get

-- ==========================================
-- Unified API (dispatches to native or Lean)
-- ==========================================

/-- SHA-256: dispatches to native or pure-Lean based on backend setting. -/
def sha256 (backend : CryptoBackend) (msg : ByteArray) : ByteArray :=
  match backend with
  | .native => nativeSHA256 msg
  | .lean   => LeanServer.sha256 msg

/-- HMAC-SHA256: dispatches to native or pure-Lean. -/
def hmacSHA256 (backend : CryptoBackend) (key msg : ByteArray) : ByteArray :=
  match backend with
  | .native => nativeHMACSHA256 key msg
  | .lean   => LeanServer.hmac_sha256 key msg

/-- AES-128-GCM encrypt: dispatches to native or pure-Lean. -/
def aes128GCMEncrypt (backend : CryptoBackend) (key iv aad plaintext : ByteArray) :
    ByteArray × ByteArray :=
  match backend with
  | .native => nativeAES128GCMEncrypt key iv aad plaintext
  | .lean   => LeanServer.aes128_gcm_encrypt key iv aad plaintext

/-- AES-128-GCM decrypt: dispatches to native or pure-Lean. -/
def aes128GCMDecrypt (backend : CryptoBackend) (key iv aad ciphertextWithTag : ByteArray) :
    Option ByteArray :=
  match backend with
  | .native => nativeAES128GCMDecrypt key iv aad ciphertextWithTag
  | .lean   => LeanServer.aes128_gcm_decrypt key iv aad ciphertextWithTag

/-- X25519 scalar multiplication: dispatches to native or pure-Lean. -/
def x25519 (backend : CryptoBackend) (scalar point : ByteArray) : ByteArray :=
  match backend with
  | .native => nativeX25519 scalar point
  | .lean   => LeanServer.X25519.scalarmult scalar point

/-- X25519 base-point multiplication: dispatches to native or pure-Lean. -/
def x25519Base (backend : CryptoBackend) (scalar : ByteArray) : ByteArray :=
  match backend with
  | .native => nativeX25519Base scalar
  | .lean   =>
    -- Base point (9) in little-endian: 0x09 followed by 31 zero bytes
    let basePoint := ByteArray.mk #[9, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0]
    LeanServer.X25519.scalarmult scalar basePoint

-- ==========================================
-- Config-based initialization
-- ==========================================

/-- Parse crypto_backend from a config string value.
    Accepts "native", "openssl", "ffi" for native mode;
    anything else defaults to lean. -/
def parseCryptoBackend (value : String) : CryptoBackend :=
  let v := value.toLower
  if v == "native" || v == "openssl" || v == "ffi" then .native
  else .lean

end LeanServer.CryptoFFI
