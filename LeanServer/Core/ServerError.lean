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

namespace LeanServer

/-- Network-level error categories -/
inductive NetworkErrorKind where
  | connectionRefused
  | connectionReset
  | connectionTimeout
  | bindFailed
  | listenFailed
  | sendFailed
  | recvFailed
  | addressInUse
  | socketClosed
  deriving Inhabited, BEq, Repr

/-- TLS/crypto error categories -/
inductive TLSErrorKind where
  | handshakeFailed
  | certificateInvalid
  | certificateExpired
  | badRecord
  | decryptionFailed
  | unsupportedVersion
  | unsupportedCipherSuite
  | alertReceived (level : UInt8) (description : UInt8)
  deriving Inhabited, BEq, Repr

/-- HTTP protocol error categories -/
inductive ProtocolErrorKind where
  | malformedRequest
  | malformedResponse
  | frameTooLarge
  | streamClosed
  | flowControlError
  | compressionError
  | settingsTimeout
  | enhanceYourCalm  -- HTTP/2 ENHANCE_YOUR_CALM
  | internalError
  deriving Inhabited, BEq, Repr

/-- QUIC-specific error categories -/
inductive QUICErrorKind where
  | connectionIdMismatch
  | versionNegotiationFailed
  | transportError (code : UInt64)
  | applicationError (code : UInt64)
  | cryptoError
  | idleTimeout
  | antiAmplificationLimit
  deriving Inhabited, BEq, Repr

/-- Configuration error categories -/
inductive ConfigErrorKind where
  | fileNotFound
  | parseError
  | invalidValue (key : String)
  | missingRequired (key : String)
  deriving Inhabited, BEq, Repr

/-- Unified server error type with structured categories -/
inductive ServerError where
  | network    (kind : NetworkErrorKind)  (message : String)
  | tls        (kind : TLSErrorKind)      (message : String)
  | protocol   (kind : ProtocolErrorKind) (message : String)
  | quic       (kind : QUICErrorKind)     (message : String)
  | config     (kind : ConfigErrorKind)   (message : String)
  | database   (message : String)
  | io         (message : String)
  | internal   (message : String)
  deriving Inhabited, Repr

instance : ToString NetworkErrorKind where
  toString
    | .connectionRefused => "CONNECTION_REFUSED"
    | .connectionReset   => "CONNECTION_RESET"
    | .connectionTimeout => "CONNECTION_TIMEOUT"
    | .bindFailed        => "BIND_FAILED"
    | .listenFailed      => "LISTEN_FAILED"
    | .sendFailed        => "SEND_FAILED"
    | .recvFailed        => "RECV_FAILED"
    | .addressInUse      => "ADDRESS_IN_USE"
    | .socketClosed      => "SOCKET_CLOSED"

instance : ToString TLSErrorKind where
  toString
    | .handshakeFailed        => "HANDSHAKE_FAILED"
    | .certificateInvalid     => "CERTIFICATE_INVALID"
    | .certificateExpired     => "CERTIFICATE_EXPIRED"
    | .badRecord              => "BAD_RECORD"
    | .decryptionFailed       => "DECRYPTION_FAILED"
    | .unsupportedVersion     => "UNSUPPORTED_VERSION"
    | .unsupportedCipherSuite => "UNSUPPORTED_CIPHER_SUITE"
    | .alertReceived l d      => s!"ALERT({l},{d})"

instance : ToString ProtocolErrorKind where
  toString
    | .malformedRequest  => "MALFORMED_REQUEST"
    | .malformedResponse => "MALFORMED_RESPONSE"
    | .frameTooLarge     => "FRAME_TOO_LARGE"
    | .streamClosed      => "STREAM_CLOSED"
    | .flowControlError  => "FLOW_CONTROL_ERROR"
    | .compressionError  => "COMPRESSION_ERROR"
    | .settingsTimeout   => "SETTINGS_TIMEOUT"
    | .enhanceYourCalm   => "ENHANCE_YOUR_CALM"
    | .internalError     => "INTERNAL_ERROR"

instance : ToString QUICErrorKind where
  toString
    | .connectionIdMismatch       => "CID_MISMATCH"
    | .versionNegotiationFailed   => "VERSION_NEGOTIATION_FAILED"
    | .transportError code        => s!"TRANSPORT_ERROR({code})"
    | .applicationError code      => s!"APPLICATION_ERROR({code})"
    | .cryptoError                => "CRYPTO_ERROR"
    | .idleTimeout                => "IDLE_TIMEOUT"
    | .antiAmplificationLimit     => "ANTI_AMPLIFICATION_LIMIT"

instance : ToString ConfigErrorKind where
  toString
    | .fileNotFound        => "FILE_NOT_FOUND"
    | .parseError          => "PARSE_ERROR"
    | .invalidValue key    => s!"INVALID_VALUE({key})"
    | .missingRequired key => s!"MISSING_REQUIRED({key})"

instance : ToString ServerError where
  toString
    | .network kind msg  => s!"[NET/{kind}] {msg}"
    | .tls kind msg      => s!"[TLS/{kind}] {msg}"
    | .protocol kind msg => s!"[PROTO/{kind}] {msg}"
    | .quic kind msg     => s!"[QUIC/{kind}] {msg}"
    | .config kind msg   => s!"[CONFIG/{kind}] {msg}"
    | .database msg      => s!"[DB] {msg}"
    | .io msg            => s!"[IO] {msg}"
    | .internal msg      => s!"[INTERNAL] {msg}"

/-- Get the error category as a string (for structured logging) -/
def ServerError.category : ServerError → String
  | .network ..  => "network"
  | .tls ..      => "tls"
  | .protocol .. => "protocol"
  | .quic ..     => "quic"
  | .config ..   => "config"
  | .database .. => "database"
  | .io ..       => "io"
  | .internal .. => "internal"

/-- Get the message from any ServerError -/
def ServerError.message : ServerError → String
  | .network _ msg  => msg
  | .tls _ msg      => msg
  | .protocol _ msg => msg
  | .quic _ msg     => msg
  | .config _ msg   => msg
  | .database msg   => msg
  | .io msg         => msg
  | .internal msg   => msg

/-- Is this error retryable? -/
def ServerError.isRetryable : ServerError → Bool
  | .network .connectionTimeout _ => true
  | .network .connectionReset _   => true
  | .network .recvFailed _        => true
  | .quic .idleTimeout _          => true
  | .database _                   => true
  | _                             => false

/-- Alias: ServerResult is Except ServerError α -/
abbrev ServerResult (α : Type) := Except ServerError α

/-- Lift IO errors into ServerError.io -/
def ServerError.fromIO {α : Type} (action : IO α) : IO (ServerResult α) := do
  try
    let result ← action
    return Except.ok result
  catch e =>
    return Except.error (.io (toString e))

end LeanServer
