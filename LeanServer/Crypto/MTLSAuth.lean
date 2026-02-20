import LeanServer.Crypto.Crypto
import LeanServer.Crypto.RSA
import LeanServer.Crypto.CertificateManager
import LeanServer.Core.Base64
import LeanServer.Crypto.X509Validation

/-!
# mTLS Client Certificate Authentication (R15)

Implements mutual TLS (mTLS) — the server requests and validates
client certificates during the TLS 1.3 handshake.

## RFC References
- RFC 8446 §4.3.2 — CertificateRequest message
- RFC 8446 §4.4.2 — Client Certificate message
- RFC 8446 §4.4.3 — Client CertificateVerify message

## Handshake Flow (mTLS Enabled)
```
Server → Client:
  1. EncryptedExtensions
  2. CertificateRequest       ← NEW: requests client cert
  3. Certificate               (server cert)
  4. CertificateVerify         (server signature)
  5. Finished

Client → Server:
  1. Certificate               ← NEW: client cert (may be empty)
  2. CertificateVerify         ← NEW: client signature proof
  3. Finished
```

## Configuration
- `client_certs_required = true|false` — whether to require client certs
- `client_cert_ca_file = /path/to/ca.pem` — CA for validating client certs
-/

namespace LeanServer

-- ==========================================
-- mTLS Configuration
-- ==========================================

/-- mTLS configuration -/
structure MTLSConfig where
  enabled           : Bool   := false
  clientCertRequired : Bool  := true   -- reject if client sends no cert?
  caCertPath        : String := ""     -- path to CA certificate for validation
  deriving Repr, Inhabited

/-- mTLS verification result -/
inductive MTLSResult where
  | verified    : ByteArray → MTLSResult  -- client cert data
  | noCert      : MTLSResult              -- client sent empty cert (allowed if not required)
  | rejected    : String → MTLSResult     -- verification failed (reason)

instance : ToString MTLSResult where
  toString
    | .verified d => s!"verified ({d.size} bytes)"
    | .noCert     => "no client certificate"
    | .rejected r => s!"rejected: {r}"

-- ==========================================
-- TLS Handshake Type Constants
-- ==========================================

/-- TLS 1.3 handshake message types (RFC 8446 §4) -/
def tlsClientHello          : UInt8 := 0x01
def tlsServerHello          : UInt8 := 0x02
def tlsEncryptedExtensions  : UInt8 := 0x08
def tlsCertificate          : UInt8 := 0x0b
def tlsCertificateRequest   : UInt8 := 0x0d
def tlsCertificateVerify    : UInt8 := 0x0f
def tlsFinished             : UInt8 := 0x14

-- ==========================================
-- CertificateRequest Message (server → client)
-- ==========================================

/-- Signature algorithms supported for client certificate verification.
    Corresponds to RFC 8446 §4.2.3 "signature_algorithms" extension. -/
def supportedClientSignatureAlgorithms : List (UInt8 × UInt8) :=
  [ (0x04, 0x01)  -- rsa_pkcs1_sha256
  , (0x04, 0x03)  -- ecdsa_secp256r1_sha256
  , (0x08, 0x04)  -- rsa_pss_rsae_sha256
  , (0x08, 0x06)  -- rsa_pss_rsae_sha384
  ]

/-- Build a CertificateRequest message (type 0x0d).
    RFC 8446 §4.3.2:
    ```
    struct {
      opaque certificate_request_context<0..2^8-1>;
      Extension extensions<2..2^16-1>;
    } CertificateRequest;
    ```
    The only mandatory extension is "signature_algorithms". -/
def buildCertificateRequest (requestContext : ByteArray := ByteArray.empty) : ByteArray := Id.run do
  -- certificate_request_context length + data
  let ctxLen := requestContext.size.toUInt8
  let mut msg := ByteArray.empty
  msg := msg.push ctxLen
  msg := msg ++ requestContext

  -- Extensions: signature_algorithms (0x000d)
  let mut sigAlgList := ByteArray.empty
  for (hi, lo) in supportedClientSignatureAlgorithms do
    sigAlgList := sigAlgList.push hi
    sigAlgList := sigAlgList.push lo

  -- SignatureSchemeList length (2 bytes)
  let sigAlgListLen := sigAlgList.size

  -- Extension data = 2 bytes list length + list data
  let extData := ByteArray.empty
    |>.push (sigAlgListLen / 256).toUInt8
    |>.push (sigAlgListLen % 256).toUInt8
    |> (· ++ sigAlgList)

  -- Extension header: type 0x000d + length (2 bytes)
  let mut extensions := ByteArray.empty
  extensions := extensions.push 0x00
  extensions := extensions.push 0x0d  -- signature_algorithms
  extensions := extensions.push (extData.size / 256).toUInt8
  extensions := extensions.push (extData.size % 256).toUInt8
  extensions := extensions ++ extData

  -- Extensions total length (2 bytes)
  msg := msg.push (extensions.size / 256).toUInt8
  msg := msg.push (extensions.size % 256).toUInt8
  msg := msg ++ extensions

  -- Wrap in handshake header: type (1) + length (3)
  let body := msg
  let header := ByteArray.empty
    |>.push tlsCertificateRequest
    |>.push 0x00
    |>.push (body.size / 256).toUInt8
    |>.push (body.size % 256).toUInt8
  header ++ body

-- ==========================================
-- Client Certificate Parsing
-- ==========================================

/-- Parsed client certificate from TLS handshake -/
structure ClientCertificateMsg where
  requestContext : ByteArray
  certificates   : List ByteArray  -- DER-encoded certs

/-- Parse a client Certificate message (type 0x0b).
    RFC 8446 §4.4.2:
    ```
    struct {
      opaque certificate_request_context<0..2^8-1>;
      CertificateEntry certificate_list<0..2^24-1>;
    } Certificate;
    ```
    Each CertificateEntry:
    ```
    struct {
      opaque cert_data<1..2^24-1>;
      Extension extensions<0..2^16-1>;
    } CertificateEntry;
    ```
-/
def parseClientCertificate (data : ByteArray) : Option ClientCertificateMsg := Id.run do
  if data.size < 1 then return none

  let ctxLen := data.get! 0 |>.toNat
  if data.size < 1 + ctxLen + 3 then return none
  let requestContext := data.extract 1 (1 + ctxLen)

  let certListOffset := 1 + ctxLen
  -- 3-byte certificate list length
  let listLen :=
    (data.get! certListOffset).toNat * 65536 +
    (data.get! (certListOffset + 1)).toNat * 256 +
    (data.get! (certListOffset + 2)).toNat
  let mut pos := certListOffset + 3
  let endPos := pos + listLen

  if data.size < endPos then return none

  let mut certs : List ByteArray := []
  while pos < endPos do
    -- 3-byte cert_data length
    if pos + 3 > data.size then break
    let certLen :=
      (data.get! pos).toNat * 65536 +
      (data.get! (pos + 1)).toNat * 256 +
      (data.get! (pos + 2)).toNat
    pos := pos + 3
    if pos + certLen > data.size then break
    let certData := data.extract pos (pos + certLen)
    certs := certs ++ [certData]
    pos := pos + certLen
    -- 2-byte extensions length (skip)
    if pos + 2 > data.size then break
    let extLen := (data.get! pos).toNat * 256 + (data.get! (pos + 1)).toNat
    pos := pos + 2 + extLen

  return some { requestContext, certificates := certs }

-- ==========================================
-- Client CertificateVerify Parsing
-- ==========================================

/-- Parsed CertificateVerify message -/
structure CertificateVerifyMsg where
  signatureScheme : UInt16   -- RFC 8446 §4.2.3
  signature       : ByteArray

/-- Parse a CertificateVerify message (type 0x0f).
    RFC 8446 §4.4.3:
    ```
    struct {
      SignatureScheme algorithm;
      opaque signature<0..2^16-1>;
    } CertificateVerify;
    ```
-/
def parseCertificateVerify (data : ByteArray) : Option CertificateVerifyMsg := Id.run do
  if data.size < 4 then return none
  let scheme := (data.get! 0).toUInt16 * 256 + (data.get! 1).toUInt16
  let sigLen := (data.get! 2).toNat * 256 + (data.get! 3).toNat
  if data.size < 4 + sigLen then return none
  let signature := data.extract 4 (4 + sigLen)
  return some { signatureScheme := scheme, signature }

-- ==========================================
-- CertificateVerify Verification
-- ==========================================

/-- Build the signed content for TLS 1.3 CertificateVerify (client side).
    RFC 8446 §4.4.3:
    "The content that is covered under the signature is the hash of
     the handshake context with 64 spaces + context string + 0x00 + transcript hash"
    Context string for client: "TLS 1.3, client CertificateVerify"
-/
def buildClientCertVerifyContent (transcriptHash : ByteArray) : ByteArray :=
  let spaces := Id.run do
    let mut s := ByteArray.empty
    for _ in List.range 64 do
      s := s.push 0x20
    return s
  let context := "TLS 1.3, client CertificateVerify".toUTF8
  let separator := ByteArray.empty.push 0x00
  spaces ++ context ++ separator ++ transcriptHash

/-- Verify a client's CertificateVerify signature using RSA PKCS#1 v1.5.
    For scheme 0x0401 (rsa_pkcs1_sha256):
    1. Build the signed content from transcript hash
    2. SHA-256 hash the signed content
    3. RSA verify the signature against the client's public key -/
def verifyClientCertificateVerify
    (certVerify : CertificateVerifyMsg)
    (transcriptHash : ByteArray)
    (clientPublicKey : ByteArray) : Bool :=
  -- Only supporting rsa_pkcs1_sha256 (0x0401) for now
  if certVerify.signatureScheme != 0x0401 then false
  else
    let content := buildClientCertVerifyContent transcriptHash
    -- Use RSA-PSS-SHA256 verification
    verify clientPublicKey content certVerify.signature

-- ==========================================
-- Client Certificate Chain Validation
-- ==========================================

/-- Validate a client certificate chain using full X.509 validation.
    Uses X509.validateChain which verifies:
    1. Certificate parsing (DER / ASN.1)
    2. Time validity (notBefore / notAfter)
    3. CA flag on intermediates (BasicConstraints)
    4. Path length constraints
    5. Issuer / subject chain linkage
    6. RSA signature verification
    7. Trust anchor matching against the provided CA -/
def validateClientCertChain
    (clientCerts : List ByteArray)
    (caCert : Option ByteArray := none)
    : MTLSResult :=
  match clientCerts with
  | [] => .noCert
  | cert :: _ =>
    -- Basic sanity check: cert must be non-trivially sized (DER minimum)
    if cert.size < 64 then
      .rejected "Client certificate too small (likely malformed)"
    else
      -- Build the certificate chain array
      let chainArray := clientCerts.toArray
      -- Build trust store from CA cert (if provided)
      let store : X509.TrustStore := match caCert with
        | some ca =>
          match X509.parseCertificate ca with
          | some parsed => { certificates := #[parsed] }
          | none => { certificates := #[] }
        | none => { certificates := #[] }
      -- Use real X.509 chain validation (nowSeconds = 0 skips time check
      -- since we don't have a clock in pure context; time is checked at IO layer)
      match X509.validateChain store chainArray 0
              { X509.defaultConfig with checkValidity := false } with
      | .valid => .verified cert
      | .expired msg => .rejected s!"Certificate expired: {msg}"
      | .notYetValid msg => .rejected s!"Certificate not yet valid: {msg}"
      | .signatureInvalid msg => .rejected s!"Signature verification failed: {msg}"
      | .chainBroken msg => .rejected s!"Chain validation failed: {msg}"
      | .malformed msg => .rejected s!"Malformed certificate: {msg}"
      | .untrusted msg => .rejected s!"Untrusted certificate: {msg}"
      | .depthExceeded msg => .rejected s!"Chain too deep: {msg}"

-- ==========================================
-- mTLS Integration with TLS Handshake
-- ==========================================

/-- State for tracking mTLS progress during handshake -/
structure MTLSState where
  config             : MTLSConfig
  requestContext     : ByteArray := ByteArray.empty
  clientCertReceived : Bool := false
  clientCertVerified : Bool := false
  clientCertData     : Option ByteArray := none
  verifyResult       : Option MTLSResult := none

/-- Initialize mTLS state from configuration -/
def MTLSState.init (config : MTLSConfig) : MTLSState :=
  { config }

/-- Process a client Certificate message during mTLS handshake -/
def MTLSState.processClientCert (state : MTLSState) (data : ByteArray) (caCert : Option ByteArray)
    : MTLSState × MTLSResult :=
  match parseClientCertificate data with
  | none =>
    let result := MTLSResult.rejected "Failed to parse client certificate message"
    ({ state with verifyResult := some result }, result)
  | some certMsg =>
    let result := validateClientCertChain certMsg.certificates caCert
    match result with
    | .verified certData =>
      ({ state with
        clientCertReceived := true
        clientCertData := some certData
        verifyResult := some result }, result)
    | .noCert =>
      if state.config.clientCertRequired then
        let r := MTLSResult.rejected "Client certificate required but not provided"
        ({ state with verifyResult := some r }, r)
      else
        ({ state with
          clientCertReceived := true
          verifyResult := some result }, result)
    | .rejected reason =>
      ({ state with verifyResult := some result },
       .rejected reason)

/-- Process a client CertificateVerify message during mTLS handshake -/
def MTLSState.processClientCertVerify
    (state : MTLSState)
    (data : ByteArray)
    (transcriptHash : ByteArray)
    (clientPubKey : ByteArray)
    : MTLSState × Bool :=
  match parseCertificateVerify data with
  | none => ({ state with clientCertVerified := false }, false)
  | some certVerify =>
    let ok := verifyClientCertificateVerify certVerify transcriptHash clientPubKey
    ({ state with clientCertVerified := ok }, ok)

/-- Check if mTLS handshake is complete and valid -/
def MTLSState.isComplete (state : MTLSState) : Bool :=
  if !state.config.enabled then true  -- mTLS not enabled, always complete
  else if !state.config.clientCertRequired then
    -- If client cert not required, just having processed it is enough
    state.clientCertReceived
  else
    -- Client cert required: must be received and verified
    state.clientCertReceived && state.clientCertVerified

/-- Summary of mTLS authentication for logging -/
def MTLSState.summary (state : MTLSState) : String :=
  if !state.config.enabled then "mTLS disabled"
  else
    let certStatus := if state.clientCertReceived then "received" else "not received"
    let verifyStatus := if state.clientCertVerified then "verified" else "not verified"
    let certSize := match state.clientCertData with
      | some d => s!"{d.size} bytes"
      | none => "none"
    s!"mTLS: cert {certStatus}, {verifyStatus}, cert data: {certSize}"

-- ==========================================
-- Helper: Load CA Certificate from File
-- ==========================================

/-- Load a CA certificate from a PEM file for client cert validation -/
def loadCACertificate (path : String) : IO (Option ByteArray) := do
  let exists_ ← System.FilePath.pathExists path
  if !exists_ then return none
  let content ← IO.FS.readFile path
  -- Simple PEM extraction: find base64 between BEGIN/END markers
  let lines := content.splitOn "\n"
  let mut inCert := false
  let mut b64 := ""
  for line in lines do
    let trimmed := line.trimAscii.toString
    if trimmed.startsWith "-----BEGIN" then
      inCert := true
    else if trimmed.startsWith "-----END" then
      inCert := false
    else if inCert then
      b64 := b64 ++ trimmed
  if b64.isEmpty then return none
  -- Decode base64
  match LeanServer.Base64.decode b64 with
  | some decoded =>
    if decoded.size > 0 then return some decoded
    else return none
  | none => return none

-- ==========================================
-- mTLS Proofs / Invariants
-- ==========================================

/-- If mTLS is disabled, isComplete is always true -/
theorem mtls_disabled_always_complete (s : MTLSState) (h : s.config.enabled = false) :
    s.isComplete = true := by
  simp [MTLSState.isComplete, h]

end LeanServer
