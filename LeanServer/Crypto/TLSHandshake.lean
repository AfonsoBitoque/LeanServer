import LeanServer.Crypto.Crypto

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

namespace LeanServer.TLSHandshake

/-- Parse ClientHello from raw bytes -/
@[inline] def parseClientHello (data : ByteArray) : Option LeanServer.ClientHello :=
  LeanServer.parseClientHello data

/-- Build ServerHello message -/
@[inline] def generateServerHello (ch : LeanServer.ClientHello) (serverPublicKey serverRandom : ByteArray)
    (selectedProtocol : Option String) : ByteArray :=
  LeanServer.generateServerHello ch serverPublicKey serverRandom selectedProtocol

/-- Negotiate cipher suite from client's offered suites -/
@[inline] def negotiateCipherSuite (clientSuites : Array UInt16) : Option UInt16 :=
  LeanServer.negotiateCipherSuite clientSuites

/-- Build Encrypted Extensions message -/
@[inline] def buildEncryptedExtensions (alpnProtocol : Option String) (quicParams : Option ByteArray) : ByteArray :=
  LeanServer.buildEncryptedExtensions alpnProtocol quicParams

/-- Build Certificate message from DER data -/
@[inline] def buildCertificate (certData : ByteArray) : ByteArray :=
  LeanServer.buildCertificate certData

/-- Build CertificateVerify message -/
@[inline] def buildCertificateVerify (signature : ByteArray) : ByteArray :=
  LeanServer.buildCertificateVerify signature

/-- Build Finished message -/
@[inline] def buildFinished (baseKey transcriptHash : ByteArray) : ByteArray :=
  LeanServer.buildFinished baseKey transcriptHash

/-- Build HelloRetryRequest -/
@[inline] def buildHelloRetryRequest (ch : LeanServer.ClientHello) : ByteArray :=
  LeanServer.buildHelloRetryRequest ch

/-- Build KeyUpdate message (RFC 8446 §4.6.3) -/
@[inline] def buildKeyUpdate (requestUpdate : Bool) : ByteArray :=
  LeanServer.buildKeyUpdate requestUpdate

end LeanServer.TLSHandshake
