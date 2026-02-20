import LeanServer.Crypto.Crypto

/-!
  # Certificate Manager — Re-export Module
  Focused import path for X.509 certificate operations.

  ## Key Functions
  - `loadCertificateChain` — Load PEM certificate chain from file
  - `buildCertificateChain` — Build TLS certificate chain message
  - `buildCertificateChainWithOCSP` — Certificate chain with OCSP stapling
  - `buildCertificateChainWithSCT` — Certificate chain with SCT
  - `loadOCSPResponse` — Load OCSP response from file
  - `loadSCTList` — Load SCT list from file
  - `loadCertificateDER` — Load DER certificate
  - `loadPrivateKey` — Load PEM private key
  - `sign` / `verify` — RSA signing/verification

  ## Usage
  ```lean
  import LeanServer.Crypto.CertificateManager
  let chain ← LeanServer.loadCertificateChain "cert.pem"
  ```
-/

namespace LeanServer.CertificateManager

/-- Load PEM certificate chain -/
@[inline] def loadChain (path : String) : IO (Array ByteArray) :=
  LeanServer.loadCertificateChain path

/-- Build certificate chain message for TLS -/
@[inline] def buildChain (leafCert : ByteArray) (intermediates : Array ByteArray) : ByteArray :=
  LeanServer.buildCertificateChain leafCert intermediates

/-- Build certificate chain with OCSP stapling -/
@[inline] def buildChainWithOCSP (leafCert : ByteArray) (intermediates : Array ByteArray) (ocsp : Option ByteArray) : ByteArray :=
  LeanServer.buildCertificateChainWithOCSP leafCert intermediates ocsp

/-- Build certificate chain with SCT (Certificate Transparency) -/
@[inline] def buildChainWithSCT (leafCert : ByteArray) (intermediates : Array ByteArray)
    (ocsp : Option ByteArray) (sctList : Option ByteArray) : ByteArray :=
  LeanServer.buildCertificateChainWithSCT leafCert intermediates ocsp sctList

/-- Load OCSP response from file -/
@[inline] def loadOCSP (path : String) : IO (Option ByteArray) :=
  LeanServer.loadOCSPResponse path

/-- Load SCT list from file -/
@[inline] def loadSCT (path : String) : IO (Option ByteArray) :=
  LeanServer.loadSCTList path

end LeanServer.CertificateManager
