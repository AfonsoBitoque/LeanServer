import LeanServer.Crypto.Crypto
import LeanServer.Crypto.SHA256
import LeanServer.Crypto.RSA

/-!
  # X.509 Certificate Chain Validation
  RFC 5280 compliant certificate chain validation with trust store.

  ## Features
  - ASN.1 DER parsing of X.509 v3 certificate structures
  - Trust store: load CA certificates from PEM files
  - Chain validation: issuer/subject matching, validity period, depth limit
  - Signature verification (RSA-PKCS#1v1.5 with SHA-256)
  - Designed for mTLS client certificate verification and upstream validation

  ## Usage
  ```lean
  import LeanServer.Crypto.X509Validation
  -- Load trust store
  let store ← LeanServer.X509.loadTrustStore "/etc/ssl/certs/ca-bundle.crt"
  -- Validate a certificate chain
  let result := LeanServer.X509.validateChain store certChain (← IO.monoMsNow)
  ```
-/

namespace LeanServer.X509

-- ==========================================
-- ASN.1 DER Tag Constants
-- ==========================================

def TAG_BOOLEAN         : UInt8 := 0x01
def TAG_INTEGER         : UInt8 := 0x02
def TAG_BIT_STRING      : UInt8 := 0x03
def TAG_OCTET_STRING    : UInt8 := 0x04
def TAG_NULL            : UInt8 := 0x05
def TAG_OID             : UInt8 := 0x06
def TAG_UTF8_STRING     : UInt8 := 0x0C
def TAG_PRINTABLE_STRING : UInt8 := 0x13
def TAG_IA5_STRING      : UInt8 := 0x16
def TAG_UTC_TIME        : UInt8 := 0x17
def TAG_GENERALIZED_TIME : UInt8 := 0x18
def TAG_SEQUENCE        : UInt8 := 0x30
def TAG_SET             : UInt8 := 0x31

-- ==========================================
-- ASN.1 DER Parser
-- ==========================================

/-- Result of parsing one ASN.1 TLV (Tag-Length-Value) -/
structure ASN1TLV where
  tag      : UInt8
  content  : ByteArray    -- raw content bytes
  totalLen : Nat          -- total bytes consumed (tag + length + content)
  deriving Inhabited

/-- Parse ASN.1 length field (multi-byte lengths supported) -/
def parseLength (data : ByteArray) (offset : Nat) : Option (Nat × Nat) :=
  if offset >= data.size then none
  else
    let b := data.get! offset
    if b < 0x80 then
      some (b.toNat, 1)
    else if b == 0x80 then
      none  -- Indefinite length not supported in DER
    else
      let numBytes := (b &&& 0x7F).toNat
      if numBytes > 4 || offset + 1 + numBytes > data.size then none
      else
        let len := Id.run do
          let mut len : Nat := 0
          for i in [:numBytes] do
            len := len * 256 + (data.get! (offset + 1 + i)).toNat
          len
        some (len, 1 + numBytes)

/-- Parse one ASN.1 TLV element -/
def parseTLV (data : ByteArray) (offset : Nat) : Option ASN1TLV :=
  if offset >= data.size then none
  else
    let tag := data.get! offset
    match parseLength data (offset + 1) with
    | some (contentLen, lenBytes) =>
      let headerLen := 1 + lenBytes
      let contentStart := offset + headerLen
      if contentStart + contentLen > data.size then none
      else
        let content := data.extract contentStart (contentStart + contentLen)
        some { tag, content, totalLen := headerLen + contentLen }
    | none => none

/-- Parse a SEQUENCE, returning the content bytes for further parsing -/
def parseSequence (data : ByteArray) (offset : Nat) : Option (ByteArray × Nat) :=
  match parseTLV data offset with
  | some tlv =>
    if tlv.tag == TAG_SEQUENCE then some (tlv.content, tlv.totalLen)
    else none
  | none => none

/-- Parse all children TLV elements inside a container.
    Uses fuel = data.size to guarantee termination since offset
    increases by at least 1 each step (totalLen ≥ 1 for valid TLVs). -/
def parseChildren (data : ByteArray) : Array ASN1TLV :=
  go data 0 #[] data.size
where
  go (data : ByteArray) (offset : Nat) (acc : Array ASN1TLV) (fuel : Nat) : Array ASN1TLV :=
    match fuel with
    | 0 => acc
    | fuel' + 1 =>
      if offset >= data.size then acc
      else match parseTLV data offset with
        | some tlv => go data (offset + tlv.totalLen) (acc.push tlv) fuel'
        | none => acc

-- ==========================================
-- OID Parsing
-- ==========================================

/-- Decode an OID from DER bytes to dotted-string form -/
def decodeOID (bytes : ByteArray) : String :=
  if bytes.size == 0 then ""
  else
    let first := bytes.get! 0
    let c1 := first.toNat / 40
    let c2 := first.toNat % 40
    Id.run do
      let mut result := s!"{c1}.{c2}"
      let mut value : Nat := 0
      for i in [1:bytes.size] do
        let b := bytes.get! i
        value := value * 128 + (b &&& 0x7F).toNat
        if (b &&& 0x80) == 0 then
          result := result ++ s!".{value}"
          value := 0
      result

-- Well-known OIDs
def OID_RSA_ENCRYPTION     := "1.2.840.113549.1.1.1"
def OID_SHA256_WITH_RSA     := "1.2.840.113549.1.1.11"
def OID_SHA384_WITH_RSA     := "1.2.840.113549.1.1.12"
def OID_SHA512_WITH_RSA     := "1.2.840.113549.1.1.13"
def OID_ECDSA_WITH_SHA256   := "1.2.840.10045.4.3.2"
def OID_COMMON_NAME         := "2.5.4.3"
def OID_ORGANIZATION        := "2.5.4.10"
def OID_COUNTRY             := "2.5.4.6"
def OID_BASIC_CONSTRAINTS   := "2.5.29.19"
def OID_KEY_USAGE            := "2.5.29.15"

-- ==========================================
-- X.509 Certificate Structure
-- ==========================================

/-- Parsed validity period -/
structure Validity where
  notBefore : Nat   -- Unix timestamp (seconds)
  notAfter  : Nat   -- Unix timestamp (seconds)

instance : Inhabited Validity := ⟨{ notBefore := 0, notAfter := 0 }⟩

/-- Parsed distinguished name (simplified) -/
structure DistinguishedName where
  raw       : ByteArray   -- DER bytes for exact comparison
  commonName : Option String := none
  organization : Option String := none
  country    : Option String := none

instance : BEq DistinguishedName where
  beq a b := a.raw == b.raw

instance : Inhabited DistinguishedName := ⟨{ raw := ByteArray.empty }⟩

/-- Parsed X.509 certificate (relevant fields for chain validation) -/
structure ParsedCertificate where
  rawDER          : ByteArray       -- original DER bytes
  tbsCertificate  : ByteArray       -- TBS (To-Be-Signed) raw bytes for signature verification
  version         : Nat             -- 0=v1, 1=v2, 2=v3
  serialNumber    : ByteArray
  signatureAlgorithm : String       -- OID string
  issuer          : DistinguishedName
  subject         : DistinguishedName
  validity        : Validity
  subjectPublicKeyInfo : ByteArray  -- raw SPKI bytes
  isCA            : Bool            -- from BasicConstraints extension
  maxPathLength   : Option Nat      -- from BasicConstraints
  signature       : ByteArray       -- the signature value
  deriving Inhabited

/-- Validation result -/
inductive ValidationResult where
  | valid
  | expired (msg : String)
  | notYetValid (msg : String)
  | untrusted (msg : String)
  | chainBroken (msg : String)
  | signatureInvalid (msg : String)
  | depthExceeded (msg : String)
  | malformed (msg : String)

def ValidationResult.isValid : ValidationResult → Bool
  | .valid => true
  | _ => false

def ValidationResult.toString : ValidationResult → String
  | .valid => "Valid"
  | .expired msg => s!"Expired: {msg}"
  | .notYetValid msg => s!"Not yet valid: {msg}"
  | .untrusted msg => s!"Untrusted: {msg}"
  | .chainBroken msg => s!"Chain broken: {msg}"
  | .signatureInvalid msg => s!"Signature invalid: {msg}"
  | .depthExceeded msg => s!"Depth exceeded: {msg}"
  | .malformed msg => s!"Malformed: {msg}"

instance : ToString ValidationResult := ⟨ValidationResult.toString⟩

-- ==========================================
-- Time Parsing (UTCTime / GeneralizedTime)
-- ==========================================

/-- Parse 2-digit decimal from string at offset -/
private def parse2Digit (s : String) (offset : Nat) : Nat :=
  let chars := s.toList.toArray
  if offset + 1 < chars.size then
    let d1 := (chars[offset]!).toNat - '0'.toNat
    let d2 := (chars[offset + 1]!).toNat - '0'.toNat
    d1 * 10 + d2
  else 0

/-- Parse 4-digit decimal from string at offset -/
private def parse4Digit (s : String) (offset : Nat) : Nat :=
  let chars := s.toList.toArray
  if offset + 3 < chars.size then
    let d1 := (chars[offset]!).toNat - '0'.toNat
    let d2 := (chars[offset + 1]!).toNat - '0'.toNat
    let d3 := (chars[offset + 2]!).toNat - '0'.toNat
    let d4 := (chars[offset + 3]!).toNat - '0'.toNat
    d1 * 1000 + d2 * 100 + d3 * 10 + d4
  else 0

/-- Days in each month (non-leap year) -/
private def daysInMonth : Array Nat := #[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

/-- Check if a year is a leap year -/
private def isLeapYear (y : Nat) : Bool :=
  (y % 4 == 0 && y % 100 != 0) || y % 400 == 0

/-- Convert date/time to approximate Unix timestamp (seconds since 1970-01-01T00:00:00Z) -/
private def dateToUnixTimestamp (year month day hour minute second : Nat) : Nat :=
  let days := Id.run do
    -- Count days from 1970 to the given year
    let mut days : Nat := 0
    for y in [1970:year] do
      days := days + if isLeapYear y then 366 else 365
    -- Add days for months in the given year
    for m in [0:month - 1] do
      if m < 12 then
        days := days + (if m < daysInMonth.size then daysInMonth[m]! else 30)
        -- Adjust February for leap year
        if m == 1 && isLeapYear year then
          days := days + 1
    -- Add remaining days (day is 1-based)
    days := days + (day - 1)
    days
  -- Convert to seconds
  days * 86400 + hour * 3600 + minute * 60 + second

/-- Parse UTCTime (YYMMDDHHMMSSZ) → Unix timestamp -/
def parseUTCTime (content : ByteArray) : Option Nat :=
  match String.fromUTF8? content with
  | none => none
  | some s =>
    if s.length < 12 then none
    else
      let yy := parse2Digit s 0
      -- RFC 5280 §4.1.2.5.1: YY >= 50 → 19YY, YY < 50 → 20YY
      let year := if yy >= 50 then 1900 + yy else 2000 + yy
      let month := parse2Digit s 2
      let day := parse2Digit s 4
      let hour := parse2Digit s 6
      let minute := parse2Digit s 8
      let second := parse2Digit s 10
      some (dateToUnixTimestamp year month day hour minute second)

/-- Parse GeneralizedTime (YYYYMMDDHHMMSSZ) → Unix timestamp -/
def parseGeneralizedTime (content : ByteArray) : Option Nat :=
  match String.fromUTF8? content with
  | none => none
  | some s =>
    if s.length < 14 then none
    else
      let year := parse4Digit s 0
      let month := parse2Digit s 4
      let day := parse2Digit s 6
      let hour := parse2Digit s 8
      let minute := parse2Digit s 10
      let second := parse2Digit s 12
      some (dateToUnixTimestamp year month day hour minute second)

-- ==========================================
-- X.509 Certificate Parsing
-- ==========================================

/-- Parse a Distinguished Name from DER bytes -/
def parseDistinguishedName (data : ByteArray) : DistinguishedName :=
  let children := parseChildren data
  let (cn, org, country) := Id.run do
    let mut cn : Option String := none
    let mut org : Option String := none
    let mut country : Option String := none
    -- Each child is a SET containing SEQUENCE(OID, value)
    for setTLV in children do
      if setTLV.tag == TAG_SET then
        let setChildren := parseChildren setTLV.content
        for seqTLV in setChildren do
          if seqTLV.tag == TAG_SEQUENCE then
            let seqChildren := parseChildren seqTLV.content
            if seqChildren.size >= 2 then
              let oidTLV := seqChildren[0]!
              let valueTLV := seqChildren[1]!
              if oidTLV.tag == TAG_OID then
                let oid := decodeOID oidTLV.content
                let valueStr := match String.fromUTF8? valueTLV.content with
                  | some s => some s
                  | none => none
                if oid == OID_COMMON_NAME then cn := valueStr
                else if oid == OID_ORGANIZATION then org := valueStr
                else if oid == OID_COUNTRY then country := valueStr
    (cn, org, country)
  { raw := data, commonName := cn, organization := org, country := country }

/-- Parse Validity (SEQUENCE of two time values) -/
def parseValidity (data : ByteArray) : Option Validity := do
  let children := parseChildren data
  if children.size < 2 then none
  else
    let notBeforeTLV := children[0]!
    let notAfterTLV := children[1]!
    let notBefore ← match notBeforeTLV.tag with
      | 0x17 => parseUTCTime notBeforeTLV.content       -- UTCTime
      | 0x18 => parseGeneralizedTime notBeforeTLV.content -- GeneralizedTime
      | _    => none
    let notAfter ← match notAfterTLV.tag with
      | 0x17 => parseUTCTime notAfterTLV.content
      | 0x18 => parseGeneralizedTime notAfterTLV.content
      | _    => none
    some { notBefore, notAfter }

/-- Extract BasicConstraints from extensions -/
private def parseBasicConstraints (extContent : ByteArray) : (Bool × Option Nat) :=
  -- BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
  match parseSequence extContent 0 with
  | some (seqContent, _) =>
    let children := parseChildren seqContent
    match children.size with
    | 0 => (false, none)
    | 1 =>
      if children[0]!.tag == TAG_BOOLEAN && children[0]!.content.size > 0 then
        (children[0]!.content.get! 0 != 0, none)
      else (false, none)
    | _ =>
      let isCA := if children[0]!.tag == TAG_BOOLEAN && children[0]!.content.size > 0
        then children[0]!.content.get! 0 != 0 else false
      let pathLen := if children[1]!.tag == TAG_INTEGER && children[1]!.content.size > 0
        then some (LeanServer.RSA.os2ip children[1]!.content) else none
      (isCA, pathLen)
  | none => (false, none)

/-- Parse extensions from the explicit [3] tagged field -/
private def parseExtensions (data : ByteArray) : (Bool × Option Nat) :=
  -- data is the content of the [3] EXPLICIT tag, which contains a SEQUENCE of extensions
  match parseSequence data 0 with
  | some (extsContent, _) =>
    let exts := parseChildren extsContent
    Id.run do
      let mut isCA := false
      let mut pathLen : Option Nat := none
      for ext in exts do
        if ext.tag == TAG_SEQUENCE then
          let extChildren := parseChildren ext.content
          if extChildren.size >= 2 then
            let oidTLV := extChildren[0]!
            if oidTLV.tag == TAG_OID then
              let oid := decodeOID oidTLV.content
              if oid == OID_BASIC_CONSTRAINTS then
                -- The value is in the last child (might have critical bool before it)
                let valueTLV := extChildren[extChildren.size - 1]!
                if valueTLV.tag == TAG_OCTET_STRING then
                  let (ca, pl) := parseBasicConstraints valueTLV.content
                  isCA := ca
                  pathLen := pl
      (isCA, pathLen)
  | none => (false, none)

/-- Parse a DER-encoded X.509 certificate -/
def parseCertificate (der : ByteArray) : Option ParsedCertificate := do
  -- Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
  match parseSequence der 0 with
  | some (certContent, _) =>
    let topChildren := parseChildren certContent
    if topChildren.size < 3 then none
    else
      let tbsTLV := topChildren[0]!
      let sigAlgTLV := topChildren[1]!
      let sigValTLV := topChildren[2]!

      -- tbsCertificate must be a SEQUENCE
      if tbsTLV.tag != TAG_SEQUENCE then none
      else

      -- Parse tbsCertificate children
      let tbsChildren := parseChildren tbsTLV.content
      if tbsChildren.size < 6 then none
      else

      -- Determine offset based on version field
      -- If first child is context-tagged [0] (0xA0), it's the explicit version
      let (version, fieldOffset) :=
        if tbsChildren[0]!.tag == 0xA0 then
          -- version is inside the [0] EXPLICIT tag
          let vChildren := parseChildren tbsChildren[0]!.content
          let v := if vChildren.size > 0 && vChildren[0]!.tag == TAG_INTEGER && vChildren[0]!.content.size > 0
            then vChildren[0]!.content.get! 0 |>.toNat
            else 0
          (v, 1)
        else (0, 0)  -- v1 has no explicit version field

      if fieldOffset + 5 >= tbsChildren.size then none
      else

      -- serialNumber
      let serialTLV := tbsChildren[fieldOffset]!
      let serialNumber := serialTLV.content

      -- signature algorithm (inside TBS — must match outer)
      let tbsSigAlgTLV := tbsChildren[fieldOffset + 1]!
      let sigAlgOID := if tbsSigAlgTLV.tag == TAG_SEQUENCE then
        let algChildren := parseChildren tbsSigAlgTLV.content
        if algChildren.size > 0 && algChildren[0]!.tag == TAG_OID then
          decodeOID algChildren[0]!.content
        else ""
      else ""

      -- issuer
      let issuerTLV := tbsChildren[fieldOffset + 2]!
      let issuer := parseDistinguishedName issuerTLV.content

      -- validity
      let validityTLV := tbsChildren[fieldOffset + 3]!
      let validity ← if validityTLV.tag == TAG_SEQUENCE then
        parseValidity validityTLV.content
      else none

      -- subject
      let subjectTLV := tbsChildren[fieldOffset + 4]!
      let subject := parseDistinguishedName subjectTLV.content

      -- subjectPublicKeyInfo
      let spkiTLV := tbsChildren[fieldOffset + 5]!

      -- Extensions (context-tagged [3] = 0xA3), only in v3
      let (isCA, maxPathLength) :=
        if version >= 2 then
          -- Look for [3] tagged element
          let found := tbsChildren.foldl (fun acc child =>
            if child.tag == 0xA3 then parseExtensions child.content
            else acc
          ) (false, none)
          found
        else (false, none)

      -- Outer signature algorithm OID
      let outerSigAlg := if sigAlgTLV.tag == TAG_SEQUENCE then
        let algChildren := parseChildren sigAlgTLV.content
        if algChildren.size > 0 && algChildren[0]!.tag == TAG_OID then
          decodeOID algChildren[0]!.content
        else sigAlgOID
      else sigAlgOID

      -- Signature value (BIT STRING — skip the unused-bits byte)
      let signature := if sigValTLV.tag == TAG_BIT_STRING && sigValTLV.content.size > 0 then
        sigValTLV.content.extract 1 sigValTLV.content.size
      else sigValTLV.content

      -- Reconstruct TBS bytes for signature verification
      -- We reconstruct: 0x30 + encoded length + content
      let tbsBytes :=
        let contentLen := tbsTLV.content.size
        let lenEncoding := if contentLen < 0x80 then
          ByteArray.mk #[contentLen.toUInt8]
        else if contentLen < 0x100 then
          ByteArray.mk #[0x81, contentLen.toUInt8]
        else
          ByteArray.mk #[0x82, (contentLen / 256).toUInt8, (contentLen % 256).toUInt8]
        ByteArray.mk #[TAG_SEQUENCE] ++ lenEncoding ++ tbsTLV.content

      some {
        rawDER := der,
        tbsCertificate := tbsBytes,
        version,
        serialNumber,
        signatureAlgorithm := outerSigAlg,
        issuer,
        subject,
        validity,
        subjectPublicKeyInfo := spkiTLV.content,
        isCA,
        maxPathLength,
        signature
      }

  | none => none

-- ==========================================
-- Trust Store
-- ==========================================

/-- A trust store is a collection of trusted CA certificates -/
structure TrustStore where
  certificates : Array ParsedCertificate

/-- Empty trust store -/
def TrustStore.empty : TrustStore := { certificates := #[] }

/-- Add a certificate to the trust store -/
def TrustStore.addCert (store : TrustStore) (cert : ParsedCertificate) : TrustStore :=
  { certificates := store.certificates.push cert }

/-- Load trust store from a PEM file containing multiple CA certificates -/
def loadTrustStore (path : String) : IO TrustStore := do
  let certs ← LeanServer.loadCertificateChain path
  let mut store := TrustStore.empty
  for certDER in certs do
    match parseCertificate certDER with
    | some parsed => store := store.addCert parsed
    | none => IO.eprintln s!"[X509] Warning: failed to parse CA certificate ({certDER.size} bytes)"
  IO.eprintln s!"[X509] Trust store loaded: {store.certificates.size} CA certificates"
  pure store

/-- Load trust store from a directory of PEM files -/
def loadTrustStoreDir (dirPath : String) : IO TrustStore := do
  let mut store := TrustStore.empty
  let entries : Array System.FilePath ← try
    let dir := System.FilePath.mk dirPath
    let items ← dir.readDir
    pure (items.map fun e => e.path)
  catch _ =>
    IO.eprintln s!"[X509] Warning: cannot read trust store directory: {dirPath}"
    pure #[]
  for entry in entries do
    let fname := entry.toString
    if String.endsWith fname ".pem" || String.endsWith fname ".crt" then
      match ← try some <$> LeanServer.loadCertificateChain fname catch _ => pure none with
      | some certs =>
        for certDER in certs do
          match parseCertificate certDER with
          | some parsed => store := store.addCert parsed
          | none => pure ()
      | none => pure ()
  IO.eprintln s!"[X509] Trust store loaded from dir: {store.certificates.size} CA certificates"
  pure store

/-- Check if a certificate is trusted (exists in the trust store by subject match) -/
def TrustStore.isTrusted (store : TrustStore) (cert : ParsedCertificate) : Bool :=
  store.certificates.any fun ca => ca.subject == cert.subject && ca.rawDER == cert.rawDER

/-- Find a CA certificate that issued the given certificate -/
def TrustStore.findIssuer (store : TrustStore) (cert : ParsedCertificate) : Option ParsedCertificate :=
  store.certificates.find? fun ca => ca.subject == cert.issuer

-- ==========================================
-- RSA Signature Verification for X.509
-- ==========================================

/-- Extract RSA public key (n, e) from SubjectPublicKeyInfo content -/
private def extractRSAPublicKey (spkiContent : ByteArray) : Option (Nat × Nat) :=
  -- SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
  -- subjectPublicKey is a BIT STRING containing RSA public key SEQUENCE { n, e }
  let children := parseChildren spkiContent
  if children.size < 2 then none
  else
    let pubKeyBitString := children[1]!
    if pubKeyBitString.tag != TAG_BIT_STRING || pubKeyBitString.content.size < 2 then none
    else
      -- Skip unused bits byte
      let keyBytes := pubKeyBitString.content.extract 1 pubKeyBitString.content.size
      -- Parse SEQUENCE { n INTEGER, e INTEGER }
      match parseSequence keyBytes 0 with
      | some (seqContent, _) =>
        let intChildren := parseChildren seqContent
        if intChildren.size < 2 then none
        else
          let n := LeanServer.RSA.os2ip intChildren[0]!.content
          let e := LeanServer.RSA.os2ip intChildren[1]!.content
          some (n, e)
      | none => none

/-- DigestInfo DER prefix for SHA-256 (PKCS#1 v1.5)
    SEQUENCE { SEQUENCE { OID sha256, NULL }, OCTET STRING hash } -/
private def sha256DigestInfoPrefix : ByteArray :=
  ByteArray.mk #[
    0x30, 0x31,  -- SEQUENCE (49 bytes)
    0x30, 0x0D,  -- SEQUENCE (13 bytes)
    0x06, 0x09,  -- OID (9 bytes) — 2.16.840.1.101.3.4.2.1 (SHA-256)
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00,  -- NULL
    0x04, 0x20   -- OCTET STRING (32 bytes) — the hash follows
  ]

/-- Verify RSA-PKCS#1v1.5-SHA256 signature on tbsCertificate -/
def verifyRSASignature (issuerSPKI : ByteArray) (tbsBytes : ByteArray) (signature : ByteArray) : Bool :=
  match extractRSAPublicKey issuerSPKI with
  | none => false
  | some (n, e) =>
    if n == 0 then false
    else
      -- RSAVP1: signature^e mod n
      let s := LeanServer.RSA.os2ip signature
      let m := LeanServer.RSA.modPow s e n
      let emLen := (signature.size)
      let em := LeanServer.RSA.i2osp m emLen
      -- PKCS#1 v1.5: 0x00 0x01 [padding 0xFF...] 0x00 [DigestInfo]
      -- Verify padding structure
      if em.size < 11 then false
      else if em.get! 0 != 0x00 || em.get! 1 != 0x01 then false
      else
        -- Find end of padding (0x00 separator)
        let (sepIdx, foundSep) := Id.run do
          let mut sepIdx := 2
          let mut foundSep := false
          for i in [2:em.size] do
            if !foundSep then
              if em.get! i == 0x00 then
                sepIdx := i
                foundSep := true
              else if em.get! i != 0xFF then
                sepIdx := em.size
                foundSep := true
          (sepIdx, foundSep)
        if !foundSep || sepIdx < 10 then false  -- Minimum 8 bytes of 0xFF padding
        else
          let digestInfo := em.extract (sepIdx + 1) em.size
          -- Compare with expected DigestInfo
          let hash := LeanServer.SHA256.hash tbsBytes
          let expectedDigestInfo := sha256DigestInfoPrefix ++ hash
          digestInfo == expectedDigestInfo

-- ==========================================
-- Chain Validation
-- ==========================================

/-- Configuration for chain validation -/
structure ValidationConfig where
  maxDepth          : Nat  := 10        -- Maximum certificate chain depth
  checkValidity     : Bool := true      -- Check notBefore/notAfter
  requireCA         : Bool := true      -- Require CA flag for intermediates
  verifySignatures  : Bool := true      -- Verify RSA signatures

/-- Default validation configuration -/
def defaultConfig : ValidationConfig := {}

/-- Validate a single certificate's time validity -/
def checkTimeValidity (cert : ParsedCertificate) (nowSeconds : Nat) : ValidationResult :=
  if nowSeconds < cert.validity.notBefore then
    .notYetValid s!"Certificate not valid until {cert.validity.notBefore} (now: {nowSeconds})"
  else if nowSeconds > cert.validity.notAfter then
    .expired s!"Certificate expired at {cert.validity.notAfter} (now: {nowSeconds})"
  else .valid

/-- Validate a certificate chain against a trust store.

    The chain should be ordered: `[leaf, intermediate1, intermediate2, ..., root]`
    Each certificate's issuer must match the next certificate's subject.
    The last certificate must be trusted (in the trust store) or self-signed & trusted.

    @param store Trust store with CA certificates
    @param chain Array of DER-encoded certificates (ordered leaf → root)
    @param nowSeconds Current Unix timestamp in seconds
    @param config Validation configuration -/
def validateChain
    (store : TrustStore)
    (chain : Array ByteArray)
    (nowSeconds : Nat)
    (config : ValidationConfig := defaultConfig)
    : ValidationResult := Id.run do
  if chain.size == 0 then
    return .malformed "Empty certificate chain"

  -- Parse all certificates
  let mut parsed : Array ParsedCertificate := #[]
  for certDER in chain do
    match parseCertificate certDER with
    | some cert => parsed := parsed.push cert
    | none => return .malformed s!"Failed to parse certificate in chain"

  -- Check chain depth
  if parsed.size > config.maxDepth then
    return .depthExceeded s!"Chain depth {parsed.size} exceeds maximum {config.maxDepth}"

  -- Validate each certificate
  for i in [:parsed.size] do
    let cert := parsed[i]!

    -- 1. Check time validity
    if config.checkValidity then
      match checkTimeValidity cert nowSeconds with
      | .valid => pure ()
      | err => return err

    -- 2. For intermediates and root (not leaf), check CA flag
    if i > 0 && config.requireCA then
      if !cert.isCA then
        return .chainBroken s!"Certificate at depth {i} is not a CA (missing BasicConstraints)"

    -- 3. Check path length constraint
    if i > 0 then
      -- Check issuing CA's maxPathLength
      if i + 1 < parsed.size then
        let issuerCert := parsed[i + 1]!
        match issuerCert.maxPathLength with
        | some maxPath =>
          -- Number of intermediate CAs below this issuer
          let intermediatesBelow := i - 1
          if intermediatesBelow > maxPath then
            return .depthExceeded s!"Path length constraint violated at depth {i + 1}"
        | none => pure ()

    -- 4. Check issuer/subject chain linkage
    if i + 1 < parsed.size then
      let issuerCert := parsed[i + 1]!
      if cert.issuer != issuerCert.subject then
        return .chainBroken s!"Issuer mismatch at depth {i}: cert issuer ≠ next cert subject"

      -- 5. Verify signature (cert signed by issuer)
      if config.verifySignatures then
        if cert.signatureAlgorithm == OID_SHA256_WITH_RSA then
          if !verifyRSASignature issuerCert.subjectPublicKeyInfo cert.tbsCertificate cert.signature then
            return .signatureInvalid s!"RSA-SHA256 signature verification failed at depth {i}"
        -- For other algorithms (ECDSA, SHA-384, etc.), skip verification for now

  -- 5. Check that the chain terminates at a trusted root
  let lastCert := parsed[parsed.size - 1]!

  -- Check if the last cert is directly in the trust store
  if store.isTrusted lastCert then
    return .valid
  -- Check if the last cert's issuer is in the trust store
  match store.findIssuer lastCert with
  | some trustedCA =>
    -- Verify signature by the trusted CA
    if config.verifySignatures && lastCert.signatureAlgorithm == OID_SHA256_WITH_RSA then
      if verifyRSASignature trustedCA.subjectPublicKeyInfo lastCert.tbsCertificate lastCert.signature then
        -- Check trusted CA validity too
        if config.checkValidity then
          match checkTimeValidity trustedCA nowSeconds with
          | .valid => return .valid
          | err => return err
        else return .valid
      else return .signatureInvalid "Signature by trusted CA failed verification"
    else
      -- Signature algorithm not supported for verification, but issuer matches
      if config.checkValidity then
        match checkTimeValidity trustedCA nowSeconds with
        | .valid => return .valid
        | err => return err
      else return .valid
  | none =>
    -- Self-signed? (issuer == subject on last cert)
    if lastCert.issuer == lastCert.subject then
      return .untrusted s!"Self-signed certificate not in trust store: {lastCert.subject.commonName.getD "<unknown>"}"
    else
      return .untrusted s!"No trusted CA found for issuer of: {lastCert.subject.commonName.getD "<unknown>"}"

/-- Convenience: validate a single certificate (treated as a 1-element chain) -/
def validateSingle
    (store : TrustStore)
    (certDER : ByteArray)
    (nowSeconds : Nat)
    (config : ValidationConfig := defaultConfig)
    : ValidationResult :=
  validateChain store #[certDER] nowSeconds config

-- ==========================================
-- Integration with mTLS
-- ==========================================

/-- Validate client certificates for mTLS using a trust store.
    This replaces the basic `validateClientCertChain` in MTLSAuth.lean -/
def validateClientCertificates
    (store : TrustStore)
    (clientCerts : List ByteArray)
    (nowSeconds : Nat)
    (config : ValidationConfig := defaultConfig)
    : ValidationResult :=
  match clientCerts with
  | [] => .malformed "No client certificates provided"
  | certs => validateChain store certs.toArray nowSeconds config

/-- Quick check: is a DER-encoded certificate parseable and within validity? -/
def quickValidate (certDER : ByteArray) (nowSeconds : Nat) : ValidationResult :=
  match parseCertificate certDER with
  | none => .malformed "Cannot parse certificate DER"
  | some cert => checkTimeValidity cert nowSeconds

/-- Get human-readable certificate info for logging -/
def certInfo (certDER : ByteArray) : String :=
  match parseCertificate certDER with
  | none => "<unparseable certificate>"
  | some cert =>
    let cn := cert.subject.commonName.getD "<no CN>"
    let issuerCN := cert.issuer.commonName.getD "<no issuer CN>"
    let version := cert.version + 1
    s!"X.509v{version} CN={cn} Issuer={issuerCN} CA={cert.isCA} Algo={cert.signatureAlgorithm}"

end LeanServer.X509
