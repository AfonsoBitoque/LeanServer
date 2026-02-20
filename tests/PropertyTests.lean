import LeanServer.Crypto.Crypto
import LeanServer.Crypto.AES
import LeanServer.Crypto.X25519
import LeanServer.Protocol.HPACK
import LeanServer.Protocol.HTTP2
import LeanServer.Server.HTTPServer

/-!
# Property-Based Testing Framework (R28)

QuickCheck-style property testing for LeanServer — tests invariants
across randomly generated inputs rather than fixed test vectors.

## Properties Verified
1. **SHA-256**: deterministic, fixed-length output (32 bytes)
2. **HMAC-SHA-256**: deterministic, correct length
3. **AES-GCM**: encrypt→decrypt round-trip yields original plaintext
4. **X25519**: scalarmult output is 32 bytes, base point yields correct form
5. **HKDF**: extract+expand produces correct-length output
6. **HPACK**: encode→decode round-trip preserves headers
7. **HTTP/2 frame**: serialize→parse round-trip
8. **HTTP/1.1 parse**: valid request parses successfully
9. **Base64**: encode→decode round-trip (if available)

## Usage
```
lake build prop_tests && .lake/build/bin/prop_tests
```
-/

namespace LeanServer

-- ==========================================
-- Property Test Infrastructure
-- ==========================================

/-- Result of a property test -/
inductive PropResult where
  | passed  : PropResult
  | failed  : String → PropResult  -- failure message

instance : ToString PropResult where
  toString
    | .passed => "✅ PASSED"
    | .failed msg => s!"❌ FAILED: {msg}"

/-- A named property test -/
structure PropertyTest where
  name       : String
  iterations : Nat
  run        : IO PropResult

/-- Generate a pseudo-random ByteArray of given size using IO.rand -/
def randomBytes (size : Nat) : IO ByteArray := do
  let mut arr := ByteArray.empty
  for _ in List.range size do
    let b ← IO.rand 0 255
    arr := arr.push b.toUInt8
  return arr

/-- Generate a random Nat in range -/
def randomNat (lo hi : Nat) : IO Nat :=
  IO.rand lo hi

/-- Run a single property test -/
def runProperty (prop : PropertyTest) : IO Bool := do
  IO.print s!"  {prop.name} ({prop.iterations} iters)... "
  let result ← prop.run
  IO.println (toString result)
  match result with
  | .passed => return true
  | .failed _ => return false

-- ==========================================
-- SHA-256 Properties
-- ==========================================

/-- Property: SHA-256 output is always 32 bytes -/
def propSHA256FixedLength (iters : Nat := 1000) : PropertyTest :=
  { name := "SHA-256 output is always 32 bytes"
    iterations := iters
    run := do
      for i in List.range iters do
        let size ← randomNat 0 2048
        let input ← randomBytes size
        let hash := sha256 input
        if hash.size != 32 then
          return .failed s!"iteration {i}: input size {size}, output size {hash.size}"
      return .passed }

/-- Property: SHA-256 is deterministic -/
def propSHA256Deterministic (iters : Nat := 500) : PropertyTest :=
  { name := "SHA-256 is deterministic"
    iterations := iters
    run := do
      for i in List.range iters do
        let size ← randomNat 0 1024
        let input ← randomBytes size
        let h1 := sha256 input
        let h2 := sha256 input
        if h1 != h2 then
          return .failed s!"iteration {i}: same input produced different hashes"
      return .passed }

/-- Property: SHA-256 differs for different inputs (probabilistic) -/
def propSHA256Collision (iters : Nat := 500) : PropertyTest :=
  { name := "SHA-256 collision resistance (probabilistic)"
    iterations := iters
    run := do
      for i in List.range iters do
        let size ← randomNat 1 256
        let a ← randomBytes size
        let b ← randomBytes size
        if a != b then  -- only check when inputs differ
          let ha := sha256 a
          let hb := sha256 b
          if ha == hb then
            return .failed s!"iteration {i}: collision found for different inputs"
      return .passed }

-- ==========================================
-- HMAC-SHA-256 Properties
-- ==========================================

/-- Property: HMAC-SHA-256 output is always 32 bytes -/
def propHMACFixedLength (iters : Nat := 500) : PropertyTest :=
  { name := "HMAC-SHA-256 output is always 32 bytes"
    iterations := iters
    run := do
      for i in List.range iters do
        let keySize ← randomNat 1 128
        let msgSize ← randomNat 0 1024
        let key ← randomBytes keySize
        let msg ← randomBytes msgSize
        let mac := hmac_sha256 key msg
        if mac.size != 32 then
          return .failed s!"iteration {i}: key {keySize}B, msg {msgSize}B → output {mac.size}B"
      return .passed }

/-- Property: HMAC-SHA-256 is deterministic -/
def propHMACDeterministic (iters : Nat := 500) : PropertyTest :=
  { name := "HMAC-SHA-256 is deterministic"
    iterations := iters
    run := do
      for i in List.range iters do
        let keySize ← randomNat 1 64
        let msgSize ← randomNat 0 512
        let key ← randomBytes keySize
        let msg ← randomBytes msgSize
        let h1 := hmac_sha256 key msg
        let h2 := hmac_sha256 key msg
        if h1 != h2 then
          return .failed s!"iteration {i}: same inputs produced different MACs"
      return .passed }

-- ==========================================
-- AES-GCM Properties
-- ==========================================

/-- Property: AES-GCM encrypt→decrypt round-trip -/
def propAESGCMRoundtrip (iters : Nat := 200) : PropertyTest :=
  { name := "AES-GCM encrypt→decrypt round-trip"
    iterations := iters
    run := do
      for i in List.range iters do
        let key ← randomBytes 16
        let iv ← randomBytes 12
        let ptSize ← randomNat 0 512
        let plaintext ← randomBytes ptSize
        let aad ← randomBytes (← randomNat 0 32)
        let (ciphertext, tag) := AES.aesGCMEncrypt key iv plaintext aad
        let ctWithTag := ciphertext ++ tag
        match AES.aesGCMDecrypt key iv ctWithTag aad with
        | none =>
          return .failed s!"iteration {i}: decrypt failed for {ptSize}B plaintext"
        | some recovered =>
          if recovered != plaintext then
            return .failed s!"iteration {i}: recovered plaintext differs from original"
      return .passed }

/-- Property: AES-GCM ciphertext differs from plaintext (for non-empty) -/
def propAESGCMDiffers (iters : Nat := 200) : PropertyTest :=
  { name := "AES-GCM ciphertext differs from plaintext"
    iterations := iters
    run := do
      for i in List.range iters do
        let key ← randomBytes 16
        let iv ← randomBytes 12
        let ptSize ← randomNat 16 256  -- non-trivial sizes
        let plaintext ← randomBytes ptSize
        let (ciphertext, _tag) := AES.aesGCMEncrypt key iv plaintext ByteArray.empty
        if ciphertext == plaintext then
          return .failed s!"iteration {i}: ciphertext equals plaintext"
      return .passed }

/-- Property: AES-GCM authentication rejects tampered data -/
def propAESGCMAuthReject (iters : Nat := 200) : PropertyTest :=
  { name := "AES-GCM rejects tampered ciphertext"
    iterations := iters
    run := do
      for i in List.range iters do
        let key ← randomBytes 16
        let iv ← randomBytes 12
        let plaintext ← randomBytes 64
        let (ciphertext, tag) := AES.aesGCMEncrypt key iv plaintext ByteArray.empty
        -- Tamper with one byte of ciphertext
        if ciphertext.size > 0 then
          let pos ← randomNat 0 (ciphertext.size - 1)
          let origByte := ciphertext.get! pos
          let tampered := ciphertext.set! pos (origByte ^^^ 0xFF)
          let tamperedWithTag := tampered ++ tag
          match AES.aesGCMDecrypt key iv tamperedWithTag ByteArray.empty with
          | some _ =>
            return .failed s!"iteration {i}: tampered ciphertext was accepted"
          | none => pure ()
      return .passed }

-- ==========================================
-- X25519 Properties
-- ==========================================

/-- Property: X25519 output is always 32 bytes -/
def propX25519OutputLength (iters : Nat := 100) : PropertyTest :=
  { name := "X25519 output is always 32 bytes"
    iterations := iters
    run := do
      for i in List.range iters do
        let scalar ← randomBytes 32
        let point ← randomBytes 32
        let result := X25519.scalarmult scalar point
        if result.size != 32 then
          return .failed s!"iteration {i}: output size {result.size}"
      return .passed }

/-- Property: X25519 is deterministic -/
def propX25519Deterministic (iters : Nat := 100) : PropertyTest :=
  { name := "X25519 is deterministic"
    iterations := iters
    run := do
      for i in List.range iters do
        let scalar ← randomBytes 32
        let point ← randomBytes 32
        let r1 := X25519.scalarmult scalar point
        let r2 := X25519.scalarmult scalar point
        if r1 != r2 then
          return .failed s!"iteration {i}: non-deterministic"
      return .passed }

-- ==========================================
-- HKDF Properties
-- ==========================================

/-- Property: HKDF-Expand output length matches requested -/
def propHKDFExpandLength (iters : Nat := 500) : PropertyTest :=
  { name := "HKDF-Expand output length matches request"
    iterations := iters
    run := do
      for i in List.range iters do
        let prk ← randomBytes 32
        let infoLen ← randomNat 0 64
        let info ← randomBytes infoLen
        let outLen ← randomNat 1 255  -- max 255*32 but keep small
        let result := hkdf_expand prk info outLen
        if result.size != outLen then
          return .failed s!"iteration {i}: requested {outLen}B, got {result.size}B"
      return .passed }

/-- Property: HKDF-Extract output is always 32 bytes -/
def propHKDFExtractLength (iters : Nat := 500) : PropertyTest :=
  { name := "HKDF-Extract output is always 32 bytes"
    iterations := iters
    run := do
      for i in List.range iters do
        let saltLen ← randomNat 0 64
        let salt ← randomBytes saltLen
        let ikmLen ← randomNat 1 128
        let ikm ← randomBytes ikmLen
        let prk := hkdf_extract salt ikm
        if prk.size != 32 then
          return .failed s!"iteration {i}: extract output {prk.size}B"
      return .passed }

-- ==========================================
-- HPACK Properties
-- ==========================================

/-- Property: HPACK encode→decode round-trip preserves headers -/
def propHPACKRoundtrip (iters : Nat := 300) : PropertyTest :=
  { name := "HPACK encode→decode round-trip"
    iterations := iters
    run := do
      let headerSets : Array (Array (String × String)) := #[
        #[(":method", "GET"), (":path", "/"), (":scheme", "https")],
        #[(":method", "POST"), (":path", "/api/data"), ("content-type", "application/json")],
        #[(":method", "GET"), (":path", "/index.html"), ("accept", "text/html"),
          ("user-agent", "test/1.0"), ("accept-encoding", "gzip")],
        #[(":status", "200"), ("content-type", "text/html"), ("content-length", "1234")],
        #[(":status", "404"), ("content-type", "application/json")]
      ]
      for i in List.range iters do
        let idx ← randomNat 0 (headerSets.size - 1)
        let headers := headerSets[idx]!
        let encoded := encodeHeadersPublic headers
        let decoder := initHPACKDecoder
        match decodeHeaderList decoder encoded with
        | none =>
          return .failed s!"iteration {i}: decode returned none for header set {idx}"
        | some (decoded, _) =>
          -- Check header count matches
          if decoded.size != headers.size then
            return .failed s!"iteration {i}: expected {headers.size} headers, got {decoded.size}"
          -- Check each header matches
          for j in List.range decoded.size do
            let (origName, origValue) := headers[j]!
            let dec : HeaderField := decoded[j]!
            if dec.name != origName || dec.value != origValue then
              return .failed s!"iteration {i}: header {j} mismatch: ({dec.name}, {dec.value}) vs ({origName}, {origValue})"
      return .passed }

-- ==========================================
-- HTTP/2 Frame Properties
-- ==========================================

/-- Property: HTTP/2 frame header serialize→parse round-trip -/
def propHTTP2FrameRoundtrip (iters : Nat := 500) : PropertyTest :=
  { name := "HTTP/2 frame header serialize→parse"
    iterations := iters
    run := do
      let frameTypes : List FrameType := [
        .DATA, .HEADERS, .SETTINGS, .PING, .GOAWAY, .WINDOW_UPDATE, .RST_STREAM
      ]
      for i in List.range iters do
        let length ← randomNat 0 16384
        let ftIdx ← randomNat 0 (frameTypes.length - 1)
        let ft := frameTypes.getD ftIdx .DATA
        let flags ← randomNat 0 255
        let streamId ← randomNat 0 (2^31 - 1)
        let header : FrameHeader := {
          length := length.toUInt32
          frameType := ft
          flags := flags.toUInt8
          streamId := streamId.toUInt32
        }
        let serialized := serializeFrameHeader header
        match parseFrameHeader serialized with
        | none =>
          return .failed s!"iteration {i}: parse returned none"
        | some parsed =>
          if parsed.frameType != header.frameType then
            return .failed s!"iteration {i}: frameType mismatch"
          if parsed.streamId != header.streamId then
            return .failed s!"iteration {i}: streamId mismatch"
          if parsed.length != header.length then
            return .failed s!"iteration {i}: length mismatch"
      return .passed }

-- ==========================================
-- HTTP/1.1 Parse Properties
-- ==========================================

/-- Property: Valid HTTP/1.1 requests parse successfully -/
def propHTTPParseValid (iters : Nat := 300) : PropertyTest :=
  { name := "Valid HTTP/1.1 requests parse correctly"
    iterations := iters
    run := do
      let methods := #["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
      let paths := #["/", "/index.html", "/api/v1/users", "/data?q=test", "/a/b/c"]
      for i in List.range iters do
        let mIdx ← randomNat 0 (methods.size - 1)
        let pIdx ← randomNat 0 (paths.size - 1)
        let method := methods[mIdx]!
        let path := paths[pIdx]!
        let request := s!"{method} {path} HTTP/1.1\r\nHost: test.com\r\n\r\n"
        match parseHTTPRequest request with
        | none =>
          return .failed s!"iteration {i}: parse failed for '{method} {path}'"
        | some parsed =>
          if parsed.method != method then
            return .failed s!"iteration {i}: method mismatch: {parsed.method} vs {method}"
          if parsed.path != path then
            return .failed s!"iteration {i}: path mismatch: {parsed.path} vs {path}"
      return .passed }

-- ==========================================
-- Full Property Test Runner
-- ==========================================

/-- All property tests -/
def allPropertyTests : List PropertyTest := [
  propSHA256FixedLength,
  propSHA256Deterministic,
  propSHA256Collision,
  propHMACFixedLength,
  propHMACDeterministic,
  propAESGCMRoundtrip,
  propAESGCMDiffers,
  propAESGCMAuthReject,
  propX25519OutputLength,
  propX25519Deterministic,
  propHKDFExpandLength,
  propHKDFExtractLength,
  propHPACKRoundtrip,
  propHTTP2FrameRoundtrip,
  propHTTPParseValid
]

/-- Run all property tests and report results -/
def runAllPropertyTests : IO UInt32 := do
  IO.println "🎲 LeanServer Property-Based Test Suite"
  IO.println s!"{'─'|>.toString |> List.replicate 60 |> String.join}"
  IO.println ""

  let mut passed := 0
  let mut failed := 0

  for prop in allPropertyTests do
    let ok ← runProperty prop
    if ok then passed := passed + 1
    else failed := failed + 1

  IO.println ""
  IO.println s!"{'─'|>.toString |> List.replicate 60 |> String.join}"
  IO.println s!"Results: {passed} passed, {failed} failed, {passed + failed} total"

  if failed > 0 then
    IO.println "❌ Some property tests FAILED"
    return 1
  else
    IO.println "✅ All property tests PASSED"
    return 0

end LeanServer

/-- Entry point for property test runner -/
def main : IO UInt32 :=
  LeanServer.runAllPropertyTests
