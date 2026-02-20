import LeanServer.Protocol.HPACK
import LeanServer.Protocol.HTTP2
import LeanServer.Protocol.QUIC
import LeanServer.Crypto.AES
import LeanServer.Crypto.Crypto
import LeanServer.Crypto.SHA256
import Init.System.IO

/-!
# Extended Fuzzing & Mutation Tests (ROADMAP F1.6)

Extends the existing property-based testing framework with:
1. **Differential testing** — HPACK encode/decode consistency checks
2. **Mutation testing** — verify that synthetic bugs are detected
3. **Boundary value** fuzzing — edge cases at protocol limits
4. **Cross-module** invariant checks — multi-step pipeline consistency
-/

open LeanServer

-- ═══════════════════════════════════════════════════════════
-- Infrastructure
-- ═══════════════════════════════════════════════════════════

def randomBytes (maxLen : Nat) : IO ByteArray := do
  let len ← IO.rand 0 maxLen
  let mut bs := ByteArray.empty
  for _ in [:len] do
    let b ← IO.rand 0 255
    bs := bs.push b.toUInt8
  return bs

def randomAsciiString (maxLen : Nat) : IO String := do
  let len ← IO.rand 0 maxLen
  let mut s := ""
  for _ in [:len] do
    let c ← IO.rand 0x20 0x7E  -- printable ASCII
    s := s.push (Char.ofNat c)
  return s

def assert (name : String) (cond : Bool) : IO Bool := do
  if cond then
    return true
  else
    IO.println s!"    ❌ FAIL: {name}"
    return false

-- ═══════════════════════════════════════════════════════════
-- Suite 1: HPACK Differential Testing
-- ═══════════════════════════════════════════════════════════

/-- Test that HPACK integer encoding is self-consistent across prefix sizes -/
def testHPACKIntegerSelfConsistency (iterations : Nat) : IO Bool := do
  IO.println "  ── HPACK Integer Self-Consistency ──"
  let mut allPass := true
  for _ in [:iterations] do
    let value ← IO.rand 0 65535
    for pfx in [5, 6, 7, 8] do
      let encoded := encodeInteger value pfx 0x00
      let decoded := decodeInteger encoded 0 pfx
      match decoded with
      | some (v, _) =>
        if v != value then
          IO.println s!"    ❌ HPACK int roundtrip failed: {value} with pfx {pfx} → {v}"
          allPass := false
      | none =>
        IO.println s!"    ❌ HPACK int decode failed: {value} with pfx {pfx}"
        allPass := false
  if allPass then IO.println s!"    ✅ {iterations} HPACK integer roundtrips OK (prefixes 5-8)"
  return allPass

/-- Test that HPACK string encoding preserves content -/
def testHPACKStringSelfConsistency (iterations : Nat) : IO Bool := do
  IO.println "  ── HPACK String Self-Consistency ──"
  let mut allPass := true
  for _ in [:iterations] do
    let s ← randomAsciiString 64
    -- Non-Huffman encoding
    let encoded := encodeString s
    let decoded := decodeString encoded 0
    match decoded with
    | some (decodedStr, _) =>
      if decodedStr != s then
        IO.println s!"    ❌ HPACK string roundtrip failed for: {s}"
        allPass := false
    | none =>
      IO.println s!"    ❌ HPACK string decode failed for: {s}"
      allPass := false
  if allPass then IO.println s!"    ✅ {iterations} HPACK string roundtrips OK"
  return allPass

-- ═══════════════════════════════════════════════════════════
-- Suite 2: Mutation Testing
-- ═══════════════════════════════════════════════════════════

/-- Verify that flipping bits in encrypted data causes decryption to fail -/
def testAESGCMBitFlipDetection (iterations : Nat) : IO Bool := do
  IO.println "  ── AES-GCM Bit Flip Detection ──"
  let mut detected := 0
  let mut total := 0
  let key := ByteArray.mk #[0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                             0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10]
  let iv := ByteArray.mk #[0xCA,0xFE,0xBA,0xBE,0xDE,0xAD,0xBE,0xEF,0x01,0x02,0x03,0x04]
  for _ in [:iterations] do
    let plaintext ← randomBytes 64
    if plaintext.size == 0 then continue
    let (ciphertext, tag) := AES.aesGCMEncrypt key iv plaintext ByteArray.empty
    let encrypted := ciphertext ++ tag
    if encrypted.size < 2 then continue
    total := total + 1
    -- Flip a random bit in the ciphertext
    let flipPos ← IO.rand 0 (encrypted.size - 1)
    let mut tampered := encrypted
    let origByte := tampered.get! flipPos
    tampered := tampered.set! flipPos (origByte ^^^ 0x01)
    -- Decryption should fail or produce different output
    let decrypted := AES.aesGCMDecrypt key iv tampered ByteArray.empty
    if decrypted != some plaintext then
      detected := detected + 1
  let rate := if total > 0 then detected * 100 / total else 0
  IO.println s!"    Detection rate: {detected}/{total} ({rate}%)"
  let ok := rate >= 95  -- Should detect at least 95% of bit flips
  if ok then IO.println s!"    ✅ Bit flip detection rate ≥ 95%"
  else IO.println s!"    ❌ Bit flip detection rate < 95%"
  return ok

/-- Verify that modified HTTP/2 frames don't parse as original -/
def testHTTP2FrameMutation (iterations : Nat) : IO Bool := do
  IO.println "  ── HTTP/2 Frame Mutation Detection ──"
  let mut detected := 0
  let mut total := 0
  for _ in [:iterations] do
    -- Create a valid frame
    let streamId ← IO.rand 1 1000
    let payload ← randomBytes 32
    let frame := createHTTP2Frame FrameType.DATA 0x00 streamId.toUInt32 payload
    let serialized := serializeHTTP2Frame frame
    if serialized.size < 10 then continue
    total := total + 1
    -- Mutate one byte in the payload area (after 9-byte header)
    let mutPos ← IO.rand 9 (serialized.size - 1)
    let mut mutated := serialized
    let origByte := mutated.get! mutPos
    mutated := mutated.set! mutPos (origByte ^^^ 0xFF)
    -- Parse the mutated frame
    match parseHTTP2Frame mutated with
    | some mutFrame =>
      if mutFrame.payload != frame.payload then
        detected := detected + 1
    | none => detected := detected + 1
  let rate := if total > 0 then detected * 100 / total else 0
  IO.println s!"    Detection rate: {detected}/{total} ({rate}%)"
  let ok := rate >= 90
  if ok then IO.println s!"    ✅ Frame mutation detection rate ≥ 90%"
  else IO.println s!"    ❌ Frame mutation detection rate < 90%"
  return ok

-- ═══════════════════════════════════════════════════════════
-- Suite 3: Boundary Value Fuzzing
-- ═══════════════════════════════════════════════════════════

/-- Test protocol limits: maximum frame size, minimum sizes, edge values -/
def testBoundaryValues : IO Bool := do
  IO.println "  ── Boundary Value Fuzzing ──"
  let mut allPass := true

  -- Empty inputs to all parsers
  let r1 ← assert "parseFrameHeader(empty) = none" (parseFrameHeader ByteArray.empty).isNone
  allPass := allPass && r1

  -- Exactly 9 bytes (minimum valid frame header)
  let minFrame := ByteArray.mk #[0x00,0x00,0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00]
  let r2 ← assert "9-byte frame header parseable" (parseFrameHeader minFrame).isSome
  allPass := allPass && r2

  -- 8 bytes (one short of valid)
  let shortFrame := ByteArray.mk #[0x00,0x00,0x00, 0x00, 0x00, 0x00,0x00,0x00]
  let r3 ← assert "8-byte frame → none" (parseFrameHeader shortFrame).isNone
  allPass := allPass && r3

  -- Maximum HPACK integer value that fits in 1 byte (prefix=5: 2^5-2=30)
  let encoded30 := encodeInteger 30 5 0x00
  let decoded30 := decodeInteger encoded30 0 5
  let r4 ← assert "HPACK int 30/5 fits 1 byte" (encoded30.size == 1 && decoded30.isSome)
  allPass := allPass && r4

  -- Value 31 with prefix=5 requires 2 bytes
  let encoded31 := encodeInteger 31 5 0x00
  let r5 ← assert "HPACK int 31/5 requires 2+ bytes" (encoded31.size > 1)
  allPass := allPass && r5

  -- QUIC VarInt edge values
  let enc63 := encodeVarInt (63 : UInt64)      -- max 1-byte
  let enc64 := encodeVarInt (64 : UInt64)      -- min 2-byte
  let enc16383 := encodeVarInt (16383 : UInt64)    -- max 2-byte
  let enc16384 := encodeVarInt (16384 : UInt64)    -- min 4-byte
  let r6 ← assert "VarInt 63 → 1 byte" (enc63.size == 1)
  let r7 ← assert "VarInt 64 → 2 bytes" (enc64.size == 2)
  let r8 ← assert "VarInt 16383 → 2 bytes" (enc16383.size == 2)
  let r9 ← assert "VarInt 16384 → 4 bytes" (enc16384.size == 4)
  allPass := allPass && r6 && r7 && r8 && r9

  -- FrameType boundary: byte 0x09 is max valid, 0x0A is invalid
  let r10 ← assert "FrameType 0x09 = CONTINUATION" (FrameType.fromByte 0x09).isSome
  let r11 ← assert "FrameType 0x0A = none" (FrameType.fromByte 0x0A).isNone
  allPass := allPass && r10 && r11

  if allPass then IO.println "    ✅ All boundary values passed"
  return allPass

-- ═══════════════════════════════════════════════════════════
-- Suite 4: Cross-Module Invariant Checks
-- ═══════════════════════════════════════════════════════════

/-- Verify that the full pipeline (create → serialize → parse) preserves invariants -/
def testCrossModuleInvariants (iterations : Nat) : IO Bool := do
  IO.println "  ── Cross-Module Pipeline Invariants ──"
  let mut allPass := true
  for _ in [:iterations] do
    let streamId ← IO.rand 1 1000
    let payload ← randomBytes 100
    -- Create → Serialize → Parse
    let frame := createHTTP2Frame FrameType.DATA 0x00 streamId.toUInt32 payload
    let serialized := serializeHTTP2Frame frame
    match parseHTTP2Frame serialized with
    | some parsed =>
      -- Invariant: streamId is preserved
      if parsed.header.streamId != streamId.toUInt32 then
        IO.println s!"    ❌ StreamId mismatch: {parsed.header.streamId} != {streamId}"
        allPass := false
      -- Invariant: payload is preserved
      if parsed.payload != payload then
        IO.println s!"    ❌ Payload mismatch at streamId {streamId}"
        allPass := false
      -- Invariant: frame type is preserved
      if parsed.header.frameType != FrameType.DATA then
        IO.println s!"    ❌ FrameType mismatch at streamId {streamId}"
        allPass := false
    | none =>
      IO.println s!"    ❌ Parse failed for streamId {streamId}, payload size {payload.size}"
      allPass := false
  if allPass then IO.println s!"    ✅ {iterations} pipeline invariant checks passed"
  return allPass

/-- Verify SHA-256 collision resistance (no two distinct random inputs produce same hash) -/
def testSHA256CollisionResistance (iterations : Nat) : IO Bool := do
  IO.println "  ── SHA-256 Collision Resistance ──"
  let mut seen : Array (ByteArray × ByteArray) := #[]  -- (input, hash) pairs
  let mut collisions := 0
  for i in [:iterations] do
    -- Use fixed 32-byte inputs with unique prefix to guarantee distinctness
    let suffix ← randomBytes 24
    let mut input := ByteArray.empty
    -- Encode iteration index as 8 bytes to ensure uniqueness
    for j in [:8] do
      input := input.push ((i >>> (j * 8)) % 256).toUInt8
    input := input ++ suffix
    let hash := sha256 input
    for (prevInput, prevHash) in seen do
      if prevHash == hash && prevInput != input then
        collisions := collisions + 1
    seen := seen.push (input, hash)
  let ok := collisions == 0
  if ok then IO.println s!"    ✅ {iterations} unique hashes, 0 collisions"
  else IO.println s!"    ❌ {collisions} collisions found!"
  return ok

-- ═══════════════════════════════════════════════════════════
-- Main
-- ═══════════════════════════════════════════════════════════

def main : IO UInt32 := do
  IO.println "╔══════════════════════════════════════════════════════════╗"
  IO.println "║     LeanServer6 — Extended Fuzz Tests (F1.6)           ║"
  IO.println "╚══════════════════════════════════════════════════════════╝"
  IO.println ""

  let mut suitesPassed := 0
  let mut suitesTotal := 0

  -- Suite 1: HPACK Differential Testing
  IO.println "▶ Suite 1: HPACK Differential Testing"
  suitesTotal := suitesTotal + 1
  let s1a ← testHPACKIntegerSelfConsistency 500
  let s1b ← testHPACKStringSelfConsistency 200
  if s1a && s1b then
    IO.println "  ✅ Suite passed"
    suitesPassed := suitesPassed + 1
  else IO.println "  ❌ Suite failed"
  IO.println ""

  -- Suite 2: Mutation Testing
  IO.println "▶ Suite 2: Mutation Testing"
  suitesTotal := suitesTotal + 1
  let s2a ← testAESGCMBitFlipDetection 100
  let s2b ← testHTTP2FrameMutation 200
  if s2a && s2b then
    IO.println "  ✅ Suite passed"
    suitesPassed := suitesPassed + 1
  else IO.println "  ❌ Suite failed"
  IO.println ""

  -- Suite 3: Boundary Value Fuzzing
  IO.println "▶ Suite 3: Boundary Value Fuzzing"
  suitesTotal := suitesTotal + 1
  let s3 ← testBoundaryValues
  if s3 then
    IO.println "  ✅ Suite passed"
    suitesPassed := suitesPassed + 1
  else IO.println "  ❌ Suite failed"
  IO.println ""

  -- Suite 4: Cross-Module Invariants
  IO.println "▶ Suite 4: Cross-Module Invariants"
  suitesTotal := suitesTotal + 1
  let s4a ← testCrossModuleInvariants 300
  let s4b ← testSHA256CollisionResistance 200
  if s4a && s4b then
    IO.println "  ✅ Suite passed"
    suitesPassed := suitesPassed + 1
  else IO.println "  ❌ Suite failed"
  IO.println ""

  IO.println "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  IO.println s!"  Result: {suitesPassed}/{suitesTotal} suites passed"
  IO.println "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  if suitesPassed == suitesTotal then
    IO.println "🎉 All extended fuzz tests passed!"
    return 0
  else
    IO.println "❌ Some suites failed!"
    return 1
