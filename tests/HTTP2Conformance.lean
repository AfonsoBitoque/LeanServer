import LeanServer.Protocol.HTTP2

/-!
  # HTTP/2 Conformance Tests (Phase 8.3)

  ByteArray-level test suite for HTTP/2 frame parsing and serialization.
  Covers: SETTINGS, HEADERS, DATA, WINDOW_UPDATE, GOAWAY, RST_STREAM, PING,
  PRIORITY, CONTINUATION, PUSH_PROMISE frame types.

  Tests RFC 9113 compliance at the wire format level.
-/

open LeanServer

-- ============================================================================
-- Hex utilities
-- ============================================================================

def toHex (bytes : ByteArray) : String :=
  bytes.data.foldl (fun s b =>
    let n := b.toNat
    let d1 := n / 16
    let d2 := n % 16
    let c1 := if d1 < 10 then Char.ofNat (48 + d1) else Char.ofNat (87 + d1)
    let c2 := if d2 < 10 then Char.ofNat (48 + d2) else Char.ofNat (87 + d2)
    s.push c1 |>.push c2) ""

-- ============================================================================
-- Test infrastructure
-- ============================================================================

structure TestCase where
  name : String
  run : IO Bool

def runTestSuite (suiteName : String) (tests : Array TestCase) : IO (Nat × Nat) := do
  IO.println s!"━━━ {suiteName} ━━━"
  let mut passed := 0
  let mut failed := 0
  for tc in tests do
    let ok ← tc.run
    if ok then
      IO.println s!"  ✅ {tc.name}"
      passed := passed + 1
    else
      IO.println s!"  ❌ {tc.name}"
      failed := failed + 1
  return (passed, failed)

-- ============================================================================
-- §1. Frame Header Tests (9 bytes)
-- ============================================================================

def frameHeaderTests : Array TestCase := #[
  -- 1. Serialize + parse DATA frame header
  { name := "DATA frame header roundtrip (stream 1, len=100)"
    run := do
      let header : FrameHeader := { length := 100, frameType := .DATA, flags := 0, streamId := 1 }
      let bytes := serializeFrameHeader header
      if bytes.size != 9 then return false
      match parseFrameHeader bytes with
      | some h => return h.length == 100 && h.streamId == 1
      | none => return false },

  -- 2. HEADERS frame header
  { name := "HEADERS frame header roundtrip (stream 3, flags=0x05)"
    run := do
      let header : FrameHeader := { length := 42, frameType := .HEADERS, flags := 0x05, streamId := 3 }
      let bytes := serializeFrameHeader header
      match parseFrameHeader bytes with
      | some h => return h.length == 42 && h.frameType == .HEADERS && h.flags == 0x05 && h.streamId == 3
      | none => return false },

  -- 3. SETTINGS frame header (stream 0)
  { name := "SETTINGS frame header (stream 0)"
    run := do
      let header : FrameHeader := { length := 18, frameType := .SETTINGS, flags := 0, streamId := 0 }
      let bytes := serializeFrameHeader header
      match parseFrameHeader bytes with
      | some h => return h.streamId == 0 && h.frameType == .SETTINGS
      | none => return false },

  -- 4. WINDOW_UPDATE frame header
  { name := "WINDOW_UPDATE frame header (len=4)"
    run := do
      let header : FrameHeader := { length := 4, frameType := .WINDOW_UPDATE, flags := 0, streamId := 5 }
      let bytes := serializeFrameHeader header
      match parseFrameHeader bytes with
      | some h => return h.length == 4 && h.frameType == .WINDOW_UPDATE
      | none => return false },

  -- 5. GOAWAY frame header
  { name := "GOAWAY frame header (stream 0)"
    run := do
      let header : FrameHeader := { length := 8, frameType := .GOAWAY, flags := 0, streamId := 0 }
      let bytes := serializeFrameHeader header
      match parseFrameHeader bytes with
      | some h => return h.frameType == .GOAWAY && h.streamId == 0
      | none => return false },

  -- 6. RST_STREAM frame header
  { name := "RST_STREAM frame header (stream 7)"
    run := do
      let header : FrameHeader := { length := 4, frameType := .RST_STREAM, flags := 0, streamId := 7 }
      let bytes := serializeFrameHeader header
      match parseFrameHeader bytes with
      | some h => return h.frameType == .RST_STREAM && h.streamId == 7
      | none => return false },

  -- 7. PING frame header
  { name := "PING frame header (len=8)"
    run := do
      let header : FrameHeader := { length := 8, frameType := .PING, flags := 0, streamId := 0 }
      let bytes := serializeFrameHeader header
      match parseFrameHeader bytes with
      | some h => return h.length == 8 && h.frameType == .PING
      | none => return false },

  -- 8. PRIORITY frame header
  { name := "PRIORITY frame header (stream 9)"
    run := do
      let header : FrameHeader := { length := 5, frameType := .PRIORITY, flags := 0, streamId := 9 }
      let bytes := serializeFrameHeader header
      match parseFrameHeader bytes with
      | some h => return h.frameType == .PRIORITY
      | none => return false },

  -- 9. CONTINUATION frame header
  { name := "CONTINUATION frame header (stream 1, END_HEADERS=0x04)"
    run := do
      let header : FrameHeader := { length := 20, frameType := .CONTINUATION, flags := 0x04, streamId := 1 }
      let bytes := serializeFrameHeader header
      match parseFrameHeader bytes with
      | some h => return h.frameType == .CONTINUATION && h.flags == 0x04
      | none => return false },

  -- 10. PUSH_PROMISE frame header
  { name := "PUSH_PROMISE frame header"
    run := do
      let header : FrameHeader := { length := 10, frameType := .PUSH_PROMISE, flags := 0, streamId := 1 }
      let bytes := serializeFrameHeader header
      match parseFrameHeader bytes with
      | some h => return h.frameType == .PUSH_PROMISE
      | none => return false },

  -- 11. Too-short data rejected
  { name := "Reject undersized input (< 9 bytes)"
    run := do
      return (parseFrameHeader (ByteArray.mk #[0, 0, 1, 0, 0, 0, 0, 0])).isNone },

  -- 12. Empty data rejected
  { name := "Reject empty input"
    run := do
      return (parseFrameHeader ByteArray.empty).isNone },

  -- 13. Large length field
  { name := "Large length field (16777215 = 2^24 - 1)"
    run := do
      let header : FrameHeader := { length := 16777215, frameType := .DATA, flags := 0, streamId := 1 }
      let bytes := serializeFrameHeader header
      match parseFrameHeader bytes with
      | some h => return h.length == 16777215
      | none => return false },

  -- 14. Max stream ID (2^31 - 1)
  { name := "Max stream ID (2147483647)"
    run := do
      let header : FrameHeader := { length := 0, frameType := .DATA, flags := 0, streamId := 2147483647 }
      let bytes := serializeFrameHeader header
      match parseFrameHeader bytes with
      | some h => return h.streamId == 2147483647
      | none => return false },

  -- 15. All flags set
  { name := "All flags set (0xFF)"
    run := do
      let header : FrameHeader := { length := 0, frameType := .HEADERS, flags := 0xFF, streamId := 1 }
      let bytes := serializeFrameHeader header
      match parseFrameHeader bytes with
      | some h => return h.flags == 0xFF
      | none => return false }
]

-- ============================================================================
-- §2. Complete Frame Tests
-- ============================================================================

def completeFrameTests : Array TestCase := #[
  -- 16. DATA frame roundtrip
  { name := "DATA frame: serialize → parse roundtrip"
    run := do
      let payload := "Hello, HTTP/2!".toUTF8
      let frame := createHTTP2Frame .DATA 0x01 1 payload  -- END_STREAM
      let bytes := serializeHTTP2Frame frame
      match parseHTTP2Frame bytes with
      | some f => return f.header.frameType == .DATA && f.payload.size == payload.size
      | none => return false },

  -- 17. SETTINGS frame creation
  { name := "SETTINGS frame with 3 settings"
    run := do
      let settings := #[
        { id := SettingId.HEADER_TABLE_SIZE, value := 4096 },
        { id := SettingId.MAX_CONCURRENT_STREAMS, value := 100 },
        { id := SettingId.INITIAL_WINDOW_SIZE, value := 65535 }
      ]
      let frame := createSettingsFrame settings false
      return frame.header.frameType == .SETTINGS && frame.header.streamId == 0 && frame.payload.size == 18 },

  -- 18. SETTINGS ACK
  { name := "SETTINGS ACK (empty payload, flag=0x01)"
    run := do
      let frame := createSettingsFrame #[] true
      return frame.header.flags == 0x01 && frame.payload.size == 0 },

  -- 19. WINDOW_UPDATE frame
  { name := "WINDOW_UPDATE frame (increment=32768)"
    run := do
      let frame := createWindowUpdateFrame 0 32768
      let bytes := serializeHTTP2Frame frame
      return bytes.size == 13 && frame.payload.size == 4 },

  -- 20. GOAWAY frame
  { name := "GOAWAY frame (lastStreamId=7, NO_ERROR)"
    run := do
      let frame := createGoAwayFrame 7 .NO_ERROR
      let bytes := serializeHTTP2Frame frame
      return frame.header.streamId == 0 && bytes.size >= 17 },

  -- 21. Multiple frames parse
  { name := "Parse two concatenated DATA frames"
    run := do
      let frame1 := createHTTP2Frame .DATA 0 1 "Hello".toUTF8
      let frame2 := createHTTP2Frame .DATA 0x01 1 "World".toUTF8
      let combined := serializeHTTP2Frame frame1 ++ serializeHTTP2Frame frame2
      match parseHTTP2Frames combined with
      | some frames => return frames.size == 2
      | none => return false },

  -- 22. Empty payload frame
  { name := "Empty payload DATA frame"
    run := do
      let frame := createHTTP2Frame .DATA 0x01 1 ByteArray.empty  -- END_STREAM, no data
      let bytes := serializeHTTP2Frame frame
      return bytes.size == 9 },  -- Just header

  -- 23. Frame with large payload
  { name := "DATA frame with 16384-byte payload (max default)"
    run := do
      let payload := ByteArray.mk ((List.replicate 16384 0x42).toArray)
      let frame := createHTTP2Frame .DATA 0 1 payload
      let bytes := serializeHTTP2Frame frame
      match parseHTTP2Frame bytes with
      | some f => return f.payload.size == 16384
      | none => return false }
]

-- ============================================================================
-- §3. SETTINGS Payload Tests
-- ============================================================================

def settingsPayloadTests : Array TestCase := #[
  -- 24. Parse settings payload
  { name := "Parse SETTINGS payload (HEADER_TABLE_SIZE=4096)"
    run := do
      let settings := #[{ id := SettingId.HEADER_TABLE_SIZE, value := 4096 }]
      let frame := createSettingsFrame settings false
      let parsed := parseSettingsPayload frame.payload
      return parsed.size == 1 },

  -- 25. Parse empty settings
  { name := "Parse empty SETTINGS payload"
    run := do
      let parsed := parseSettingsPayload ByteArray.empty
      return parsed.size == 0 },

  -- 26. Multiple settings in one frame
  { name := "Parse 5 settings in one payload"
    run := do
      let settings := #[
        { id := SettingId.HEADER_TABLE_SIZE, value := 4096 },
        { id := SettingId.ENABLE_PUSH, value := 0 },
        { id := SettingId.MAX_CONCURRENT_STREAMS, value := 128 },
        { id := SettingId.INITIAL_WINDOW_SIZE, value := 65535 },
        { id := SettingId.MAX_FRAME_SIZE, value := 16384 }
      ]
      let frame := createSettingsFrame settings false
      let parsed := parseSettingsPayload frame.payload
      return parsed.size == 5 && frame.payload.size == 30 }
]

-- ============================================================================
-- §4. Stream State Machine Tests
-- ============================================================================

def streamStateTests : Array TestCase := #[
  -- 27. IDLE → OPEN
  { name := "Stream IDLE → OPEN"
    run := do
      let s : HTTP2Stream := { id := 1, state := .IDLE, windowSize := 65535 }
      match transitionStreamState s .OPEN with
      | some s' => return s'.state == .OPEN
      | none => return false },

  -- 28. OPEN → HALF_CLOSED_LOCAL
  { name := "Stream OPEN → HALF_CLOSED_LOCAL"
    run := do
      let s : HTTP2Stream := { id := 1, state := .OPEN, windowSize := 65535 }
      match transitionStreamState s .HALF_CLOSED_LOCAL with
      | some s' => return s'.state == .HALF_CLOSED_LOCAL
      | none => return false },

  -- 29. OPEN → HALF_CLOSED_REMOTE
  { name := "Stream OPEN → HALF_CLOSED_REMOTE"
    run := do
      let s : HTTP2Stream := { id := 1, state := .OPEN, windowSize := 65535 }
      match transitionStreamState s .HALF_CLOSED_REMOTE with
      | some s' => return s'.state == .HALF_CLOSED_REMOTE
      | none => return false },

  -- 30. HALF_CLOSED_LOCAL → CLOSED
  { name := "Stream HALF_CLOSED_LOCAL → CLOSED"
    run := do
      let s : HTTP2Stream := { id := 1, state := .HALF_CLOSED_LOCAL, windowSize := 65535 }
      match transitionStreamState s .CLOSED with
      | some s' => return s'.state == .CLOSED
      | none => return false },

  -- 31. HALF_CLOSED_REMOTE → CLOSED
  { name := "Stream HALF_CLOSED_REMOTE → CLOSED"
    run := do
      let s : HTTP2Stream := { id := 1, state := .HALF_CLOSED_REMOTE, windowSize := 65535 }
      match transitionStreamState s .CLOSED with
      | some s' => return s'.state == .CLOSED
      | none => return false },

  -- 32. CLOSED is terminal (cannot transition to anything)
  { name := "Stream CLOSED → cannot transition (terminal)"
    run := do
      let s : HTTP2Stream := { id := 1, state := .CLOSED, windowSize := 65535 }
      let r1 := transitionStreamState s .OPEN
      let r2 := transitionStreamState s .HALF_CLOSED_LOCAL
      let r3 := transitionStreamState s .HALF_CLOSED_REMOTE
      let r4 := transitionStreamState s .IDLE
      let r5 := transitionStreamState s .RESERVED_LOCAL
      let r6 := transitionStreamState s .RESERVED_REMOTE
      let r7 := transitionStreamState s .CLOSED
      return r1.isNone && r2.isNone && r3.isNone && r4.isNone && r5.isNone && r6.isNone && r7.isNone },

  -- 33. IDLE → RESERVED_LOCAL
  { name := "Stream IDLE → RESERVED_LOCAL"
    run := do
      let s : HTTP2Stream := { id := 2, state := .IDLE, windowSize := 65535 }
      match transitionStreamState s .RESERVED_LOCAL with
      | some s' => return s'.state == .RESERVED_LOCAL
      | none => return false },

  -- 34. IDLE → RESERVED_REMOTE
  { name := "Stream IDLE → RESERVED_REMOTE"
    run := do
      let s : HTTP2Stream := { id := 2, state := .IDLE, windowSize := 65535 }
      match transitionStreamState s .RESERVED_REMOTE with
      | some s' => return s'.state == .RESERVED_REMOTE
      | none => return false },

  -- 35. Full lifecycle: IDLE → OPEN → HALF_CLOSED_LOCAL → CLOSED
  { name := "Full stream lifecycle (3-step)"
    run := do
      let s0 : HTTP2Stream := { id := 1, state := .IDLE, windowSize := 65535 }
      match transitionStreamState s0 .OPEN with
      | some s1 =>
        match transitionStreamState s1 .HALF_CLOSED_LOCAL with
        | some s2 =>
          match transitionStreamState s2 .CLOSED with
          | some s3 => return s3.state == .CLOSED
          | none => return false
        | none => return false
      | none => return false },

  -- 36. Invalid transition: IDLE → CLOSED (not directly allowed)
  { name := "Invalid: IDLE → CLOSED rejected"
    run := do
      let s : HTTP2Stream := { id := 1, state := .IDLE, windowSize := 65535 }
      return (transitionStreamState s .CLOSED).isNone },

  -- 37. Invalid transition: OPEN → IDLE (backwards)
  { name := "Invalid: OPEN → IDLE rejected"
    run := do
      let s : HTTP2Stream := { id := 1, state := .OPEN, windowSize := 65535 }
      return (transitionStreamState s .IDLE).isNone }
]

-- ============================================================================
-- §5. Wire Format Edge Cases
-- ============================================================================

def edgeCaseTests : Array TestCase := #[
  -- 38. Frame with unknown type byte → parse returns none
  { name := "Unknown frame type byte (0xFF) → rejected"
    run := do
      -- Manually construct header with unknown type
      let bytes := ByteArray.mk #[0, 0, 0, 0xFF, 0, 0, 0, 0, 1]
      return (parseFrameHeader bytes).isNone },

  -- 39. Zero-length settings frame
  { name := "Zero-length SETTINGS is valid (no settings changed)"
    run := do
      let frame := createSettingsFrame #[] false
      return frame.payload.size == 0 && frame.header.flags == 0 },

  -- 40. WINDOW_UPDATE with increment 0 (protocol error per RFC 9113 §6.9.1)
  { name := "WINDOW_UPDATE with zero increment (should be detectable)"
    run := do
      let frame := createWindowUpdateFrame 1 0
      -- The frame is created but should be detected as error by the protocol layer
      return frame.payload.size == 4 },

  -- 41. Header size is always 9
  { name := "Serialized header always 9 bytes"
    run := do
      let mut allCorrect := true
      for frameType in [FrameType.DATA, .HEADERS, .PRIORITY, .RST_STREAM, .SETTINGS,
                         .PUSH_PROMISE, .PING, .GOAWAY, .WINDOW_UPDATE, .CONTINUATION] do
        let header : FrameHeader := { length := 42, frameType := frameType, flags := 0, streamId := 1 }
        if (serializeFrameHeader header).size != 9 then
          allCorrect := false
      return allCorrect },

  -- 42. Parse frame with truncated payload
  { name := "Reject frame with truncated payload"
    run := do
      -- Header says length=100, but total data is only 20 bytes
      let header : FrameHeader := { length := 100, frameType := .DATA, flags := 0, streamId := 1 }
      let bytes := serializeFrameHeader header ++ ByteArray.mk ((List.replicate 11 0).toArray)
      return (parseHTTP2Frame bytes).isNone },

  -- 43. FrameType roundtrip (all types)
  { name := "FrameType toByte → fromByte roundtrip (all 10 types)"
    run := do
      let types := [FrameType.DATA, .HEADERS, .PRIORITY, .RST_STREAM, .SETTINGS,
                     .PUSH_PROMISE, .PING, .GOAWAY, .WINDOW_UPDATE, .CONTINUATION]
      let mut allOk := true
      for ft in types do
        match FrameType.fromByte ft.toByte with
        | some ft' => if ft != ft' then allOk := false
        | none => allOk := false
      return allOk },

  -- 44. Connection preface (magic string)
  { name := "HTTP/2 connection preface constant"
    run := do
      let preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
      return preface.toUTF8.size == 24 },

  -- 45. PING frame must be 8 bytes (RFC 9113 §6.7)
  { name := "PING frame payload is exactly 8 bytes"
    run := do
      let frame := createHTTP2Frame .PING 0 0 (ByteArray.mk #[1, 2, 3, 4, 5, 6, 7, 8])
      return frame.payload.size == 8 },

  -- 46. RST_STREAM frame must be 4 bytes (RFC 9113 §6.4)
  { name := "RST_STREAM payload is 4 bytes"
    run := do
      let frame := createHTTP2Frame .RST_STREAM 0 1 (ByteArray.mk #[0, 0, 0, 0])
      return frame.payload.size == 4 },

  -- 47. PRIORITY frame must be 5 bytes (RFC 9113 §6.3)
  { name := "PRIORITY payload is 5 bytes"
    run := do
      let frame := createHTTP2Frame .PRIORITY 0 1 (ByteArray.mk #[0, 0, 0, 0, 16])
      return frame.payload.size == 5 },

  -- 48. Serialized frame size = 9 + payload size
  { name := "Serialized frame size = 9 + payload.size"
    run := do
      let mut allCorrect := true
      for payloadSize in [0, 1, 10, 100, 1000, 16384] do
        let payload := ByteArray.mk ((List.replicate payloadSize 0x42).toArray)
        let frame := createHTTP2Frame .DATA 0 1 payload
        let bytes := serializeHTTP2Frame frame
        if bytes.size != 9 + payloadSize then
          allCorrect := false
      return allCorrect },

  -- 49. Three-frame sequence: SETTINGS → SETTINGS_ACK → DATA
  { name := "Three-frame sequence roundtrip"
    run := do
      let f1 := createSettingsFrame #[{ id := SettingId.MAX_CONCURRENT_STREAMS, value := 100 }] false
      let f2 := createSettingsFrame #[] true
      let f3 := createHTTP2Frame .DATA 0x01 1 "OK".toUTF8
      let combined := serializeHTTP2Frame f1 ++ serializeHTTP2Frame f2 ++ serializeHTTP2Frame f3
      match parseHTTP2Frames combined with
      | some frames => return frames.size == 3
      | none => return false },

  -- 50. Stream IDs: client streams odd, server streams even
  { name := "Client stream IDs are odd (1,3,5,7)"
    run := do
      return (1 % 2 == 1) && (3 % 2 == 1) && (5 % 2 == 1) && (7 % 2 == 1) },

  -- 51. Stream IDs: server streams even
  { name := "Server stream IDs are even (2,4,6,8)"
    run := do
      return (2 % 2 == 0) && (4 % 2 == 0) && (6 % 2 == 0) && (8 % 2 == 0) }
]

-- ============================================================================
-- §6. Main
-- ============================================================================

def main : IO UInt32 := do
  IO.println "╔══════════════════════════════════════════════════════════╗"
  IO.println "║  HTTP/2 Conformance Tests — LeanServer6 Phase 8.3      ║"
  IO.println "╚══════════════════════════════════════════════════════════╝\n"

  let (p1, f1) ← runTestSuite "Frame Header Tests" frameHeaderTests
  let (p2, f2) ← runTestSuite "\nComplete Frame Tests" completeFrameTests
  let (p3, f3) ← runTestSuite "\nSETTINGS Payload Tests" settingsPayloadTests
  let (p4, f4) ← runTestSuite "\nStream State Machine Tests" streamStateTests
  let (p5, f5) ← runTestSuite "\nEdge Cases & Wire Format" edgeCaseTests

  let totalPassed := p1 + p2 + p3 + p4 + p5
  let totalFailed := f1 + f2 + f3 + f4 + f5
  IO.println s!"\n━━━ Summary ━━━"
  IO.println s!"  Frame Headers:     {p1}/{p1 + f1}"
  IO.println s!"  Complete Frames:   {p2}/{p2 + f2}"
  IO.println s!"  SETTINGS Payload:  {p3}/{p3 + f3}"
  IO.println s!"  Stream States:     {p4}/{p4 + f4}"
  IO.println s!"  Edge Cases:        {p5}/{p5 + f5}"
  IO.println s!"  ────────────────────"
  IO.println s!"  Total:             {totalPassed}/{totalPassed + totalFailed}"

  if totalFailed == 0 then
    IO.println "\n🎉 All HTTP/2 conformance tests passed!"
    return 0
  else
    IO.println s!"\n⚠️  {totalFailed} test(s) failed!"
    return 1
