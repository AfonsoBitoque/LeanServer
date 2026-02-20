import LeanServer.Server.HTTPServer

/-!
# Fuzz WebSocket Frame Parsing

O WebSocket frame parsing em LeanServer está inline no websocketLoop
(HTTPServer.lean). Este harness testa a lógica de parsing de frames
com payloads aleatórios para verificar que não há crashes.
-/

open LeanServer

/-- Gera um ByteArray com `n` bytes aleatórios -/
def randomBytes (n : Nat) : IO ByteArray := do
  let mut buf := ByteArray.empty
  for _ in List.range n do
    let b ← IO.rand 0 255
    buf := buf.push b.toUInt8
  return buf

/-- Simula o parsing de um WebSocket frame header.
    Replica a lógica do websocketLoop sem a parte de rede.
    RFC 6455 §5.2: frame format. -/
def parseWSFrameHeader (data : ByteArray) : Option (UInt8 × Bool × UInt64 × Nat) :=
  if data.size < 2 then none
  else
    let byte0 := data.get! 0
    let opcode := byte0 &&& 0x0F
    let byte1 := data.get! 1
    let masked := (byte1 &&& 0x80) != 0
    let lenByte := (byte1 &&& 0x7F).toNat
    if lenByte < 126 then
      let headerLen := if masked then 6 else 2
      if data.size < headerLen then none
      else some (opcode, masked, lenByte.toUInt64, headerLen)
    else if lenByte == 126 then
      if data.size < 4 then none
      else
        let extLen := (data.get! 2).toUInt64 <<< 8 ||| (data.get! 3).toUInt64
        let headerLen := if masked then 8 else 4
        if data.size < headerLen then none
        else some (opcode, masked, extLen, headerLen)
    else -- 127 → 8-byte extended payload length
      if data.size < 10 then none
      else
        let extLen := [2, 3, 4, 5, 6, 7, 8, 9].foldl (fun (acc : UInt64) (i : Nat) =>
          (acc <<< 8) ||| (data.get! i).toUInt64) (0 : UInt64)
        let headerLen := if masked then 14 else 10
        if data.size < headerLen then none
        else some (opcode, masked, extLen, headerLen)

/-- Apply WebSocket masking (RFC 6455 §5.3) -/
def applyWSMask (data : ByteArray) (mask : ByteArray) : ByteArray :=
  if mask.size < 4 then data
  else
    (List.range data.size).foldl (fun acc i =>
      acc.push (data.get! i ^^^ mask.get! (i % 4))) ByteArray.empty

def main : IO Unit := do
  let iterations := 10000
  IO.println s!"🔍 Fuzzing WebSocket parsers ({iterations} iterações)..."

  -- Fuzz parseWSFrameHeader
  let mut wsOk := 0
  let mut wsNone := 0
  for _ in List.range iterations do
    let size ← IO.rand 0 32
    let data ← randomBytes size
    match parseWSFrameHeader data with
    | some _ => wsOk := wsOk + 1
    | none   => wsNone := wsNone + 1
  IO.println s!"  ✅ parseWSFrameHeader: {wsOk} parsed, {wsNone} rejected (0 crashes)"

  -- Fuzz applyWSMask — should never crash for any input
  for _ in List.range iterations do
    let dataSize ← IO.rand 0 128
    let data ← randomBytes dataSize
    let maskSize ← IO.rand 0 8
    let mask ← randomBytes maskSize
    let _ := applyWSMask data mask
  IO.println s!"  ✅ applyWSMask: {iterations} inputs (0 crashes)"

  -- Fuzz with well-formed WebSocket frames (random opcode + payload)
  let mut validFrames := 0
  for _ in List.range iterations do
    let opcode ← IO.rand 0 15
    let payloadLen ← IO.rand 0 125
    let payload ← randomBytes payloadLen
    let mask ← randomBytes 4
    -- Build frame: [FIN+opcode, MASK+len, mask[4], payload]
    let byte0 := (0x80 ||| opcode).toUInt8  -- FIN=1
    let byte1 := (0x80 ||| payloadLen).toUInt8  -- MASK=1
    let mut frame := ByteArray.empty
    frame := frame.push byte0
    frame := frame.push byte1
    frame := frame ++ mask
    frame := frame ++ payload
    match parseWSFrameHeader frame with
    | some (op, masked, len, _) =>
      if op == opcode.toUInt8 && masked && len.toNat == payloadLen then
        validFrames := validFrames + 1
    | none => pure ()
  IO.println s!"  ✅ Well-formed frames: {validFrames}/{iterations} correctly parsed"

  IO.println "🎉 WebSocket fuzzing concluído sem crashes!"
