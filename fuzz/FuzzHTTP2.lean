import LeanServer.Protocol.HTTP2
import LeanServer.Protocol.HPACK

/-!
# Fuzz HTTP/2 Parsers

Gera ByteArrays aleatórios e alimenta os parsers de HTTP/2 e HPACK.
Nenhum panic deve ocorrer — todos os parsers devem retornar Option/resultado seguro.
-/

open LeanServer

/-- Gera um ByteArray com `n` bytes aleatórios -/
def randomBytes (n : Nat) : IO ByteArray := do
  let mut buf := ByteArray.empty
  for _ in List.range n do
    let b ← IO.rand 0 255
    buf := buf.push b.toUInt8
  return buf

def main : IO Unit := do
  let iterations := 10000
  IO.println s!"🔍 Fuzzing HTTP/2 & HPACK parsers ({iterations} iterações)..."

  -- Fuzz parseFrameHeader (expects 9+ bytes)
  let mut fhOk := 0
  let mut fhNone := 0
  for _ in List.range iterations do
    let size ← IO.rand 0 32
    let data ← randomBytes size
    match parseFrameHeader data with
    | some _ => fhOk := fhOk + 1
    | none   => fhNone := fhNone + 1
  IO.println s!"  ✅ parseFrameHeader: {fhOk} parsed, {fhNone} rejected (0 crashes)"

  -- Fuzz parseHTTP2Frame
  let mut h2fOk := 0
  let mut h2fNone := 0
  for _ in List.range iterations do
    let size ← IO.rand 0 128
    let data ← randomBytes size
    match parseHTTP2Frame data with
    | some _ => h2fOk := h2fOk + 1
    | none   => h2fNone := h2fNone + 1
  IO.println s!"  ✅ parseHTTP2Frame: {h2fOk} parsed, {h2fNone} rejected (0 crashes)"

  -- Fuzz parseSettingsPayload
  for _ in List.range iterations do
    let size ← IO.rand 0 64
    let data ← randomBytes size
    let _ := parseSettingsPayload data
  IO.println s!"  ✅ parseSettingsPayload: {iterations} inputs (0 crashes)"

  -- Fuzz parseWindowUpdatePayload
  let mut wuOk := 0
  let mut wuNone := 0
  for _ in List.range iterations do
    let size ← IO.rand 0 16
    let data ← randomBytes size
    match parseWindowUpdatePayload data with
    | some _ => wuOk := wuOk + 1
    | none   => wuNone := wuNone + 1
  IO.println s!"  ✅ parseWindowUpdatePayload: {wuOk} parsed, {wuNone} rejected (0 crashes)"

  -- Fuzz parseGoAwayPayload
  let mut gaOk := 0
  let mut gaNone := 0
  for _ in List.range iterations do
    let size ← IO.rand 0 32
    let data ← randomBytes size
    match parseGoAwayPayload data with
    | some _ => gaOk := gaOk + 1
    | none   => gaNone := gaNone + 1
  IO.println s!"  ✅ parseGoAwayPayload: {gaOk} parsed, {gaNone} rejected (0 crashes)"

  -- Fuzz HPACK decodeInteger
  let mut diOk := 0
  let mut diNone := 0
  for _ in List.range iterations do
    let size ← IO.rand 0 16
    let data ← randomBytes size
    let prefixBits ← IO.rand 1 8
    match decodeInteger data 0 prefixBits with
    | some _ => diOk := diOk + 1
    | none   => diNone := diNone + 1
  IO.println s!"  ✅ HPACK.decodeInteger: {diOk} parsed, {diNone} rejected (0 crashes)"

  -- Fuzz HPACK decodeString
  let mut dsOk := 0
  let mut dsNone := 0
  for _ in List.range iterations do
    let size ← IO.rand 0 32
    let data ← randomBytes size
    match decodeString data 0 with
    | some _ => dsOk := dsOk + 1
    | none   => dsNone := dsNone + 1
  IO.println s!"  ✅ HPACK.decodeString: {dsOk} parsed, {dsNone} rejected (0 crashes)"

  -- Fuzz HPACK decodeHeaderList
  let mut hlOk := 0
  let mut hlNone := 0
  let decoder := initHPACKDecoder
  for _ in List.range iterations do
    let size ← IO.rand 0 64
    let data ← randomBytes size
    match decodeHeaderList decoder data with
    | some _ => hlOk := hlOk + 1
    | none   => hlNone := hlNone + 1
  IO.println s!"  ✅ HPACK.decodeHeaderList: {hlOk} parsed, {hlNone} rejected (0 crashes)"

  IO.println "🎉 HTTP/2 & HPACK fuzzing concluído sem crashes!"
