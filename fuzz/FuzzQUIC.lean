import LeanServer.Protocol.QUIC

/-!
# Fuzz QUIC Parsers

Gera ByteArrays aleatórios e alimenta os parsers de QUIC.
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
  IO.println s!"🔍 Fuzzing QUIC parsers ({iterations} iterações)..."

  -- Fuzz decodeVarInt at various start positions
  let mut viOk := 0
  let mut viNone := 0
  for _ in List.range iterations do
    let size ← IO.rand 0 16
    let data ← randomBytes size
    let start ← IO.rand 0 (size + 2)
    match decodeVarInt data start with
    | some _ => viOk := viOk + 1
    | none   => viNone := viNone + 1
  IO.println s!"  ✅ decodeVarInt: {viOk} parsed, {viNone} rejected (0 crashes)"

  -- Fuzz encodeVarInt → decodeVarInt roundtrip
  let mut rtOk := 0
  for _ in List.range iterations do
    let v ← IO.rand 0 1073741823  -- up to 4-byte range
    let encoded := encodeVarInt v.toUInt64
    match decodeVarInt encoded 0 with
    | some (decoded, _) =>
      if decoded.toNat == v then rtOk := rtOk + 1
      else IO.println s!"  ⚠️ Roundtrip mismatch: {v} → {decoded}"
    | none => IO.println s!"  ⚠️ Failed to decode encoded value: {v}"
  IO.println s!"  ✅ encodeVarInt/decodeVarInt roundtrip: {rtOk}/{iterations} OK"

  -- Fuzz decodeQUICCryptoFrame
  let mut cfOk := 0
  let mut cfNone := 0
  for _ in List.range iterations do
    let size ← IO.rand 0 64
    let data ← randomBytes size
    match decodeQUICCryptoFrame data with
    | some _ => cfOk := cfOk + 1
    | none   => cfNone := cfNone + 1
  IO.println s!"  ✅ decodeQUICCryptoFrame: {cfOk} parsed, {cfNone} rejected (0 crashes)"

  -- Fuzz decodeQUICStreamFrame
  let mut sfOk := 0
  let mut sfNone := 0
  for _ in List.range iterations do
    let size ← IO.rand 0 64
    let data ← randomBytes size
    match decodeQUICStreamFrame data with
    | some _ => sfOk := sfOk + 1
    | none   => sfNone := sfNone + 1
  IO.println s!"  ✅ decodeQUICStreamFrame: {sfOk} parsed, {sfNone} rejected (0 crashes)"

  -- Fuzz parseQUICFrame
  let mut qfOk := 0
  let mut qfNone := 0
  for _ in List.range iterations do
    let size ← IO.rand 0 64
    let data ← randomBytes size
    match parseQUICFrame data with
    | some _ => qfOk := qfOk + 1
    | none   => qfNone := qfNone + 1
  IO.println s!"  ✅ parseQUICFrame: {qfOk} parsed, {qfNone} rejected (0 crashes)"

  IO.println "🎉 QUIC fuzzing concluído sem crashes!"
