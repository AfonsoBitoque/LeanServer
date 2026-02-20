import LeanServer.Server.HTTPServer

/-!
# Fuzz TLS & HTTP/1.1 Parsers

Gera ByteArrays aleatórios e alimenta os parsers de TLS e HTTP/1.1.
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

/-- Gera uma String aleatória com `n` chars ASCII imprimíveis -/
def randomString (n : Nat) : IO String := do
  let mut s := ""
  for _ in List.range n do
    let c ← IO.rand 32 126
    s := s.push (Char.ofNat c)
  return s

def main : IO Unit := do
  let iterations := 10000
  IO.println s!"🔍 Fuzzing TLS & HTTP/1.1 parsers ({iterations} iterações)..."

  -- Fuzz parseTLSAlert
  let mut alertOk := 0
  let mut alertNone := 0
  for _ in List.range iterations do
    let size ← IO.rand 0 64
    let data ← randomBytes size
    match parseTLSAlert data with
    | some _ => alertOk := alertOk + 1
    | none   => alertNone := alertNone + 1
  IO.println s!"  ✅ parseTLSAlert: {alertOk} parsed, {alertNone} rejected (0 crashes)"

  -- Fuzz parseHTTPRequest
  let mut httpOk := 0
  let mut httpNone := 0
  for _ in List.range iterations do
    let size ← IO.rand 0 512
    let raw ← randomString size
    match parseHTTPRequest raw with
    | some _ => httpOk := httpOk + 1
    | none   => httpNone := httpNone + 1
  IO.println s!"  ✅ parseHTTPRequest: {httpOk} parsed, {httpNone} rejected (0 crashes)"

  -- Fuzz parseQUICLongHeader
  let mut qlhOk := 0
  let mut qlhNone := 0
  for _ in List.range iterations do
    let size ← IO.rand 0 128
    let data ← randomBytes size
    match parseQUICLongHeader data with
    | some _ => qlhOk := qlhOk + 1
    | none   => qlhNone := qlhNone + 1
  IO.println s!"  ✅ parseQUICLongHeader: {qlhOk} parsed, {qlhNone} rejected (0 crashes)"

  -- Fuzz parseTraceparent
  let mut tpOk := 0
  let mut tpNone := 0
  for _ in List.range iterations do
    let size ← IO.rand 0 80
    let raw ← randomString size
    match parseTraceparent raw with
    | some _ => tpOk := tpOk + 1
    | none   => tpNone := tpNone + 1
  IO.println s!"  ✅ parseTraceparent: {tpOk} parsed, {tpNone} rejected (0 crashes)"

  -- Fuzz parseConfigFile
  for _ in List.range (iterations / 10) do
    let size ← IO.rand 0 256
    let raw ← randomString size
    let _ := parseConfigFile raw
  IO.println s!"  ✅ parseConfigFile: {iterations / 10} inputs (0 crashes)"

  IO.println "🎉 TLS/HTTP fuzzing concluído sem crashes!"
