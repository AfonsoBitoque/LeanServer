import LeanServer.Crypto.Crypto
import LeanServer.Crypto.AES
import LeanServer.Crypto.X25519
import LeanServer.Server.HTTPServer
import LeanServer.Protocol.HPACK
import LeanServer.Protocol.HTTP2

/-!
# Automated Benchmark Suite (R14)

Measures performance of core operations to quantify optimization impact.

## Benchmark Categories
1. **Crypto micro-benchmarks** — SHA-256, HMAC-SHA-256, AES-GCM, X25519
2. **HPACK encode/decode** — Header compression round-trips
3. **HTTP parsing** — Frame and request parsing throughput
4. **Key derivation** — HKDF extract+expand pipeline

## Usage
```
lake build benchmarks && .lake/build/bin/benchmarks
```

## Output Format
Each benchmark reports:
- Operation name
- Iterations run
- Total time (ms)
- Average time per operation (ns/op)
-/

namespace LeanServer

-- ==========================================
-- Benchmark Infrastructure
-- ==========================================

/-- Result of a single benchmark -/
structure BenchmarkResult where
  name       : String
  iterations : Nat
  totalNs    : Nat
  nsPerOp    : Nat
  deriving Repr

instance : ToString BenchmarkResult where
  toString r :=
    let totalMs := r.totalNs / 1_000_000
    s!"  {r.name}: {r.iterations} iters, {totalMs} ms total, {r.nsPerOp} ns/op"

/-- Run a benchmark: execute `f` for `iters` iterations and measure time -/
def runBenchmark (name : String) (iters : Nat) (f : IO Unit) : IO BenchmarkResult := do
  -- Warmup: 10 iterations
  for _ in List.range 10 do
    f
  -- Timed run
  let startNs ← IO.monoNanosNow
  for _ in List.range iters do
    f
  let endNs ← IO.monoNanosNow
  let totalNs := endNs - startNs
  let nsPerOp := if iters > 0 then totalNs / iters else 0
  return { name, iterations := iters, totalNs, nsPerOp }

/-- Run a pure benchmark (no IO effects in the function itself) -/
def runPureBenchmark (name : String) (iters : Nat) (f : Unit → α) : IO BenchmarkResult := do
  -- Warmup
  for _ in List.range 10 do
    let _ := f ()
  -- Timed run
  let startNs ← IO.monoNanosNow
  for _ in List.range iters do
    let _ := f ()
  let endNs ← IO.monoNanosNow
  let totalNs := endNs - startNs
  let nsPerOp := if iters > 0 then totalNs / iters else 0
  return { name, iterations := iters, totalNs, nsPerOp }

/-- Summary of a benchmark suite -/
structure BenchmarkSuite where
  suiteName : String
  results   : List BenchmarkResult

instance : ToString BenchmarkSuite where
  toString s :=
    let header := s!"\n{'='|>.toString |> List.replicate 60 |> String.join}\n📊 {s.suiteName}\n{'='|>.toString |> List.replicate 60 |> String.join}"
    let body := s.results.map toString
    header ++ "\n" ++ "\n".intercalate body

-- ==========================================
-- Test Data Generators
-- ==========================================

/-- Generate a deterministic ByteArray of given size -/
private def testBytes (size : Nat) (seed : UInt8 := 0x42) : ByteArray :=
  let arr := ByteArray.empty
  Id.run do
    let mut result := arr
    let mut val := seed
    for _ in List.range size do
      result := result.push val
      val := val + 0x17  -- deterministic pseudo-random step
    return result

/-- A 16-byte AES key for benchmarks -/
private def benchAESKey : ByteArray := testBytes 16 0xAA

/-- A 32-byte AES-256 key -/
private def benchAES256Key : ByteArray := testBytes 32 0xBB

/-- A 12-byte IV/nonce -/
private def benchIV : ByteArray := testBytes 12 0xCC

/-- A 32-byte X25519 scalar -/
private def benchScalar : ByteArray := testBytes 32 0xDD

/-- Test payloads of various sizes -/
private def smallPayload : ByteArray := testBytes 64
private def mediumPayload : ByteArray := testBytes 1024
private def largePayload : ByteArray := testBytes 16384

-- ==========================================
-- Crypto Benchmarks
-- ==========================================

/-- Run SHA-256 benchmark -/
def benchSHA256 (iters : Nat := 10000) : IO BenchmarkResult :=
  runPureBenchmark "SHA-256 (1KB)" iters fun () =>
    sha256 mediumPayload

/-- Run HMAC-SHA-256 benchmark -/
def benchHMACSHA256 (iters : Nat := 10000) : IO BenchmarkResult :=
  runPureBenchmark "HMAC-SHA-256 (1KB)" iters fun () =>
    hmac_sha256 benchAESKey mediumPayload

/-- Run AES key expansion benchmark -/
def benchAESKeyExpansion (iters : Nat := 10000) : IO BenchmarkResult :=
  runPureBenchmark "AES-128 key expansion" iters fun () =>
    AES.expandKey benchAESKey

/-- Run AES block encrypt benchmark -/
def benchAESEncryptBlock (iters : Nat := 10000) : IO BenchmarkResult :=
  let expandedKey := AES.expandKey benchAESKey
  let block := testBytes 16
  runPureBenchmark "AES-128 encrypt block" iters fun () =>
    AES.encryptBlock expandedKey block

/-- Run AES-GCM encrypt benchmark (64B payload) -/
def benchAESGCMSmall (iters : Nat := 5000) : IO BenchmarkResult :=
  runPureBenchmark "AES-GCM encrypt (64B)" iters fun () =>
    AES.aesGCMEncrypt benchAESKey benchIV smallPayload ByteArray.empty

/-- Run AES-GCM encrypt benchmark (1KB payload) -/
def benchAESGCMMedium (iters : Nat := 2000) : IO BenchmarkResult :=
  runPureBenchmark "AES-GCM encrypt (1KB)" iters fun () =>
    AES.aesGCMEncrypt benchAESKey benchIV mediumPayload ByteArray.empty

/-- Run AES-GCM encrypt benchmark (16KB payload) -/
def benchAESGCMLarge (iters : Nat := 200) : IO BenchmarkResult :=
  runPureBenchmark "AES-GCM encrypt (16KB)" iters fun () =>
    AES.aesGCMEncrypt benchAESKey benchIV largePayload ByteArray.empty

/-- Run X25519 scalar multiplication benchmark -/
def benchX25519 (iters : Nat := 500) : IO BenchmarkResult :=
  let basePoint := Id.run do
    let mut bp := ByteArray.empty
    for _ in List.range 32 do
      bp := bp.push 0x00
    bp := bp.set! 0 9  -- standard base point
    return bp
  runPureBenchmark "X25519 scalarmult" iters fun () =>
    X25519.scalarmult benchScalar basePoint

/-- Run HKDF extract benchmark -/
def benchHKDFExtract (iters : Nat := 10000) : IO BenchmarkResult :=
  let salt := testBytes 32 0x11
  let ikm := testBytes 32 0x22
  runPureBenchmark "HKDF-Extract" iters fun () =>
    hkdf_extract salt ikm

/-- Run HKDF expand benchmark -/
def benchHKDFExpand (iters : Nat := 10000) : IO BenchmarkResult :=
  let prk := testBytes 32 0x33
  let info := testBytes 10 0x44
  runPureBenchmark "HKDF-Expand (32B)" iters fun () =>
    hkdf_expand prk info 32

/-- Full crypto benchmark suite -/
def cryptoBenchmarks : IO BenchmarkSuite := do
  let mut results : List BenchmarkResult := []
  let r1 ← benchSHA256
  results := results ++ [r1]
  let r2 ← benchHMACSHA256
  results := results ++ [r2]
  let r3 ← benchAESKeyExpansion
  results := results ++ [r3]
  let r4 ← benchAESEncryptBlock
  results := results ++ [r4]
  let r5 ← benchAESGCMSmall
  results := results ++ [r5]
  let r6 ← benchAESGCMMedium
  results := results ++ [r6]
  let r7 ← benchAESGCMLarge
  results := results ++ [r7]
  let r8 ← benchX25519
  results := results ++ [r8]
  let r9 ← benchHKDFExtract
  results := results ++ [r9]
  let r10 ← benchHKDFExpand
  results := results ++ [r10]
  return { suiteName := "Crypto Micro-Benchmarks", results }

-- ==========================================
-- HPACK Benchmarks
-- ==========================================

/-- Typical HTTP headers for HPACK benchmark -/
private def benchHeaders : Array (String × String) :=
  #[
    (":method", "GET"),
    (":path", "/index.html"),
    (":scheme", "https"),
    (":authority", "www.example.com"),
    ("accept", "text/html,application/xhtml+xml"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-language", "en-US,en;q=0.9"),
    ("user-agent", "LeanServer/0.1.0"),
    ("cache-control", "no-cache")
  ]

/-- HPACK encode benchmark -/
def benchHPACKEncode (iters : Nat := 5000) : IO BenchmarkResult :=
  runPureBenchmark "HPACK encode (9 headers)" iters fun () =>
    encodeHeadersPublic benchHeaders

/-- HPACK decode benchmark -/
def benchHPACKDecode (iters : Nat := 5000) : IO BenchmarkResult :=
  let encoded := encodeHeadersPublic benchHeaders
  let decoder := initHPACKDecoder
  runPureBenchmark "HPACK decode" iters fun () =>
    decodeHeaderList decoder encoded

/-- HPACK round-trip benchmark -/
def benchHPACKRoundtrip (iters : Nat := 3000) : IO BenchmarkResult :=
  let decoder := initHPACKDecoder
  runPureBenchmark "HPACK encode+decode round-trip" iters fun () =>
    let encoded := encodeHeadersPublic benchHeaders
    decodeHeaderList decoder encoded

/-- Full HPACK benchmark suite -/
def hpackBenchmarks : IO BenchmarkSuite := do
  let mut results : List BenchmarkResult := []
  let r1 ← benchHPACKEncode
  results := results ++ [r1]
  let r2 ← benchHPACKDecode
  results := results ++ [r2]
  let r3 ← benchHPACKRoundtrip
  results := results ++ [r3]
  return { suiteName := "HPACK Benchmarks", results }

-- ==========================================
-- HTTP Parsing Benchmarks
-- ==========================================

/-- A typical HTTP/1.1 GET request for parsing benchmark -/
private def benchHTTPRequestStr : String :=
  "GET /api/v1/users?page=1&limit=20 HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\nAuthorization: Bearer token123\r\nUser-Agent: LeanServer/0.1.0\r\nConnection: keep-alive\r\n\r\n"

/-- A typical HTTP/2 HEADERS frame -/
private def benchHTTP2Frame : ByteArray :=
  let payload := encodeHeadersPublic benchHeaders
  let frameHeader := serializeFrameHeader {
    length := payload.size.toUInt32
    frameType := .HEADERS
    flags := 0x04  -- END_HEADERS
    streamId := 1
  }
  frameHeader ++ payload

/-- HTTP/1.1 request parse benchmark -/
def benchHTTPParse (iters : Nat := 10000) : IO BenchmarkResult :=
  runPureBenchmark "HTTP/1.1 request parse" iters fun () =>
    parseHTTPRequest benchHTTPRequestStr

/-- HTTP/2 frame header parse benchmark -/
def benchHTTP2FrameParse (iters : Nat := 10000) : IO BenchmarkResult :=
  let frame := benchHTTP2Frame
  runPureBenchmark "HTTP/2 frame parse" iters fun () =>
    parseFrameHeader frame

/-- Full HTTP parsing benchmark suite -/
def httpBenchmarks : IO BenchmarkSuite := do
  let mut results : List BenchmarkResult := []
  let r1 ← benchHTTPParse
  results := results ++ [r1]
  let r2 ← benchHTTP2FrameParse
  results := results ++ [r2]
  return { suiteName := "HTTP Parsing Benchmarks", results }

-- ==========================================
-- Key Derivation Pipeline
-- ==========================================

/-- Full TLS key schedule benchmark (extract + expand) -/
def benchTLSKeySchedule (iters : Nat := 5000) : IO BenchmarkResult :=
  let salt := testBytes 32 0x55
  let ikm := testBytes 32 0x66
  let info := "tls13 derived".toUTF8
  runPureBenchmark "TLS key schedule (extract+expand)" iters fun () =>
    let prk := hkdf_extract salt ikm
    let _ := hkdf_expand prk info 32
    let _ := hkdf_expand prk info 12  -- IV
    ()

/-- Full key derivation benchmark suite -/
def keyDerivBenchmarks : IO BenchmarkSuite := do
  let r1 ← benchTLSKeySchedule
  return { suiteName := "Key Derivation Benchmarks", results := [r1] }

-- ==========================================
-- Full Benchmark Runner
-- ==========================================

/-- Run all benchmark suites and print results -/
def runAllBenchmarks : IO Unit := do
  IO.println "🏋️  LeanServer Benchmark Suite"
  IO.println s!"{'─'|>.toString |> List.replicate 60 |> String.join}"
  IO.println ""

  let crypto ← cryptoBenchmarks
  IO.println (toString crypto)

  let hpack ← hpackBenchmarks
  IO.println (toString hpack)

  let http ← httpBenchmarks
  IO.println (toString http)

  let keyDeriv ← keyDerivBenchmarks
  IO.println (toString keyDeriv)

  -- Summary
  let allResults := crypto.results ++ hpack.results ++ http.results ++ keyDeriv.results
  IO.println s!"\n{'─'|>.toString |> List.replicate 60 |> String.join}"
  IO.println s!"Total benchmarks: {allResults.length}"
  let totalIters := allResults.foldl (fun acc r => acc + r.iterations) 0
  IO.println s!"Total iterations: {totalIters}"
  IO.println "✅ All benchmarks completed"

end LeanServer
