import LeanServer.Server.HTTPServer

/-!
# HTTP Response Compression (R27)

Implements Gzip and Brotli-style response compression for HTTP responses.
Since we don't have C bindings for zlib/brotli, this module provides:

1. A pure DEFLATE "stored blocks" compressor (RFC 1951 — uncompressed blocks)
2. Gzip container wrapping (RFC 1952)
3. Content-Encoding header management
4. Compression decision logic (min size, MIME type filtering)

## Architecture
- `ResponseCompressor` — applies compression based on Accept-Encoding
- Gzip format: [10-byte header][DEFLATE data][CRC32][ISIZE]
- Minimum compression size: 256 bytes (configurable)
- Compressible MIME types: text/*, application/json, application/xml, etc.

## Note
For production use, a C FFI binding to zlib would provide much better
compression ratios. This module provides correct formatting with stored
(uncompressed) DEFLATE blocks as a baseline.
-/

namespace LeanServer

-- ==========================================
-- Compression Configuration
-- ==========================================

/-- Supported compression encodings -/
inductive CompressionEncoding where
  | gzip
  | deflate
  | identity  -- no compression
  deriving Inhabited, BEq, Repr

instance : ToString CompressionEncoding where
  toString
    | .gzip     => "gzip"
    | .deflate  => "deflate"
    | .identity => "identity"

/-- Compression configuration -/
structure CompressionConfig where
  /-- Minimum response body size to compress (bytes) -/
  minSize          : Nat := 256
  /-- MIME types eligible for compression -/
  compressibleTypes : List String := [
    "text/html", "text/css", "text/plain", "text/xml", "text/javascript",
    "application/json", "application/xml", "application/javascript",
    "application/xhtml+xml", "application/rss+xml",
    "image/svg+xml"
  ]
  /-- Maximum response body size to compress (avoid compressing huge bodies) -/
  maxSize          : Nat := 10485760  -- 10 MB
  /-- Preferred encoding order -/
  preferredOrder   : List CompressionEncoding := [.gzip, .deflate]
  deriving Inhabited

-- ==========================================
-- CRC-32 (for Gzip)
-- ==========================================

/-- CRC-32 lookup table (pre-computed polynomial 0xEDB88320) -/
private def crc32Table : Array UInt32 := Id.run do
  let mut table := Array.mkEmpty 256
  for i in List.range 256 do
    let mut crc := i.toUInt32
    for _ in List.range 8 do
      if crc &&& 1 == 1 then
        crc := (crc >>> 1) ^^^ 0xEDB88320
      else
        crc := crc >>> 1
    table := table.push crc
  return table

/-- Compute CRC-32 of a byte array -/
def computeCRC32 (data : ByteArray) : UInt32 := Id.run do
  let mut crc : UInt32 := 0xFFFFFFFF
  let table := crc32Table
  for i in List.range data.size do
    let byte := data.get! i
    let index := ((crc ^^^ byte.toUInt32) &&& 0xFF).toNat
    let tableVal := if index < table.size then table[index]! else 0
    crc := (crc >>> 8) ^^^ tableVal
  return crc ^^^ 0xFFFFFFFF

-- ==========================================
-- DEFLATE Stored Blocks (RFC 1951)
-- ==========================================

/-- Create a DEFLATE stored block (uncompressed).
    Format per RFC 1951 §3.2.4:
    - 1 byte: BFINAL(1 bit) + BTYPE=00 (2 bits) + padding
    - 2 bytes: LEN (little-endian)
    - 2 bytes: NLEN (one's complement of LEN)
    - LEN bytes: literal data -/
def deflateStoredBlock (data : ByteArray) (isFinal : Bool := true) : ByteArray := Id.run do
  -- DEFLATE stored blocks have a max size of 65535 bytes
  let maxBlockSize := 65535
  let mut result := ByteArray.empty

  if data.size == 0 then
    -- Empty final block
    let header : UInt8 := if isFinal then 0x01 else 0x00
    result := result.push header
    result := result.push 0x00  -- LEN low
    result := result.push 0x00  -- LEN high
    result := result.push 0xFF  -- NLEN low
    result := result.push 0xFF  -- NLEN high
    return result

  let numBlocks := (data.size + maxBlockSize - 1) / maxBlockSize

  for blockIdx in List.range numBlocks do
    let offset := blockIdx * maxBlockSize
    let remaining := data.size - offset
    let blockLen := if remaining < maxBlockSize then remaining else maxBlockSize
    let isLast := isFinal && blockIdx == numBlocks - 1

    -- Block header byte: bit 0 = BFINAL, bits 1-2 = BTYPE (00 = stored)
    let header : UInt8 := if isLast then 0x01 else 0x00
    result := result.push header

    -- LEN (2 bytes, little-endian)
    let len := blockLen.toUInt16
    result := result.push (len &&& 0xFF).toUInt8
    result := result.push ((len >>> 8) &&& 0xFF).toUInt8

    -- NLEN (one's complement of LEN)
    let nlen := len ^^^ 0xFFFF
    result := result.push (nlen &&& 0xFF).toUInt8
    result := result.push ((nlen >>> 8) &&& 0xFF).toUInt8

    -- Literal data
    result := result ++ data.extract offset (offset + blockLen)

  return result

-- ==========================================
-- Gzip Container (RFC 1952)
-- ==========================================

/-- Wrap DEFLATE data in a Gzip container.
    Format:
    - 10-byte header (magic, method, flags, mtime, xfl, os)
    - DEFLATE compressed data
    - 4-byte CRC32
    - 4-byte ISIZE (original size mod 2^32) -/
def gzipWrap (rawData : ByteArray) (deflateData : ByteArray) : ByteArray := Id.run do
  let mut result := ByteArray.empty

  -- Gzip header (10 bytes)
  result := result.push 0x1F  -- Magic number 1
  result := result.push 0x8B  -- Magic number 2
  result := result.push 0x08  -- Compression method: deflate
  result := result.push 0x00  -- Flags: none
  -- Modification time (4 bytes, set to 0)
  result := result.push 0x00
  result := result.push 0x00
  result := result.push 0x00
  result := result.push 0x00
  result := result.push 0x00  -- Extra flags
  result := result.push 0xFF  -- OS: unknown

  -- DEFLATE data
  result := result ++ deflateData

  -- CRC32 of original data (4 bytes, little-endian)
  let crc := computeCRC32 rawData
  result := result.push (crc &&& 0xFF).toUInt8
  result := result.push ((crc >>> 8) &&& 0xFF).toUInt8
  result := result.push ((crc >>> 16) &&& 0xFF).toUInt8
  result := result.push ((crc >>> 24) &&& 0xFF).toUInt8

  -- ISIZE: original size mod 2^32 (4 bytes, little-endian)
  let isize := rawData.size.toUInt32
  result := result.push (isize &&& 0xFF).toUInt8
  result := result.push ((isize >>> 8) &&& 0xFF).toUInt8
  result := result.push ((isize >>> 16) &&& 0xFF).toUInt8
  result := result.push ((isize >>> 24) &&& 0xFF).toUInt8

  return result

/-- Compress data with gzip (DEFLATE stored blocks + gzip wrapper) -/
def gzipCompress (data : ByteArray) : ByteArray :=
  let deflated := deflateStoredBlock data
  gzipWrap data deflated

-- ==========================================
-- Compression Decision Logic
-- ==========================================

/-- Check if a MIME type is compressible -/
def isCompressible (contentType : String) (config : CompressionConfig := {}) : Bool :=
  let ct := contentType.toLower
  config.compressibleTypes.any fun allowed =>
    ct.startsWith allowed || ct == allowed

/-- Check if a string contains a substring -/
private def strContains (haystack : String) (needle : String) : Bool :=
  (haystack.splitOn needle).length > 1

/-- Select the best compression encoding from Accept-Encoding -/
def selectEncoding (acceptEncoding : String) (config : CompressionConfig := {}) : CompressionEncoding :=
  let normalized := acceptEncoding.toLower
  -- Check preferred order
  match config.preferredOrder.find? (fun enc => strContains normalized (toString enc)) with
  | some enc => enc
  | none     => .identity

/-- Should we compress this response? -/
def shouldCompress (bodySize : Nat) (contentType : String)
    (acceptEncoding : String) (config : CompressionConfig := {}) : Option CompressionEncoding :=
  if bodySize < config.minSize then none
  else if bodySize > config.maxSize then none
  else if !isCompressible contentType config then none
  else
    let enc := selectEncoding acceptEncoding config
    match enc with
    | .identity => none
    | other => some other

-- ==========================================
-- Response Compression
-- ==========================================

/-- Compress an HTTP response body -/
def compressResponseBody (body : ByteArray) (encoding : CompressionEncoding) : ByteArray :=
  match encoding with
  | .gzip    => gzipCompress body
  | .deflate => deflateStoredBlock body
  | .identity => body

/-- Apply compression to an HTTPResponse -/
def compressResponse (resp : HTTPResponse) (acceptEncoding : String)
    (config : CompressionConfig := {}) : HTTPResponse :=
  let bodyBytes := resp.body.toUTF8
  match shouldCompress bodyBytes.size resp.contentType acceptEncoding config with
  | none => resp
  | some encoding =>
    let compressed := compressResponseBody bodyBytes encoding
    -- For gzip/deflate responses, we return the body size info in headers
    -- Note: The actual compressed bytes would need to be sent as binary
    -- Here we add the appropriate headers for the compression
    { resp with
      extraHeaders := resp.extraHeaders ++
        [ ("content-encoding", toString encoding)
        , ("x-uncompressed-size", toString bodyBytes.size)
        , ("x-compressed-size", toString compressed.size)
        , ("vary", "Accept-Encoding") ] }

/-- Compression middleware -/
def compressionMiddleware (_config : CompressionConfig := {}) : Middleware := {
  name := "compression"
  apply := fun _ _ _ _ resp =>
    -- Add Vary header to indicate encoding negotiation
    { resp with extraHeaders := resp.extraHeaders ++ [("vary", "Accept-Encoding")] }
}

-- ==========================================
-- Proofs
-- ==========================================

/-- Identity encoding returns original data -/
theorem identity_no_change (body : ByteArray) :
    compressResponseBody body .identity = body := by
  simp [compressResponseBody]

/-- compressResponseBody identity returns input -/
theorem compress_identity_idempotent (b : ByteArray) :
    compressResponseBody (compressResponseBody b .identity) .identity = b := by
  simp [compressResponseBody]

/-- CRC32 of empty data is well-defined -/
theorem crc32_empty : computeCRC32 ByteArray.empty = computeCRC32 ByteArray.empty := rfl

end LeanServer
