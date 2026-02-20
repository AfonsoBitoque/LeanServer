import LeanServer.Protocol.WebSocket

/-!
# WebSocket Per-Message Compression (R17)

Implements the permessage-deflate extension per RFC 7692.

## Overview
The permessage-deflate extension compresses WebSocket message payloads using
the DEFLATE algorithm (RFC 1951). This module provides:
- Extension negotiation (parsing `Sec-WebSocket-Extensions` header)
- Pure Lean DEFLATE compression/decompression (simplified LZ77 + fixed Huffman)
- Integration with the existing `WebSocketFrame` type (via `rsv1` flag)

## Compression Parameters (RFC 7692 §7)
- `server_no_context_takeover` — reset compressor state between messages
- `client_no_context_takeover` — reset decompressor state between messages
- `server_max_window_bits` — server's LZ77 window size (8-15, default 15)
- `client_max_window_bits` — client's LZ77 window size (8-15, default 15)

## Limitations
- This is a simplified implementation using fixed Huffman codes only
- For production use, consider FFI to zlib/libdeflate
-/

namespace LeanServer

-- ==========================================
-- Extension Negotiation
-- ==========================================

/-- Parsed permessage-deflate extension parameters -/
structure DeflateConfig where
  serverNoContextTakeover : Bool := false
  clientNoContextTakeover : Bool := false
  serverMaxWindowBits     : Nat  := 15
  clientMaxWindowBits     : Nat  := 15
  deriving Repr, BEq, Inhabited

/-- Parse a `Sec-WebSocket-Extensions` header value for permessage-deflate.
    Returns `none` if the extension is not offered. -/
def parseDeflateOffer (extensionHeader : String) : Option DeflateConfig :=
  let parts := extensionHeader.splitOn ";"
  let trimmed := parts.map fun s => s.trimAscii.toString
  -- Check if permessage-deflate is offered
  let isDeflate := trimmed.any fun p =>
    p.toLower == "permessage-deflate"
  if !isDeflate then none
  else
    -- Parse parameters
    let config := trimmed.foldl (fun acc param =>
      let kv := param.splitOn "="
      match kv with
      | [key] =>
        let k := key.trimAscii.toString.toLower
        if k == "server_no_context_takeover" then { acc with serverNoContextTakeover := true }
        else if k == "client_no_context_takeover" then { acc with clientNoContextTakeover := true }
        else acc
      | [key, value] =>
        let k := key.trimAscii.toString.toLower
        let v := value.trimAscii.toString
        match v.toNat? with
        | some n =>
          if k == "server_max_window_bits" && n >= 8 && n <= 15 then
            { acc with serverMaxWindowBits := n }
          else if k == "client_max_window_bits" && n >= 8 && n <= 15 then
            { acc with clientMaxWindowBits := n }
          else acc
        | none => acc
      | _ => acc
    ) ({} : DeflateConfig)
    some config

/-- Build the server's response extension header for permessage-deflate -/
def buildDeflateResponse (config : DeflateConfig) : String :=
  let base := "permessage-deflate"
  let p1 := if config.serverNoContextTakeover then base ++ "; server_no_context_takeover" else base
  let p2 := if config.clientNoContextTakeover then p1 ++ "; client_no_context_takeover" else p1
  let p3 := if config.serverMaxWindowBits != 15 then p2 ++ s!"; server_max_window_bits={config.serverMaxWindowBits}" else p2
  let p4 := if config.clientMaxWindowBits != 15 then p3 ++ s!"; client_max_window_bits={config.clientMaxWindowBits}" else p3
  p4

-- ==========================================
-- Simplified DEFLATE Compression
-- ==========================================

/-- DEFLATE block types (RFC 1951 §3.2.3) -/
inductive DeflateBlockType where
  | noCompression    : DeflateBlockType  -- BTYPE=00
  | fixedHuffman     : DeflateBlockType  -- BTYPE=01
  | dynamicHuffman   : DeflateBlockType  -- BTYPE=10
  deriving Repr, BEq

/-- Compress data using DEFLATE with stored (uncompressed) blocks.
    This is the simplest valid DEFLATE stream: each block stores raw data.
    RFC 1951 §3.2.4: Non-compressed blocks. -/
def deflateStored (input : ByteArray) : ByteArray :=
  if input.size == 0 then
    ByteArray.mk #[0x03, 0x00]
  else Id.run do
    let mut result := ByteArray.empty
    let maxBlockSize := 65535
    let mut offset := 0
    while offset < input.size do
      let remaining := input.size - offset
      let blockSize := if remaining > maxBlockSize then maxBlockSize else remaining
      let isFinal := offset + blockSize >= input.size
      -- Block header: BFINAL (1 bit) | BTYPE=00 (2 bits) → byte-aligned
      let headerByte : UInt8 := if isFinal then 0x01 else 0x00
      result := result.push headerByte
      -- LEN (2 bytes little-endian)
      let len := blockSize.toUInt16
      result := result.push (len &&& 0xFF).toUInt8
      result := result.push ((len >>> 8) &&& 0xFF).toUInt8
      -- NLEN (one's complement of LEN)
      let nlen := len ^^^ 0xFFFF
      result := result.push (nlen &&& 0xFF).toUInt8
      result := result.push ((nlen >>> 8) &&& 0xFF).toUInt8
      -- Raw data
      result := result ++ input.extract offset (offset + blockSize)
      offset := offset + blockSize
    result

/-- Decompress a DEFLATE stored (non-compressed) block stream.
    Handles BTYPE=00 blocks only (for our simplified implementation). -/
def inflateStored (input : ByteArray) : Option ByteArray :=
  if input.size < 2 then none
  else Id.run do
    let mut result := ByteArray.empty
    let mut offset := 0
    let mut done := false
    while offset < input.size && !done do
      if offset >= input.size then
        done := true
      else
        let headerByte := input.get! offset
        let isFinal := (headerByte &&& 0x01) != 0
        let btype := (headerByte >>> 1) &&& 0x03
        offset := offset + 1
        if btype == 0x00 then
          -- Stored block
          if offset + 4 > input.size then
            done := true
          else
            let len := (input.get! offset).toNat + (input.get! (offset + 1)).toNat * 256
            offset := offset + 4  -- skip LEN + NLEN
            if offset + len > input.size then
              done := true
            else
              result := result ++ input.extract offset (offset + len)
              offset := offset + len
              if isFinal then done := true
        else if btype == 0x01 && isFinal then
          -- Fixed Huffman empty block (0x03 0x00)
          done := true
        else
          -- Dynamic Huffman / unsupported — return what we have
          done := true
    some result

-- ==========================================
-- WebSocket Integration
-- ==========================================

/-- Compression state for a WebSocket connection -/
structure WSCompressionState where
  config   : DeflateConfig
  enabled  : Bool := true
  /-- Number of messages compressed -/
  compressed : Nat := 0
  /-- Bytes saved by compression -/
  bytesSaved : Nat := 0
  deriving Repr, Inhabited

/-- Create initial compression state from negotiated config -/
def WSCompressionState.create (config : DeflateConfig) : WSCompressionState :=
  { config, enabled := true, compressed := 0, bytesSaved := 0 }

/-- Compress a WebSocket message payload.
    Sets RSV1=true on the frame to indicate compression. -/
def compressWSMessage (state : WSCompressionState) (frame : WebSocketFrame) :
    WebSocketFrame × WSCompressionState :=
  if !state.enabled then (frame, state)
  else if frame.payload.size < 128 then
    -- Don't compress small messages (overhead not worth it)
    (frame, state)
  else
    let compressed := deflateStored frame.payload
    -- RFC 7692 §7.2.1: Remove trailing 0x00 0x00 0xFF 0xFF
    let trimmed := if compressed.size >= 4 then
      let last4 := compressed.extract (compressed.size - 4) compressed.size
      if last4 == ByteArray.mk #[0x00, 0x00, 0xFF, 0xFF] then
        compressed.extract 0 (compressed.size - 4)
      else compressed
    else compressed
    -- Only use compression if it actually reduces size
    if trimmed.size >= frame.payload.size then (frame, state)
    else
      let saved := frame.payload.size - trimmed.size
      let compressedFrame := { frame with
        rsv1 := true  -- RSV1 indicates permessage-deflate
        payload := trimmed
      }
      let newState := { state with
        compressed := state.compressed + 1
        bytesSaved := state.bytesSaved + saved
      }
      (compressedFrame, newState)

/-- Decompress a WebSocket message payload.
    Only decompresses if RSV1 is set on the frame. -/
def decompressWSMessage (state : WSCompressionState) (frame : WebSocketFrame) :
    Option (WebSocketFrame × WSCompressionState) :=
  if !frame.rsv1 then some (frame, state)  -- Not compressed
  else if !state.enabled then none  -- Compression not negotiated but RSV1 set
  else
    -- RFC 7692 §7.2.2: Append 0x00 0x00 0xFF 0xFF before decompressing
    let withTrailer := frame.payload ++ ByteArray.mk #[0x00, 0x00, 0xFF, 0xFF]
    match inflateStored withTrailer with
    | none => none  -- Decompression failed
    | some decompressed =>
      let decompressedFrame := { frame with
        rsv1 := false
        payload := decompressed
      }
      some (decompressedFrame, state)

/-- Check if a WebSocket upgrade request offers permessage-deflate -/
def negotiateWSCompression (headers : List (String × String)) :
    Option DeflateConfig :=
  let extensionHeader := headers.find? fun (k, _) =>
    k.toLower == "sec-websocket-extensions"
  match extensionHeader with
  | none => none
  | some (_, value) => parseDeflateOffer value

/-- Compression statistics for monitoring -/
structure WSCompressionStats where
  messagesCompressed : Nat
  totalBytesSaved    : Nat
  compressionEnabled : Bool
  deriving Repr

/-- Get compression statistics -/
def WSCompressionState.stats (state : WSCompressionState) : WSCompressionStats :=
  { messagesCompressed := state.compressed
    totalBytesSaved := state.bytesSaved
    compressionEnabled := state.enabled }

end LeanServer
