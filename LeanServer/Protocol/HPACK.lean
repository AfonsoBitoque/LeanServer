-- HPACK Header Compression for HTTP/2
-- Based on RFC 7541: https://tools.ietf.org/html/rfc7541

import LeanServer.Core.Basic

namespace LeanServer

-- HPACK Header Field
structure HeaderField where
  name : String
  value : String
  deriving Repr, BEq

instance : Inhabited HeaderField where
  default := { name := "", value := "" }

-- HPACK Static Table (RFC 7541 Appendix A)
def staticTable : Array HeaderField := #[
  { name := ":authority", value := "" },
  { name := ":method", value := "GET" },
  { name := ":method", value := "POST" },
  { name := ":path", value := "/" },
  { name := ":path", value := "/index.html" },
  { name := ":scheme", value := "http" },
  { name := ":scheme", value := "https" },
  { name := ":status", value := "200" },
  { name := ":status", value := "204" },
  { name := ":status", value := "206" },
  { name := ":status", value := "304" },
  { name := ":status", value := "400" },
  { name := ":status", value := "404" },
  { name := ":status", value := "500" },
  { name := "accept-charset", value := "" },
  { name := "accept-encoding", value := "gzip, deflate" },
  { name := "accept-language", value := "" },
  { name := "accept-ranges", value := "" },
  { name := "accept", value := "" },
  { name := "access-control-allow-origin", value := "" },
  { name := "age", value := "" },
  { name := "allow", value := "" },
  { name := "authorization", value := "" },
  { name := "cache-control", value := "" },
  { name := "content-disposition", value := "" },
  { name := "content-encoding", value := "" },
  { name := "content-language", value := "" },
  { name := "content-length", value := "" },
  { name := "content-location", value := "" },
  { name := "content-range", value := "" },
  { name := "content-type", value := "" },
  { name := "cookie", value := "" },
  { name := "date", value := "" },
  { name := "etag", value := "" },
  { name := "expect", value := "" },
  { name := "expires", value := "" },
  { name := "from", value := "" },
  { name := "host", value := "" },
  { name := "if-match", value := "" },
  { name := "if-modified-since", value := "" },
  { name := "if-none-match", value := "" },
  { name := "if-range", value := "" },
  { name := "if-unmodified-since", value := "" },
  { name := "last-modified", value := "" },
  { name := "link", value := "" },
  { name := "location", value := "" },
  { name := "max-forwards", value := "" },
  { name := "proxy-authenticate", value := "" },
  { name := "proxy-authorization", value := "" },
  { name := "range", value := "" },
  { name := "referer", value := "" },
  { name := "refresh", value := "" },
  { name := "retry-after", value := "" },
  { name := "server", value := "" },
  { name := "set-cookie", value := "" },
  { name := "strict-transport-security", value := "" },
  { name := "transfer-encoding", value := "" },
  { name := "user-agent", value := "" },
  { name := "vary", value := "" },
  { name := "via", value := "" },
  { name := "www-authenticate", value := "" }
]

-- HPACK Dynamic Table
structure DynamicTable where
  entries : Array HeaderField
  size : Nat  -- Current size in bytes
  maxSize : Nat  -- Maximum size in bytes
  deriving Repr

-- Initialize dynamic table
def initDynamicTable (maxSize : Nat := 4096) : DynamicTable := {
  entries := #[]
  size := 0
  maxSize := maxSize
}

-- Calculate header field size (name + value + 32)
def headerFieldSize (field : HeaderField) : Nat :=
  field.name.length + field.value.length + 32

-- Add entry to dynamic table (evicting old entries if necessary)
-- RFC 7541 §4.4: Before a new entry is added, entries are evicted from the end
-- of the dynamic table until the size of the table is less than or equal to
-- (maxTableSize - new entry size) or until the table is empty.
def addToDynamicTable (table : DynamicTable) (field : HeaderField) : DynamicTable :=
  let fieldSize := headerFieldSize field
  -- If the new entry is larger than the entire table capacity, clear it
  if fieldSize > table.maxSize then
    { table with entries := #[], size := 0 }
  else
    -- Evict oldest entries (at end of array) until there's room
    let rec evict (entries : Array HeaderField) (curSize : Nat) (fuel : Nat) : (Array HeaderField × Nat) :=
      match fuel with
      | 0 => (entries, curSize)
      | fuel' + 1 =>
        if curSize + fieldSize <= table.maxSize then
          (entries, curSize)
        else if entries.size == 0 then
          (#[], 0)
        else
          -- Evict the last entry (oldest per RFC 7541 FIFO order)
          let lastIdx := entries.size - 1
          let evicted := entries[lastIdx]!
          let evictedSize := headerFieldSize evicted
          let newSize := if curSize >= evictedSize then curSize - evictedSize else 0
          evict (entries.pop) newSize fuel'
    let (evictedEntries, evictedSize) := evict table.entries table.size table.entries.size
    -- Insert new entry at the front (index 0 = newest per RFC 7541)
    { table with entries := #[field] ++ evictedEntries, size := evictedSize + fieldSize }

-- HPACK Encoder State
structure HPACKEncoder where
  dynamicTable : DynamicTable
  deriving Repr

-- HPACK Decoder State
structure HPACKDecoder where
  dynamicTable : DynamicTable
  deriving Repr

-- Initialize HPACK encoder
def initHPACKEncoder (maxTableSize : Nat := 4096) : HPACKEncoder := {
  dynamicTable := initDynamicTable maxTableSize
}

-- Initialize HPACK decoder
def initHPACKDecoder (maxTableSize : Nat := 4096) : HPACKDecoder := {
  dynamicTable := initDynamicTable maxTableSize
}

-- Find header in static table
def findInStaticTable (name : String) (value : String) : Option Nat :=
  let rec find (i : Nat) : Option Nat :=
    if i >= staticTable.size then none
    else
      let entry := staticTable[i]!
      if entry.name == name && entry.value == value then some (i + 1)
      else find (i + 1)
  find 0

-- Find header name in static table
def findNameInStaticTable (name : String) : Option Nat :=
  let rec find (i : Nat) : Option Nat :=
    if i >= staticTable.size then none
    else
      let entry := staticTable[i]!
      if entry.name == name then some (i + 1)
      else find (i + 1)
  find 0

-- Find header in dynamic table
-- With newest-at-front ordering, array index i maps to HPACK index staticTable.size + i + 1
def findInDynamicTable (table : DynamicTable) (name : String) (value : String) : Option Nat :=
  let rec find (i : Nat) : Option Nat :=
    if i >= table.entries.size then none
    else
      let entry : HeaderField := table.entries[i]!
      if entry.name == name && entry.value == value then some (staticTable.size + i + 1)
      else find (i + 1)
  find 0

-- Find header name in dynamic table
def findNameInDynamicTable (table : DynamicTable) (name : String) : Option Nat :=
  let rec find (i : Nat) : Option Nat :=
    if i >= table.entries.size then none
    else
      let entry : HeaderField := table.entries[i]!
      if entry.name == name then some (staticTable.size + i + 1)
      else find (i + 1)
  find 0

-- Encode integer with variable length (RFC 7541 Section 5.1)
def encodeInteger (value : Nat) (prefixBits : Nat) (prefixValue : Nat) : ByteArray :=
  let maxPrefixValue := (1 <<< prefixBits) - 1
  if value < maxPrefixValue then
    -- Value fits in prefix
    ByteArray.mk #[ (prefixValue ||| value).toUInt8 ]
  else
    -- Value doesn't fit, use variable length encoding
    let rec encodeRemaining (remaining : Nat) (acc : ByteArray) : ByteArray :=
      if remaining < 128 then
        acc.push remaining.toUInt8
      else
        let newAcc := acc.push ((remaining % 128 + 128).toUInt8)
        encodeRemaining (remaining / 128) newAcc
    let firstByte := ByteArray.mk #[ (prefixValue ||| maxPrefixValue).toUInt8 ]
    let remaining := value - maxPrefixValue
    firstByte ++ encodeRemaining remaining (ByteArray.mk #[])

/-- RFC 7541 Appendix B Huffman table.
    Each entry: (symbol : UInt8, code : UInt32, codeLen : UInt8). -/
private def hpackHuffmanTable : Array (UInt8 × UInt32 × UInt8) := #[
  (0, 0x1ff8, 13), (1, 0x7fffd8, 23), (2, 0xfffffe2, 28), (3, 0xfffffe3, 28),
  (4, 0xfffffe4, 28), (5, 0xfffffe5, 28), (6, 0xfffffe6, 28), (7, 0xfffffe7, 28),
  (8, 0xfffffe8, 28), (9, 0xffffea, 24), (10, 0x3ffffffc, 30), (11, 0xfffffe9, 28),
  (12, 0xfffffea, 28), (13, 0x3ffffffd, 30), (14, 0xfffffeb, 28), (15, 0xfffffec, 28),
  (16, 0xfffffed, 28), (17, 0xfffffee, 28), (18, 0xfffffef, 28), (19, 0xffffff0, 28),
  (20, 0xffffff1, 28), (21, 0xffffff2, 28), (22, 0x3ffffffe, 30), (23, 0xffffff3, 28),
  (24, 0xffffff4, 28), (25, 0xffffff5, 28), (26, 0xffffff6, 28), (27, 0xffffff7, 28),
  (28, 0xffffff8, 28), (29, 0xffffff9, 28), (30, 0xffffffa, 28), (31, 0xffffffb, 28),
  (32, 0x14, 6), (33, 0x3f8, 10), (34, 0x3f9, 10), (35, 0xffa, 12),
  (36, 0x1ff9, 13), (37, 0x15, 6), (38, 0xf8, 8), (39, 0x7fa, 11),
  (40, 0x3fa, 10), (41, 0x3fb, 10), (42, 0xf9, 8), (43, 0x7fb, 11),
  (44, 0xfa, 8), (45, 0x16, 6), (46, 0x17, 6), (47, 0x18, 6),
  (48, 0x0, 5), (49, 0x1, 5), (50, 0x2, 5), (51, 0x19, 6),
  (52, 0x1a, 6), (53, 0x1b, 6), (54, 0x1c, 6), (55, 0x1d, 6),
  (56, 0x1e, 6), (57, 0x1f, 6),
  (58, 0x5c, 7), (59, 0xfb, 8), (60, 0x7ffc, 15), (61, 0x20, 6),
  (62, 0xffb, 12), (63, 0x3fc, 10), (64, 0x1ffa, 13),
  (65, 0x21, 6), (66, 0x5d, 7), (67, 0x5e, 7), (68, 0x5f, 7),
  (69, 0x60, 7), (70, 0x61, 7), (71, 0x62, 7), (72, 0x63, 7),
  (73, 0x64, 7), (74, 0x65, 7), (75, 0x66, 7), (76, 0x67, 7),
  (77, 0x68, 7), (78, 0x69, 7), (79, 0x6a, 7), (80, 0x6b, 7),
  (81, 0x6c, 7), (82, 0x6d, 7), (83, 0x6e, 7), (84, 0x6f, 7),
  (85, 0x70, 7), (86, 0x71, 7), (87, 0x72, 7), (88, 0xfc, 8),
  (89, 0x73, 7), (90, 0xfd, 8),
  (91, 0x1ffb, 13), (92, 0x7fff0, 19), (93, 0x1ffc, 13), (94, 0x3ffc, 14),
  (95, 0x22, 6), (96, 0x7ffd, 15),
  (97, 0x3, 5), (98, 0x23, 6), (99, 0x4, 5), (100, 0x24, 6),
  (101, 0x5, 5), (102, 0x25, 6), (103, 0x26, 6), (104, 0x27, 6),
  (105, 0x6, 5), (106, 0x74, 7), (107, 0x75, 7), (108, 0x28, 6),
  (109, 0x29, 6), (110, 0x2a, 6), (111, 0x7, 5), (112, 0x2b, 6),
  (113, 0x76, 7), (114, 0x2c, 6), (115, 0x8, 5), (116, 0x9, 5),
  (117, 0x2d, 6), (118, 0x77, 7), (119, 0x78, 7), (120, 0x79, 7),
  (121, 0x7a, 7), (122, 0x7b, 7),
  (123, 0x7fffe, 19), (124, 0x7fc, 11), (125, 0x3ffd, 14), (126, 0x1ffd, 13),
  (127, 0xffffffc, 28), (128, 0xfffe6, 20), (129, 0x3fffd2, 22), (130, 0xfffe7, 20),
  (131, 0xfffe8, 20), (132, 0x3fffd3, 22), (133, 0x3fffd4, 22), (134, 0x3fffd5, 22),
  (135, 0x7fffd9, 23), (136, 0x3fffd6, 22), (137, 0x7fffda, 23), (138, 0x7fffdb, 23),
  (139, 0x7fffdc, 23), (140, 0x7fffdd, 23), (141, 0x7fffde, 23), (142, 0xffffeb, 24),
  (143, 0x7fffdf, 23), (144, 0xffffec, 24), (145, 0xffffed, 24), (146, 0x3fffd7, 22),
  (147, 0x7fffe0, 23), (148, 0xffffee, 24), (149, 0x7fffe1, 23), (150, 0x7fffe2, 23),
  (151, 0x7fffe3, 23), (152, 0x7fffe4, 23), (153, 0x1fffdc, 21), (154, 0x3fffd8, 22),
  (155, 0x7fffe5, 23), (156, 0x3fffd9, 22), (157, 0x7fffe6, 23), (158, 0x7fffe7, 23),
  (159, 0xffffef, 24), (160, 0x3fffda, 22), (161, 0x1fffdd, 21), (162, 0xfffe9, 20),
  (163, 0x3fffdb, 22), (164, 0x3fffdc, 22), (165, 0x7fffe8, 23), (166, 0x7fffe9, 23),
  (167, 0x1fffde, 21), (168, 0x7fffea, 23), (169, 0x3fffdd, 22), (170, 0x3fffde, 22),
  (171, 0xfffff0, 24), (172, 0x1fffdf, 21), (173, 0x3fffdf, 22), (174, 0x7fffeb, 23),
  (175, 0x7fffec, 23), (176, 0x1fffe0, 21), (177, 0x1fffe1, 21), (178, 0x3fffe0, 22),
  (179, 0x1fffe2, 21), (180, 0x7fffed, 23), (181, 0x3fffe1, 22), (182, 0x7fffee, 23),
  (183, 0x7fffef, 23), (184, 0xfffea, 20), (185, 0x3fffe2, 22), (186, 0x3fffe3, 22),
  (187, 0x3fffe4, 22), (188, 0x7ffff0, 23), (189, 0x3fffe5, 22), (190, 0x3fffe6, 22),
  (191, 0x7ffff1, 23), (192, 0x3ffffe0, 26), (193, 0x3ffffe1, 26), (194, 0xfffeb, 20),
  (195, 0x7fff1, 19), (196, 0x3fffe7, 22), (197, 0x7ffff2, 23), (198, 0x3fffe8, 22),
  (199, 0x1ffffec, 25), (200, 0x3ffffe2, 26), (201, 0x3ffffe3, 26), (202, 0x3ffffe4, 26),
  (203, 0x7ffffde, 27), (204, 0x7ffffdf, 27), (205, 0x3ffffe5, 26), (206, 0xfffff1, 24),
  (207, 0x1ffffed, 25), (208, 0x7fff2, 19), (209, 0x1fffe3, 21), (210, 0x3ffffe6, 26),
  (211, 0x7ffffe0, 27), (212, 0x7ffffe1, 27), (213, 0x3ffffe7, 26), (214, 0x7ffffe2, 27),
  (215, 0xfffff2, 24), (216, 0x1fffe4, 21), (217, 0x1fffe5, 21), (218, 0x3ffffe8, 26),
  (219, 0x3ffffe9, 26), (220, 0xffffffd, 28), (221, 0x7ffffe3, 27), (222, 0x7ffffe4, 27),
  (223, 0x7ffffe5, 27), (224, 0xfffec, 20), (225, 0xfffff3, 24), (226, 0xfffed, 20),
  (227, 0x1fffe6, 21), (228, 0x3fffe9, 22), (229, 0x1fffe7, 21), (230, 0x1fffe8, 21),
  (231, 0x7ffff3, 23), (232, 0x3fffea, 22), (233, 0x3fffeb, 22), (234, 0x1ffffee, 25),
  (235, 0x1ffffef, 25), (236, 0xfffff4, 24), (237, 0xfffff5, 24), (238, 0x3ffffea, 26),
  (239, 0x7ffff4, 23), (240, 0x3ffffeb, 26), (241, 0x7ffffe6, 27), (242, 0x3ffffec, 26),
  (243, 0x3ffffed, 26), (244, 0x7ffffe7, 27), (245, 0x7ffffe8, 27), (246, 0x7ffffe9, 27),
  (247, 0x7ffffea, 27), (248, 0x7ffffeb, 27), (249, 0xffffffe, 28), (250, 0x7ffffec, 27),
  (251, 0x7ffffed, 27), (252, 0x7ffffee, 27), (253, 0x7ffffef, 27), (254, 0x7fffff0, 27),
  (255, 0x3ffffee, 26)
]

-- Huffman encoding (RFC 7541 §5.2 and Appendix B)
-- Encodes each byte using the HPACK Huffman code table.
-- Pads the final byte with EOS prefix bits (all 1s).
def huffmanEncode (bytes : ByteArray) : ByteArray := Id.run do
  -- Build a lookup from symbol to (code, codeLen)
  -- Use UInt64 to avoid overflow: Huffman codes can be up to 30 bits,
  -- and with 7 residual bits we may need 37 bits total (exceeds UInt32).
  let mut bitBuf : UInt64 := 0
  let mut bitCount : Nat := 0
  let mut result : ByteArray := ByteArray.empty
  for i in [:bytes.size] do
    let sym := bytes.get! i
    -- Look up the Huffman code for this symbol
    let (_, code, codeLen) := hpackHuffmanTable[sym.toNat]!
    let cl := codeLen.toNat
    -- Shift buffer left by codeLen and OR in the code bits
    bitBuf := (bitBuf <<< cl.toUInt64) ||| code.toUInt64
    bitCount := bitCount + cl
    -- Emit complete bytes
    while bitCount >= 8 do
      let shift := bitCount - 8
      let byte := (bitBuf >>> shift.toUInt64) &&& 0xFF
      result := result.push byte.toUInt8
      bitBuf := bitBuf &&& ((1 <<< shift.toUInt64) - 1)
      bitCount := shift
  -- Pad the last byte with 1-bits (EOS prefix) per RFC 7541 §5.2
  if bitCount > 0 then
    let padBits := 8 - bitCount
    let padded := (bitBuf <<< padBits.toUInt64) ||| ((1 <<< padBits.toUInt64) - 1)
    result := result.push (padded &&& 0xFF).toUInt8
  return result

-- Encode string literal (RFC 7541 Section 5.2)
-- Uses Huffman encoding when requested per RFC 7541 Appendix B
def encodeString (str : String) (huffman : Bool := false) : ByteArray :=
  let bytes := str.toUTF8
  let encodedBytes := if huffman then huffmanEncode bytes else bytes
  let lengthBytes := encodeInteger encodedBytes.size 7 (if huffman then 0x80 else 0x00)
  lengthBytes ++ encodedBytes

/-- Decode Huffman-encoded bytes using RFC 7541 Appendix B table. -/
def huffmanDecode (encoded : ByteArray) : Option ByteArray := Id.run do
  let mut result : ByteArray := ByteArray.empty
  let mut bitBuf : UInt32 := 0
  let mut bitCount : Nat := 0
  let mut i := 0
  while i < encoded.size do
    bitBuf := (bitBuf <<< 8) ||| (encoded.get! i).toUInt32
    bitCount := bitCount + 8
    i := i + 1
    let mut matched := true
    while matched && bitCount >= 5 do
      matched := false
      for entry in hpackHuffmanTable do
        let (sym, code, codeLen) := entry
        let cl := codeLen.toNat
        if cl <= bitCount then
          let shift := bitCount - cl
          let topBits := bitBuf >>> shift.toUInt32
          if topBits == code then
            result := result.push sym
            let mask := (1 : UInt32) <<< shift.toUInt32
            bitBuf := bitBuf &&& (mask - 1)
            bitCount := shift
            matched := true
            break
  if bitCount > 0 && bitCount <= 7 then
    return some result
  else if bitCount == 0 then
    return some result
  else
    return some result  -- Be lenient with padding

-- Encode header field (RFC 7541 compliant implementation)
/-- Headers that MUST use never-indexed representation (§7.1.3). -/
private def isSensitiveHeader (name : String) : Bool :=
  name == "authorization" || name == "cookie" || name == "set-cookie" ||
  name == "proxy-authorization"

def encodeHeaderField (encoder : HPACKEncoder) (field : HeaderField) : ByteArray × HPACKEncoder :=
  -- Sensitive headers: emit as never-indexed (§6.2.3)
  if isSensitiveHeader field.name then
    match findNameInStaticTable field.name with
    | some index =>
      let nameIndexBytes := encodeInteger index 4 0x10
      let valueBytes := encodeString field.value  -- plain, not Huffman for sensitive
      (nameIndexBytes ++ valueBytes, encoder)  -- NOT added to dynamic table
    | none =>
      let nameBytes := encodeString field.name
      let valueBytes := encodeString field.value
      (ByteArray.mk #[0x10] ++ nameBytes ++ valueBytes, encoder)
  else
  -- 1) Check exact match in static table → indexed
  match findInStaticTable field.name field.value with
  | some index =>
    let encoded := encodeInteger index 7 0x80
    (encoded, encoder)
  | none =>
  -- 2) Check exact match in dynamic table → indexed
  match findInDynamicTable encoder.dynamicTable field.name field.value with
  | some dynIdx =>
    -- dynIdx already includes staticTable.size offset from findInDynamicTable
    let encoded := encodeInteger dynIdx 7 0x80
    (encoded, encoder)
  | none =>
  -- 3) Check name match in dynamic table → literal with incremental indexing
  match findNameInDynamicTable encoder.dynamicTable field.name with
  | some dynIdx =>
    -- dynIdx already includes staticTable.size offset from findNameInDynamicTable
    let nameIndexBytes := encodeInteger dynIdx 6 0x40
    let valueBytes := encodeString field.value (huffman := true)
    let newEncoder := { encoder with dynamicTable := addToDynamicTable encoder.dynamicTable field }
    (nameIndexBytes ++ valueBytes, newEncoder)
  | none =>
  -- 4) Check name match in static table → literal with incremental indexing
  match findNameInStaticTable field.name with
  | some index =>
    let nameIndexBytes := encodeInteger index 6 0x40
    let valueBytes := encodeString field.value (huffman := true)
    let newEncoder := { encoder with dynamicTable := addToDynamicTable encoder.dynamicTable field }
    (nameIndexBytes ++ valueBytes, newEncoder)
  | none =>
    -- 5) New name → literal with incremental indexing, Huffman-encode both
    let nameBytes := encodeString field.name (huffman := true)
    let valueBytes := encodeString field.value (huffman := true)
    let newEncoder := { encoder with dynamicTable := addToDynamicTable encoder.dynamicTable field }
    (ByteArray.mk #[0x40] ++ nameBytes ++ valueBytes, newEncoder)

-- Encode header list
def encodeHeaderList (encoder : HPACKEncoder) (headers : Array HeaderField) : ByteArray × HPACKEncoder :=
  let rec encodeHeaders (i : Nat) (currentEncoder : HPACKEncoder) (acc : ByteArray) : ByteArray × HPACKEncoder :=
    if i >= headers.size then (acc, currentEncoder)
    else
      let header := headers[i]!
      let (encoded, newEncoder) := encodeHeaderField currentEncoder header
      encodeHeaders (i + 1) newEncoder (acc ++ encoded)
  encodeHeaders 0 encoder (ByteArray.mk #[])

-- Decode integer from byte array
def decodeInteger (data : ByteArray) (pos : Nat) (prefixBits : Nat) : Option (Nat × Nat) :=
  if pos >= data.size then none
  else
    let prefixValue := (1 <<< prefixBits) - 1
    let firstByte := data[pos]!.toNat
    let value := firstByte &&& prefixValue

    if value < prefixValue then
      some (value, pos + 1)
    else
      let rec decodeRemaining (currentPos : Nat) (result : Nat) (shift : Nat) : Option (Nat × Nat) :=
        if currentPos >= data.size then none
        else if shift > 28 then none  -- Overflow protection
        else
          let byte := data[currentPos]!.toNat
          let newResult := result + ((byte &&& 127) <<< shift)
          if byte &&& 128 == 0 then
            some (newResult, currentPos + 1)
          else
            decodeRemaining (currentPos + 1) newResult (shift + 7)
      decodeRemaining (pos + 1) value 0

-- Decode string literal
def decodeString (data : ByteArray) (pos : Nat) : Option (String × Nat) :=
  if pos >= data.size then none
  else
    let huffman := (data[pos]! &&& 0x80) != 0
    match decodeInteger data pos 7 with
    | some (length, newPos) =>
      if newPos + length > data.size then none
      else
        let bytes := data.extract newPos (newPos + length)
        let decodedStr := if huffman then
             match huffmanDecode bytes with
             | some decoded =>
                match String.fromUTF8? decoded with
                | some s => s
                | none => "<Binary>"
             | none => "<HuffmanDecodeFailed>"
        else
             match String.fromUTF8? bytes with
             | some s => s
             | none => "<Binary>"

        some (decodedStr, newPos + length)
    | none => none

-- Get header from table (static or dynamic)
-- Static table: index 1..staticTable.size
-- Dynamic table: index staticTable.size+1.. with newest at array index 0
def getHeaderFromTable (dynamicTable : DynamicTable) (index : Nat) : Option HeaderField :=
  if index == 0 then none
  else if index <= staticTable.size then
    some (staticTable[index - 1]!)
  else
    let dynamicIndex := index - staticTable.size - 1
    if dynamicIndex < dynamicTable.entries.size then
      some (dynamicTable.entries[dynamicIndex]!)
    else none

-- Decode header field
def decodeHeaderField (decoder : HPACKDecoder) (data : ByteArray) (pos : Nat) : Option (HeaderField × Nat × HPACKDecoder) :=
  if pos >= data.size then none
  else
    let firstByte := data[pos]!.toNat

    if firstByte &&& 0x80 != 0 then
      -- Indexed header field
      match decodeInteger data pos 7 with
      | some (index, newPos) =>
        match getHeaderFromTable decoder.dynamicTable index with
        | some field => some (field, newPos, decoder)
        | none => none
      | none => none

    else if firstByte &&& 0x40 != 0 then
      -- Literal header field with incremental indexing (§6.2.1)
      match decodeInteger data pos 6 with
      | some (nameIndex, pos1) =>
        if nameIndex == 0 then
          -- New name: decode name, then value
          match decodeString data pos1 with
          | some (name, pos2) =>
            match decodeString data pos2 with
            | some (value, pos3) =>
              let field := { name := name, value := value }
              let newDecoder := { decoder with dynamicTable := addToDynamicTable decoder.dynamicTable field }
              some (field, pos3, newDecoder)
            | none => none
          | none => none
        else
          -- Name from table
          match getHeaderFromTable decoder.dynamicTable nameIndex with
          | some tableField =>
            match decodeString data pos1 with
            | some (value, pos2) =>
              let field := { name := tableField.name, value := value }
              let newDecoder := { decoder with dynamicTable := addToDynamicTable decoder.dynamicTable field }
              some (field, pos2, newDecoder)
            | none => none
          | none => none
      | none => none

    else if firstByte &&& 0x20 != 0 then
      -- Dynamic table size update (RFC 7541 §6.3)
      -- Prefix 001xxxxx signals a dynamic table size change.
      -- Parse the new max size from the 5-bit prefix integer,
      -- then resize the dynamic table, evicting entries from the
      -- end (oldest) until the table fits within the new max size.
      match decodeInteger data pos 5 with
      | some (newSize, newPos) =>
        -- Evict oldest entries (at end of array) until table fits
        let rec evictForResize (entries : Array HeaderField) (curSize : Nat) (fuel : Nat) : (Array HeaderField × Nat) :=
          match fuel with
          | 0 => (entries, curSize)
          | fuel' + 1 =>
            if curSize <= newSize then (entries, curSize)
            else if entries.size == 0 then (#[], 0)
            else
              let lastIdx := entries.size - 1
              let evicted := entries[lastIdx]!
              let evictedSize := headerFieldSize evicted
              let newCurSize := if curSize >= evictedSize then curSize - evictedSize else 0
              evictForResize (entries.pop) newCurSize fuel'
        let (evictedEntries, evictedSize) := evictForResize decoder.dynamicTable.entries decoder.dynamicTable.size decoder.dynamicTable.entries.size
        let newTable : DynamicTable := {
          entries := evictedEntries,
          size := evictedSize,
          maxSize := newSize
        }
        let newDecoder := { decoder with dynamicTable := newTable }
        -- Return empty field name to signal this is a control instruction (skipped by decodeHeaderList)
        some ({ name := "", value := "" }, newPos, newDecoder)
      | none => none

    else if firstByte &&& 0x10 != 0 then
      -- Literal header field never indexed (§6.2.3)
      match decodeInteger data pos 4 with
      | some (nameIndex, pos1) =>
        if nameIndex == 0 then
          match decodeString data pos1 with
          | some (name, pos2) =>
            match decodeString data pos2 with
            | some (value, pos3) =>
              some ({ name := name, value := value }, pos3, decoder)
            | none => none
          | none => none
        else
          match getHeaderFromTable decoder.dynamicTable nameIndex with
          | some tableField =>
            match decodeString data pos1 with
            | some (value, pos2) =>
              some ({ name := tableField.name, value := value }, pos2, decoder)
            | none => none
          | none => none
      | none => none

    else
      -- Literal header field without indexing (§6.2.2)
      match decodeInteger data pos 4 with
      | some (nameIndex, pos1) =>
        if nameIndex == 0 then
          match decodeString data pos1 with
          | some (name, pos2) =>
            match decodeString data pos2 with
            | some (value, pos3) =>
              some ({ name := name, value := value }, pos3, decoder)
            | none => none
          | none => none
        else
          match getHeaderFromTable decoder.dynamicTable nameIndex with
          | some tableField =>
            match decodeString data pos1 with
            | some (value, pos2) =>
              some ({ name := tableField.name, value := value }, pos2, decoder)
            | none => none
          | none => none
      | none => none

-- Decode header list
def decodeHeaderList (decoder : HPACKDecoder) (data : ByteArray) : Option (Array HeaderField × HPACKDecoder) :=
  let rec decodeHeaders (pos : Nat) (headers : Array HeaderField) (currentDecoder : HPACKDecoder) : Option (Array HeaderField × HPACKDecoder) :=
    if pos >= data.size then
      some (headers, currentDecoder)
    else
      match decodeHeaderField currentDecoder data pos with
      | some (field, newPos, newDecoder) =>
        let newHeaders := if field.name != "" then headers.push field else headers  -- Skip control instructions
        if newPos > pos then
          decodeHeaders newPos newHeaders newDecoder
        else
          none  -- Prevent infinite loops
      | none => none
  decodeHeaders 0 #[] decoder

-- Public function to encode headers (stateless — creates a fresh encoder each time)
def encodeHeadersPublic (headers : Array (String × String)) : ByteArray :=
  let headerFields := headers.map (fun (name, value) => { name := name, value := value })
  let encoder := initHPACKEncoder
  let (encoded, _) := encodeHeaderList encoder headerFields
  encoded

-- Public function to encode headers with persistent encoder state (RFC 7541 compliant)
-- The encoder state MUST be preserved across header blocks within the same HTTP/2 connection.
def encodeHeadersStateful (encoder : HPACKEncoder) (headers : Array (String × String)) : ByteArray × HPACKEncoder :=
  let headerFields := headers.map (fun (name, value) => { name := name, value := value })
  encodeHeaderList encoder headerFields

end LeanServer
