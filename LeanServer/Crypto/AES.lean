import LeanServer.Core.Basic

namespace LeanServer.AES

-- ============================================================================
-- VERIFIED ACCESS: Zero get! / set! / [...]! in this file.
-- All array access uses ByteArray.get/set with bounds proved by omega.
-- ============================================================================

/-- AES S-Box table (FIPS 197) -/
def sBox : ByteArray := ByteArray.mk #[
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

/-- S-Box has exactly 256 entries -/
theorem sBox_size : sBox.size = 256 := by native_decide

/-- AES Round Constants (Rcon) -/
def rCon : ByteArray := ByteArray.mk #[
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]

theorem rCon_size : rCon.size = 10 := by native_decide

/-- Substitute a single byte using S-Box — VERIFIED: UInt8.toNat < 256 = sBox.size -/
@[inline]
def subByte (b : UInt8) : UInt8 :=
  sBox.get b.toNat (by have := sBox_size; have := b.toNat_lt; omega)

/-- "xtime" operation: multiply by 2 in GF(2^8) -/
@[inline]
def xtime (x : UInt8) : UInt8 :=
  let s := x <<< 1
  if x &&& 0x80 != 0 then s ^^^ 0x1b else s

/-- Multiply by x in GF(2^8) -/
@[inline]
def mul (a b : UInt8) : UInt8 := (Id.run do
  let mut p : UInt8 := 0
  let mut x : UInt8 := a
  let mut y : UInt8 := b
  for _ in [0:8] do
    if (y &&& 1) != 0 then
      p := p ^^^ x
    let highBit := (x &&& 0x80) != 0
    x := x <<< 1
    if highBit then
      x := x ^^^ 0x1b
    y := y >>> 1
  p)

-- ============================================================================
-- SIZE LEMMAS
-- ============================================================================

private theorem subBytes_size (state : ByteArray) :
    (ByteArray.mk (state.data.map subByte)).size = state.size := by
  cases state; simp [ByteArray.size, Array.size_map]

private theorem mk16_size (a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 a11 a12 a13 a14 a15 : UInt8) :
    (ByteArray.mk #[a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15]).size = 16 := by
  rfl

private theorem set_size (a : ByteArray) (i : Nat) (v : UInt8) (h : i < a.size) :
    (a.set i v h).size = a.size := by
  cases a; simp [ByteArray.set, ByteArray.size, Array.size_set]

-- ============================================================================
-- AES CORE OPERATIONS (Verified access on 16-byte blocks)
-- ============================================================================

/-- SubBytes step: apply S-Box to state — verified via subByte -/
@[inline] def subBytes (state : ByteArray) : ByteArray :=
  ByteArray.mk (state.data.map subByte)

/-- Column-Major ShiftRows (FIPS 197) — verified: all indices < 16 -/
@[inline] def shiftRowsColMajor (state : ByteArray) (h : state.size = 16 := by omega) : ByteArray :=
  ByteArray.mk #[
    state.get  0 (by omega), state.get  5 (by omega), state.get 10 (by omega), state.get 15 (by omega),
    state.get  4 (by omega), state.get  9 (by omega), state.get 14 (by omega), state.get  3 (by omega),
    state.get  8 (by omega), state.get 13 (by omega), state.get  2 (by omega), state.get  7 (by omega),
    state.get 12 (by omega), state.get  1 (by omega), state.get  6 (by omega), state.get 11 (by omega)
  ]

/-- MixColumns step — verified access on 16-byte state -/
@[inline] def mixColumns (state : ByteArray) (h : state.size = 16 := by omega) : ByteArray :=
  let mixCol (s0 s1 s2 s3 : UInt8) : (UInt8 × UInt8 × UInt8 × UInt8) :=
    ( (xtime s0) ^^^ (xtime s1) ^^^ s1 ^^^ s2 ^^^ s3,
      s0 ^^^ (xtime s1) ^^^ (xtime s2) ^^^ s2 ^^^ s3,
      s0 ^^^ s1 ^^^ (xtime s2) ^^^ (xtime s3) ^^^ s3,
      (xtime s0) ^^^ s0 ^^^ s1 ^^^ s2 ^^^ (xtime s3) )
  let (d00, d01, d02, d03) := mixCol
    (state.get 0 (by omega)) (state.get 1 (by omega))
    (state.get 2 (by omega)) (state.get 3 (by omega))
  let (d10, d11, d12, d13) := mixCol
    (state.get 4 (by omega)) (state.get 5 (by omega))
    (state.get 6 (by omega)) (state.get 7 (by omega))
  let (d20, d21, d22, d23) := mixCol
    (state.get 8 (by omega)) (state.get 9 (by omega))
    (state.get 10 (by omega)) (state.get 11 (by omega))
  let (d30, d31, d32, d33) := mixCol
    (state.get 12 (by omega)) (state.get 13 (by omega))
    (state.get 14 (by omega)) (state.get 15 (by omega))
  ByteArray.mk #[d00, d01, d02, d03, d10, d11, d12, d13, d20, d21, d22, d23, d30, d31, d32, d33]

/-- AddRoundKey — verified XOR on 16-byte blocks -/
@[inline] def addRoundKey (state roundKey : ByteArray)
    (hs : state.size = 16 := by omega) (hr : roundKey.size = 16 := by omega) : ByteArray :=
  ByteArray.mk #[
    state.get 0  (by omega) ^^^ roundKey.get 0  (by omega),
    state.get 1  (by omega) ^^^ roundKey.get 1  (by omega),
    state.get 2  (by omega) ^^^ roundKey.get 2  (by omega),
    state.get 3  (by omega) ^^^ roundKey.get 3  (by omega),
    state.get 4  (by omega) ^^^ roundKey.get 4  (by omega),
    state.get 5  (by omega) ^^^ roundKey.get 5  (by omega),
    state.get 6  (by omega) ^^^ roundKey.get 6  (by omega),
    state.get 7  (by omega) ^^^ roundKey.get 7  (by omega),
    state.get 8  (by omega) ^^^ roundKey.get 8  (by omega),
    state.get 9  (by omega) ^^^ roundKey.get 9  (by omega),
    state.get 10 (by omega) ^^^ roundKey.get 10 (by omega),
    state.get 11 (by omega) ^^^ roundKey.get 11 (by omega),
    state.get 12 (by omega) ^^^ roundKey.get 12 (by omega),
    state.get 13 (by omega) ^^^ roundKey.get 13 (by omega),
    state.get 14 (by omega) ^^^ roundKey.get 14 (by omega),
    state.get 15 (by omega) ^^^ roundKey.get 15 (by omega)
  ]

-- ============================================================================
-- KEY EXPANSION — Uses runtime bounds checks for extract-based intermediates.
-- Key expansion operates on variable-sized buffers built incrementally,
-- so static proofs of extract sizes require invariant tracking that is
-- disproportionate effort vs. risk. We use `if h : ... then ... else ...`
-- pattern: access is verified at runtime, no panic possible.
-- ============================================================================

/-- Safe 4-byte word access: returns (b0, b1, b2, b3) or default -/
@[inline] private def getWord4 (w : ByteArray) : (UInt8 × UInt8 × UInt8 × UInt8) :=
  if h : w.size ≥ 4 then
    (w.get 0 (by omega), w.get 1 (by omega), w.get 2 (by omega), w.get 3 (by omega))
  else (0, 0, 0, 0)

/-- Key Expansion for AES-128 -/
def expandKey (key : ByteArray) : ByteArray :=
  if key.size != 16 then key
  else
    let rec loop (w : ByteArray) (i : Nat) (rconIdx : Nat) (fuel : Nat) : ByteArray :=
      match fuel with
      | 0 => w
      | fuel + 1 =>
        if w.size >= 176 then w
        else
          let temp := w.extract (i - 4) i
          let (t0, t1, t2, t3) := getWord4 temp
          let (newWord, newRconIdx) :=
            if i % 16 == 0 then
              -- RotWord + SubWord + Rcon
              let rot0 := subByte t1
              let rot1 := subByte t2
              let rot2 := subByte t3
              let rot3 := subByte t0
              let r := if hr : rconIdx < rCon.size then rCon.get rconIdx hr else 0
              let prev := w.extract (i - 16) (i - 12)
              let (p0, p1, p2, p3) := getWord4 prev
              (ByteArray.mk #[p0 ^^^ rot0 ^^^ r, p1 ^^^ rot1, p2 ^^^ rot2, p3 ^^^ rot3], rconIdx + 1)
            else
              let prev := w.extract (i - 16) (i - 12)
              let (p0, p1, p2, p3) := getWord4 prev
              (ByteArray.mk #[p0 ^^^ t0, p1 ^^^ t1, p2 ^^^ t2, p3 ^^^ t3], rconIdx)
          loop (w ++ newWord) (i + 4) newRconIdx fuel
    loop key 16 0 100

-- ============================================================================
-- INTERNAL ROUND FUNCTION (Verified loop body)
-- ============================================================================

/-- One AES round (SubBytes + ShiftRows + MixColumns + AddRoundKey) — verified -/
private def aesRound (state : ByteArray) (roundKey : ByteArray)
    (hs : state.size = 16) (hr : roundKey.size = 16) : ByteArray :=
  let s1 := subBytes state
  have hs1 : s1.size = 16 := by
    show (ByteArray.mk (state.data.map subByte)).size = 16
    rw [subBytes_size]; exact hs
  let s2 := shiftRowsColMajor s1 hs1
  have hs2 : s2.size = 16 := by rfl
  let s3 := mixColumns s2 hs2
  have hs3 : s3.size = 16 := by rfl
  addRoundKey s3 roundKey hs3 hr

/-- Final AES round (SubBytes + ShiftRows + AddRoundKey, no MixColumns) — verified -/
private def aesFinalRound (state : ByteArray) (roundKey : ByteArray)
    (hs : state.size = 16) (hr : roundKey.size = 16) : ByteArray :=
  let s1 := subBytes state
  have hs1 : s1.size = 16 := by
    show (ByteArray.mk (state.data.map subByte)).size = 16
    rw [subBytes_size]; exact hs
  let s2 := shiftRowsColMajor s1 hs1
  have hs2 : s2.size = 16 := by rfl
  addRoundKey s2 roundKey hs2 hr

/-- Extract round key safely — returns 16-byte slice or zeros -/
@[inline] private def getRoundKey (expanded : ByteArray) (round : Nat) : ByteArray :=
  let offset := round * 16
  let rk := expanded.extract offset (offset + 16)
  if rk.size = 16 then rk else ByteArray.mk (List.replicate 16 0).toArray

private theorem getRoundKey_size (expanded : ByteArray) (round : Nat) :
    (getRoundKey expanded round).size = 16 := by
  unfold getRoundKey
  simp only
  split
  · assumption
  · rfl

/-- AES-128 Encrypt Block — verified internal rounds -/
def encryptBlock (keyExpanded : ByteArray) (block : ByteArray) : ByteArray :=
  if hb : block.size ≠ 16 then block
  else
    have hb16 : block.size = 16 := by omega
    let rk0 := getRoundKey keyExpanded 0
    have hrk0 : rk0.size = 16 := getRoundKey_size keyExpanded 0
    let state := addRoundKey block rk0 hb16 hrk0

    -- 9 Main Rounds — each round produces 16-byte output (verified)
    have hark : state.size = 16 := by rfl
    let state := (List.range 9).foldl (fun (s : { s : ByteArray // s.size = 16 }) i =>
      let round := i + 1
      let rk := getRoundKey keyExpanded round
      have hrk : rk.size = 16 := getRoundKey_size keyExpanded round
      ⟨aesRound s.val rk s.property hrk, by rfl⟩
    ) ⟨state, hark⟩

    -- Final Round
    let rk10 := getRoundKey keyExpanded 10
    have hrk10 : rk10.size = 16 := getRoundKey_size keyExpanded 10
    aesFinalRound state.val rk10 state.property hrk10

/-- XOR two ByteArrays — verified access -/
def xorBytes (a b : ByteArray) : ByteArray :=
  let len := if a.size < b.size then a.size else b.size
  let bytes := (List.range len).map fun i =>
    if ha : i < a.size then
      if hb : i < b.size then
        a.get i ha ^^^ b.get i hb
      else 0
    else 0
  ByteArray.mk bytes.toArray

-- ============================================================================
-- GCM MODE — Verified access for 16-byte block operations
-- ============================================================================

/-- Get bit i (0..127) of block — verified -/
def getBit (block : ByteArray) (i : Nat) : Bool :=
  let byteIdx := i / 8
  let bitIdx := 7 - (i % 8)
  if h : byteIdx < block.size then
    (block.get byteIdx h >>> bitIdx.toUInt8) &&& 1 == 1
  else false

/-- Shift 16-byte block right by 1 bit — verified -/
def shiftRightBlock (v : ByteArray) : ByteArray :=
  let (_, res) := (List.range v.size).foldl (fun (carry, acc) i =>
    if h : i < v.size then
      let b := v.get i h
      let nextCarry := b &&& 1
      let newByte := (b >>> 1) ||| (carry <<< 7)
      (nextCarry, acc.push newByte)
    else (carry, acc)
  ) ((0 : UInt8), ByteArray.empty)
  res

/-- GHASH Galois Field multiplication — verified -/
def gfMul (x y : ByteArray) : ByteArray :=
  let z := ByteArray.mk (List.replicate 16 0).toArray
  let v := y
  let r := ByteArray.mk (#[0xE1] ++ (List.replicate 15 0).toArray)

  let (finalZ, _) := (List.range 128).foldl (fun (z, v) i =>
    let z := if getBit x i then xorBytes z v else z
    let lsbV := if h : 15 < v.size then (v.get 15 h &&& 1) != 0 else false
    let v := shiftRightBlock v
    let v := if lsbV then xorBytes v r else v
    (z, v)
  ) (z, v)
  finalZ

/-- Increment 32-bit counter (last 4 bytes of 16-byte block) — verified -/
def inc32 (iv : ByteArray) : ByteArray :=
  if hiv : iv.size ≠ 16 then iv
  else
    have h16 : iv.size = 16 := by omega
    let b3 := iv.get 15 (by omega)
    let b2 := iv.get 14 (by omega)
    let b1 := iv.get 13 (by omega)
    let b0 := iv.get 12 (by omega)

    let val := (b0.toNat <<< 24) + (b1.toNat <<< 16) + (b2.toNat <<< 8) + b3.toNat + 1
    let valMod := val % 4294967296

    -- Construct result explicitly: keep first 12 bytes, replace last 4
    ByteArray.mk #[
      iv.get 0 (by omega), iv.get 1 (by omega), iv.get 2 (by omega), iv.get 3 (by omega),
      iv.get 4 (by omega), iv.get 5 (by omega), iv.get 6 (by omega), iv.get 7 (by omega),
      iv.get 8 (by omega), iv.get 9 (by omega), iv.get 10 (by omega), iv.get 11 (by omega),
      ((valMod / 16777216) % 256).toUInt8,
      ((valMod / 65536) % 256).toUInt8,
      ((valMod / 256) % 256).toUInt8,
      (valMod % 256).toUInt8
    ]

/-- GHASH function -/
def ghash (h : ByteArray) (aad : ByteArray) (ciphertext : ByteArray) : ByteArray :=
  let y := ByteArray.mk (List.replicate 16 0).toArray

  let rec process (y : ByteArray) (data : ByteArray) (i : Nat) : ByteArray :=
    if i >= data.size then y
    else
      let chunkLen := if data.size - i < 16 then data.size - i else 16
      let chunk := data.extract i (i + chunkLen)
      let padded := chunk ++ ByteArray.mk (List.replicate (16 - chunkLen) 0).toArray
      let y := xorBytes y padded
      let y := gfMul y h
      process y data (i + 16)
    termination_by data.size - i

  let y := process y aad 0
  let y := process y ciphertext 0

  let lenAad := aad.size * 8
  let lenC := ciphertext.size * 8
  let lenBlock := ByteArray.mk #[
    (lenAad >>> 56).toUInt8, (lenAad >>> 48).toUInt8, (lenAad >>> 40).toUInt8, (lenAad >>> 32).toUInt8,
    (lenAad >>> 24).toUInt8, (lenAad >>> 16).toUInt8, (lenAad >>> 8).toUInt8, lenAad.toUInt8,
    (lenC >>> 56).toUInt8, (lenC >>> 48).toUInt8, (lenC >>> 40).toUInt8, (lenC >>> 32).toUInt8,
    (lenC >>> 24).toUInt8, (lenC >>> 16).toUInt8, (lenC >>> 8).toUInt8, lenC.toUInt8
  ]

  let y := xorBytes y lenBlock
  gfMul y h

-- ============================================================================
-- AES-GCM ENCRYPT / DECRYPT
-- ============================================================================

/-- AES-GCM Encrypt -/
def aesGCMEncrypt (key : ByteArray) (iv : ByteArray) (plaintext : ByteArray) (aad : ByteArray) : (ByteArray × ByteArray) :=
  let expKey := expandKey key

  let zeroBlock := ByteArray.mk (List.replicate 16 0).toArray
  let h := encryptBlock expKey zeroBlock

  let j0 := if iv.size == 12 then iv ++ ByteArray.mk #[0, 0, 0, 1] else iv

  let cb := inc32 j0

  let rec encryptLoop (cb : ByteArray) (i : Nat) (ct : ByteArray) : ByteArray :=
    if i >= plaintext.size then ct
    else
      let pad := encryptBlock expKey cb
      let chunkLen := if plaintext.size - i < 16 then plaintext.size - i else 16
      let pChunk := plaintext.extract i (i + chunkLen)
      let cChunk := xorBytes pChunk (pad.extract 0 chunkLen)
      encryptLoop (inc32 cb) (i + 16) (ct ++ cChunk)
    termination_by plaintext.size - i

  let ciphertext := encryptLoop cb 0 ByteArray.empty

  let ghashTag := ghash h aad ciphertext
  let j0Enc := encryptBlock expKey j0
  let tag := xorBytes ghashTag j0Enc

  (ciphertext, tag)

/-- AES-GCM Decrypt -/
def aesGCMDecrypt (key : ByteArray) (iv : ByteArray) (ciphertextWithTag : ByteArray) (aad : ByteArray) : Option ByteArray :=
  if ciphertextWithTag.size < 16 then none
  else
    let tagLen := 16
    let ctLen := ciphertextWithTag.size - tagLen
    let ciphertext := ciphertextWithTag.extract 0 ctLen
    let receivedTag := ciphertextWithTag.extract ctLen ciphertextWithTag.size

    let expKey := expandKey key

    let zeroBlock := ByteArray.mk (List.replicate 16 0).toArray
    let h := encryptBlock expKey zeroBlock

    let j0 := if iv.size == 12 then iv ++ ByteArray.mk #[0, 0, 0, 1] else iv

    let ghashTag := ghash h aad ciphertext
    let j0Enc := encryptBlock expKey j0
    let expectedTag := xorBytes ghashTag j0Enc

    if !constantTimeEqual receivedTag expectedTag then
      none
    else
      let cb := inc32 j0

      let rec decryptLoop (cb : ByteArray) (i : Nat) (pt : ByteArray) : ByteArray :=
        if i >= ciphertext.size then pt
        else
          let pad := encryptBlock expKey cb
          let chunkLen := if ciphertext.size - i < 16 then ciphertext.size - i else 16
          let cChunk := ciphertext.extract i (i + chunkLen)
          let pChunk := xorBytes cChunk (pad.extract 0 chunkLen)
          decryptLoop (inc32 cb) (i + 16) (pt ++ pChunk)
        termination_by ciphertext.size - i

      some (decryptLoop cb 0 ByteArray.empty)

-- ============================================================================
-- AES-256 SUPPORT (14 rounds, 256-bit / 32-byte keys)
-- ============================================================================

/-- Key Expansion for AES-256 (produces 240 bytes = 15 round keys × 16 bytes) -/
def expandKey256 (key : ByteArray) : ByteArray :=
  if key.size != 32 then key
  else
    let rec loop (w : ByteArray) (i : Nat) (rconIdx : Nat) (fuel : Nat) : ByteArray :=
      match fuel with
      | 0 => w
      | fuel + 1 =>
        if w.size >= 240 then w
        else
          let temp := w.extract (i - 4) i
          let (t0, t1, t2, t3) := getWord4 temp
          let (newWord, newRconIdx) :=
            if i % 32 == 0 then
              let rot0 := subByte t1
              let rot1 := subByte t2
              let rot2 := subByte t3
              let rot3 := subByte t0
              let r := if hr : rconIdx < rCon.size then rCon.get rconIdx hr else 0
              let prev := w.extract (i - 32) (i - 28)
              let (p0, p1, p2, p3) := getWord4 prev
              (ByteArray.mk #[p0 ^^^ rot0 ^^^ r, p1 ^^^ rot1, p2 ^^^ rot2, p3 ^^^ rot3], rconIdx + 1)
            else if i % 32 == 16 then
              let sub0 := subByte t0
              let sub1 := subByte t1
              let sub2 := subByte t2
              let sub3 := subByte t3
              let prev := w.extract (i - 32) (i - 28)
              let (p0, p1, p2, p3) := getWord4 prev
              (ByteArray.mk #[p0 ^^^ sub0, p1 ^^^ sub1, p2 ^^^ sub2, p3 ^^^ sub3], rconIdx)
            else
              let prev := w.extract (i - 32) (i - 28)
              let (p0, p1, p2, p3) := getWord4 prev
              (ByteArray.mk #[p0 ^^^ t0, p1 ^^^ t1, p2 ^^^ t2, p3 ^^^ t3], rconIdx)
          loop (w ++ newWord) (i + 4) newRconIdx fuel
    loop key 32 0 200

/-- AES-256 Encrypt Block (14 rounds) — verified internal rounds -/
def aes256EncryptBlock (keyExpanded : ByteArray) (block : ByteArray) : ByteArray :=
  if hb : block.size ≠ 16 then block
  else
    have hb16 : block.size = 16 := by omega
    let rk0 := getRoundKey keyExpanded 0
    have hrk0 : rk0.size = 16 := getRoundKey_size keyExpanded 0
    let state := addRoundKey block rk0 hb16 hrk0

    -- 13 Main Rounds
    have hark : state.size = 16 := by rfl
    let state := (List.range 13).foldl (fun (s : { s : ByteArray // s.size = 16 }) i =>
      let round := i + 1
      let rk := getRoundKey keyExpanded round
      have hrk : rk.size = 16 := getRoundKey_size keyExpanded round
      ⟨aesRound s.val rk s.property hrk, by rfl⟩
    ) ⟨state, hark⟩

    -- Final Round (no MixColumns)
    let rk14 := getRoundKey keyExpanded 14
    have hrk14 : rk14.size = 16 := getRoundKey_size keyExpanded 14
    aesFinalRound state.val rk14 state.property hrk14

/-- AES-256-GCM Encrypt -/
def aes256GCMEncrypt (key : ByteArray) (iv : ByteArray) (plaintext : ByteArray) (aad : ByteArray) : (ByteArray × ByteArray) :=
  let expKey := expandKey256 key

  let zeroBlock := ByteArray.mk (List.replicate 16 0).toArray
  let h := aes256EncryptBlock expKey zeroBlock

  let j0 := if iv.size == 12 then iv ++ ByteArray.mk #[0, 0, 0, 1] else iv

  let cb := inc32 j0

  let rec encryptLoop (cb : ByteArray) (i : Nat) (ct : ByteArray) : ByteArray :=
    if i >= plaintext.size then ct
    else
      let pad := aes256EncryptBlock expKey cb
      let chunkLen := if plaintext.size - i < 16 then plaintext.size - i else 16
      let pChunk := plaintext.extract i (i + chunkLen)
      let cChunk := xorBytes pChunk (pad.extract 0 chunkLen)
      encryptLoop (inc32 cb) (i + 16) (ct ++ cChunk)
    termination_by plaintext.size - i

  let ciphertext := encryptLoop cb 0 ByteArray.empty

  let ghashTag := ghash h aad ciphertext
  let j0Enc := aes256EncryptBlock expKey j0
  let tag := xorBytes ghashTag j0Enc

  (ciphertext, tag)

/-- AES-256-GCM Decrypt -/
def aes256GCMDecrypt (key : ByteArray) (iv : ByteArray) (ciphertextWithTag : ByteArray) (aad : ByteArray) : Option ByteArray :=
  if ciphertextWithTag.size < 16 then none
  else
    let tagLen := 16
    let ctLen := ciphertextWithTag.size - tagLen
    let ciphertext := ciphertextWithTag.extract 0 ctLen
    let receivedTag := ciphertextWithTag.extract ctLen ciphertextWithTag.size

    let expKey := expandKey256 key

    let zeroBlock := ByteArray.mk (List.replicate 16 0).toArray
    let h := aes256EncryptBlock expKey zeroBlock

    let j0 := if iv.size == 12 then iv ++ ByteArray.mk #[0, 0, 0, 1] else iv

    let ghashTag := ghash h aad ciphertext
    let j0Enc := aes256EncryptBlock expKey j0
    let expectedTag := xorBytes ghashTag j0Enc

    if !constantTimeEqual receivedTag expectedTag then
      none
    else
      let cb := inc32 j0

      let rec decryptLoop (cb : ByteArray) (i : Nat) (pt : ByteArray) : ByteArray :=
        if i >= ciphertext.size then pt
        else
          let pad := aes256EncryptBlock expKey cb
          let chunkLen := if ciphertext.size - i < 16 then ciphertext.size - i else 16
          let cChunk := ciphertext.extract i (i + chunkLen)
          let pChunk := xorBytes cChunk (pad.extract 0 chunkLen)
          decryptLoop (inc32 cb) (i + 16) (pt ++ pChunk)
        termination_by ciphertext.size - i

      some (decryptLoop cb 0 ByteArray.empty)

-- ============================================================================
-- INVERSE OPERATIONS (For AES Decryption / Roundtrip Proofs)
-- ============================================================================

/-- Inverse S-Box table (FIPS 197, Table 14) -/
def invSBox : ByteArray := ByteArray.mk #[
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

/-- Inverse S-Box has exactly 256 entries -/
theorem invSBox_size : invSBox.size = 256 := by native_decide

/-- Substitute a single byte using inverse S-Box -/
@[inline]
def invSubByte (b : UInt8) : UInt8 :=
  invSBox.get b.toNat (by have := invSBox_size; have := b.toNat_lt; omega)

/-- Inverse SubBytes step: apply inverse S-Box to state -/
@[inline] def invSubBytes (state : ByteArray) : ByteArray :=
  ByteArray.mk (state.data.map invSubByte)

/-- Inverse ShiftRows (Column-Major) — verified: all indices < 16 -/
@[inline] def invShiftRowsColMajor (state : ByteArray) (h : state.size = 16 := by omega) : ByteArray :=
  ByteArray.mk #[
    state.get  0 (by omega), state.get 13 (by omega), state.get 10 (by omega), state.get  7 (by omega),
    state.get  4 (by omega), state.get  1 (by omega), state.get 14 (by omega), state.get 11 (by omega),
    state.get  8 (by omega), state.get  5 (by omega), state.get  2 (by omega), state.get 15 (by omega),
    state.get 12 (by omega), state.get  9 (by omega), state.get  6 (by omega), state.get  3 (by omega)
  ]

/-- Inverse MixColumns step — verified access on 16-byte state -/
@[inline] def invMixColumns (state : ByteArray) (h : state.size = 16 := by omega) : ByteArray :=
  let invMixCol (s0 s1 s2 s3 : UInt8) : (UInt8 × UInt8 × UInt8 × UInt8) :=
    ( mul 0x0e s0 ^^^ mul 0x0b s1 ^^^ mul 0x0d s2 ^^^ mul 0x09 s3,
      mul 0x09 s0 ^^^ mul 0x0e s1 ^^^ mul 0x0b s2 ^^^ mul 0x0d s3,
      mul 0x0d s0 ^^^ mul 0x09 s1 ^^^ mul 0x0e s2 ^^^ mul 0x0b s3,
      mul 0x0b s0 ^^^ mul 0x0d s1 ^^^ mul 0x09 s2 ^^^ mul 0x0e s3 )
  let (d00, d01, d02, d03) := invMixCol
    (state.get 0 (by omega)) (state.get 1 (by omega))
    (state.get 2 (by omega)) (state.get 3 (by omega))
  let (d10, d11, d12, d13) := invMixCol
    (state.get 4 (by omega)) (state.get 5 (by omega))
    (state.get 6 (by omega)) (state.get 7 (by omega))
  let (d20, d21, d22, d23) := invMixCol
    (state.get 8 (by omega)) (state.get 9 (by omega))
    (state.get 10 (by omega)) (state.get 11 (by omega))
  let (d30, d31, d32, d33) := invMixCol
    (state.get 12 (by omega)) (state.get 13 (by omega))
    (state.get 14 (by omega)) (state.get 15 (by omega))
  ByteArray.mk #[d00, d01, d02, d03, d10, d11, d12, d13, d20, d21, d22, d23, d30, d31, d32, d33]

-- ============================================================================
-- SIMD OPTIMIZATIONS (Pure Lean — delegates to verified core)
-- ============================================================================

namespace SIMD

@[inline] def subBytesSIMD (state : ByteArray) : ByteArray := subBytes state

@[inline] def shiftRowsSIMD (state : ByteArray) (h : state.size = 16 := by omega) : ByteArray :=
  shiftRowsColMajor state h

def mixColumnsSIMD (state : ByteArray) (h : state.size = 16 := by omega) : ByteArray :=
  mixColumns state h

@[inline] def addRoundKeySIMD (state roundKey : ByteArray) : ByteArray :=
  xorBytes state roundKey

def encryptBlockSIMD (expKey : ByteArray) (block : ByteArray) : ByteArray :=
  encryptBlock expKey block

def aesCTR_SIMD (key : ByteArray) (iv : ByteArray) (plaintext : ByteArray) : ByteArray :=
  let expKey := expandKey key

  let rec process (offset : Nat) (counter : ByteArray) (result : ByteArray) : ByteArray :=
    if _h : offset >= plaintext.size then result
    else
      let keystream := encryptBlock expKey counter
      let chunkSize := Nat.min 16 (plaintext.size - offset)
      let plaintextChunk := plaintext.extract offset (offset + chunkSize)
      let ciphertextChunk := xorBytes plaintextChunk (keystream.extract 0 chunkSize)
      let nextCounter := inc32 counter
      process (offset + chunkSize) nextCounter (result ++ ciphertextChunk)
  termination_by plaintext.size - offset
  decreasing_by
    simp only [Nat.min_def]
    split <;> omega

  process 0 iv ByteArray.empty

end SIMD

end LeanServer.AES
