import LeanServer.Core.Basic

/-!
  # ByteSlice: Zero-Copy Sub-Range Reference (ROADMAP F8.1)

  A `ByteSlice` references a contiguous sub-range of a `ByteArray`
  without copying. Bounds are enforced by construction — the `h_bounds`
  proof term makes out-of-bounds access unrepresentable.

  ## Motivation
  The HTTPServer module has 193+ `ByteArray.extract` and `++` calls.
  Each copies data. `ByteSlice` eliminates copies for read-only access
  to protocol headers, payload windows, and parser outputs.

  ## Safety Guarantee
  The dependent type `offset + length ≤ backing.size` means:
  - Every index `i < length` maps to `backing[offset + i]`
  - No runtime bounds check is needed — safety is compile-time
  - Slicing a slice produces a new proof, not a new allocation
-/

namespace LeanServer

-- ============================================================================
-- Core Type
-- ============================================================================

/-- A zero-copy view into a `ByteArray`.
    The proof `h_bounds` ensures `offset + length ≤ backing.size`,
    making out-of-bounds access unrepresentable at the type level. -/
structure ByteSlice where
  backing : ByteArray
  offset  : Nat
  length  : Nat
  h_bounds : offset + length ≤ backing.size

-- ============================================================================
-- Construction
-- ============================================================================

/-- Create a ByteSlice covering the entire ByteArray -/
def ByteSlice.ofByteArray (ba : ByteArray) : ByteSlice where
  backing := ba
  offset := 0
  length := ba.size
  h_bounds := by omega

/-- Create a ByteSlice from offset and length, returning none if out of bounds -/
def ByteSlice.mk? (ba : ByteArray) (off len : Nat) : Option ByteSlice :=
  if h : off + len ≤ ba.size then
    some ⟨ba, off, len, h⟩
  else
    none

-- ============================================================================
-- Access
-- ============================================================================

/-- Get byte at index `i` within the slice — VERIFIED: proof that i < length
    ensures the access is within the backing array bounds. -/
@[inline] def ByteSlice.get (s : ByteSlice) (i : Nat) (h : i < s.length := by omega) : UInt8 :=
  s.backing.get (s.offset + i) (by have := s.h_bounds; omega)

/-- Get byte at index `i` within the slice, unchecked (caller ensures i < length) -/
def ByteSlice.get! (s : ByteSlice) (i : Nat) : UInt8 :=
  s.backing.get! (s.offset + i)

/-- Get byte at index `i` or return 0 if out of bounds -/
def ByteSlice.getD (s : ByteSlice) (i : Nat) : UInt8 :=
  if h : i < s.length then s.get i h else 0

/-- Check if the slice is empty -/
def ByteSlice.isEmpty (s : ByteSlice) : Bool := s.length == 0

-- ============================================================================
-- Multi-byte Readers (Verified)
-- ============================================================================

/-- Read a UInt16 big-endian from the slice at a given offset — verified -/
@[inline] def ByteSlice.getUInt16BE (s : ByteSlice) (off : Nat)
    (h : off + 2 ≤ s.length := by omega) : UInt16 :=
  let hi := (s.get (off) (by omega)).toUInt16
  let lo := (s.get (off + 1) (by omega)).toUInt16
  hi <<< 8 ||| lo

/-- Read a UInt32 big-endian from the slice at a given offset — verified -/
@[inline] def ByteSlice.getUInt32BE (s : ByteSlice) (off : Nat)
    (h : off + 4 ≤ s.length := by omega) : UInt32 :=
  let b0 := (s.get (off) (by omega)).toUInt32
  let b1 := (s.get (off + 1) (by omega)).toUInt32
  let b2 := (s.get (off + 2) (by omega)).toUInt32
  let b3 := (s.get (off + 3) (by omega)).toUInt32
  b0 <<< 24 ||| b1 <<< 16 ||| b2 <<< 8 ||| b3

/-- Read a 3-byte big-endian Nat from the slice at a given offset — verified -/
@[inline] def ByteSlice.getUInt24BE (s : ByteSlice) (off : Nat)
    (h : off + 3 ≤ s.length := by omega) : Nat :=
  (s.get (off) (by omega)).toNat <<< 16 +
  (s.get (off + 1) (by omega)).toNat <<< 8 +
  (s.get (off + 2) (by omega)).toNat

-- ============================================================================
-- Sub-slicing (zero-copy)
-- ============================================================================

/-- Take a sub-slice starting at `start` with given `len`.
    Returns `none` if the sub-range exceeds the current slice. -/
def ByteSlice.slice (s : ByteSlice) (start len : Nat) : Option ByteSlice :=
  if h : start + len ≤ s.length then
    have hb : (s.offset + start) + len ≤ s.backing.size := by
      have := s.h_bounds; omega
    some ⟨s.backing, s.offset + start, len, hb⟩
  else
    none

/-- Drop the first `n` bytes from the slice -/
def ByteSlice.drop (s : ByteSlice) (n : Nat) : ByteSlice :=
  if h : n ≤ s.length then
    have hb : (s.offset + n) + (s.length - n) ≤ s.backing.size := by
      have := s.h_bounds; omega
    ⟨s.backing, s.offset + n, s.length - n, hb⟩
  else
    have hb : (s.offset + s.length) + 0 ≤ s.backing.size := by
      have := s.h_bounds; omega
    ⟨s.backing, s.offset + s.length, 0, hb⟩

/-- Take the first `n` bytes from the slice -/
def ByteSlice.take (s : ByteSlice) (n : Nat) : ByteSlice :=
  if h : n ≤ s.length then
    have hb : s.offset + n ≤ s.backing.size := by
      have := s.h_bounds; omega
    ⟨s.backing, s.offset, n, hb⟩
  else
    s  -- If n > length, return the whole slice

-- ============================================================================
-- Conversion
-- ============================================================================

/-- Extract the slice contents as a new ByteArray (copies data) -/
def ByteSlice.toByteArray (s : ByteSlice) : ByteArray :=
  s.backing.extract s.offset (s.offset + s.length)

/-- Compare two slices for equality (byte-by-byte) -/
def ByteSlice.beq (a b : ByteSlice) : Bool :=
  if heq : a.length = b.length then
    let rec go (i : Nat) : Bool :=
      if h : i < a.length then
        have hb : i < b.length := by omega
        if a.get i h == b.get i hb then go (i + 1) else false
      else true
    go 0
  else false

instance : BEq ByteSlice := ⟨ByteSlice.beq⟩

-- ============================================================================
-- Fold / Iteration
-- ============================================================================

/-- Fold over all bytes in the slice -/
def ByteSlice.foldl (s : ByteSlice) (f : α → UInt8 → α) (init : α) : α :=
  let rec go (i : Nat) (acc : α) : α :=
    if h : i < s.length then go (i + 1) (f acc (s.get i h)) else acc
  go 0 init

/-- Convert slice to a list of bytes -/
def ByteSlice.toList (s : ByteSlice) : List UInt8 :=
  s.foldl (fun acc b => acc ++ [b]) []

-- ============================================================================
-- Proofs
-- ============================================================================

/-- A ByteSlice's length never exceeds its backing array size -/
theorem ByteSlice.length_le_backing_size (s : ByteSlice) :
    s.length ≤ s.backing.size := by
  have := s.h_bounds; omega

/-- KEY PROOF: Any valid slice index maps to a valid backing array index.
    This is the fundamental safety guarantee of ByteSlice. -/
theorem ByteSlice.get_in_bounds (s : ByteSlice) (i : Nat) (h : i < s.length) :
    s.offset + i < s.backing.size := by
  have := s.h_bounds; omega

/-- An empty slice from any ByteArray is valid -/
theorem ByteSlice.empty_valid (ba : ByteArray) :
    0 + 0 ≤ ba.size := by omega

/-- ofByteArray produces a slice with length = backing size -/
theorem ByteSlice.ofByteArray_length (ba : ByteArray) :
    (ByteSlice.ofByteArray ba).length = ba.size := by
  simp [ByteSlice.ofByteArray]

/-- ofByteArray produces a slice with offset 0 -/
theorem ByteSlice.ofByteArray_offset (ba : ByteArray) :
    (ByteSlice.ofByteArray ba).offset = 0 := by
  simp [ByteSlice.ofByteArray]

/-- drop 0 preserves the slice length -/
theorem ByteSlice.drop_zero_length (s : ByteSlice) :
    (s.drop 0).length = s.length := by
  simp [ByteSlice.drop]

/-- take with n ≤ length gives exactly n bytes -/
theorem ByteSlice.take_length (s : ByteSlice) (n : Nat) (h : n ≤ s.length) :
    (s.take n).length = n := by
  simp [ByteSlice.take, h]

/-- isEmpty iff length = 0 -/
theorem ByteSlice.isEmpty_iff (s : ByteSlice) :
    s.isEmpty = true ↔ s.length = 0 := by
  simp [ByteSlice.isEmpty, BEq.beq]

/-- slice produces a sub-slice with the requested length -/
theorem ByteSlice.slice_length (s : ByteSlice) (start len : Nat)
    (h : start + len ≤ s.length) :
    ∃ sl, s.slice start len = some sl ∧ sl.length = len := by
  simp [ByteSlice.slice, h]

end LeanServer
