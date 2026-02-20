/-!
  # Safe Byte Access
  Provides bounds-checked byte array access for network protocol parsing.
  Prevents panic!/crash from out-of-bounds `get!` when processing untrusted network data.

  ## Usage
  ```lean
  -- Instead of: let b := data.get! offset
  -- Use:        let b ← safeGet data offset |>.toIO "context"
  -- Or:         match safeGet data offset with | some b => ... | none => ...
  ```
-/

namespace LeanServer

/-- Safe byte access — returns none if index is out of bounds -/
@[inline] def safeGet (data : ByteArray) (idx : Nat) : Option UInt8 :=
  if h : idx < data.size then some (data.get idx) else none

/-- Safe byte access with default — returns 0 if out of bounds -/
@[inline] def safeGetD (data : ByteArray) (idx : Nat) (default : UInt8 := 0) : UInt8 :=
  if h : idx < data.size then data.get idx else default

/-- Read a UInt16 big-endian from byte array at offset (safe) -/
@[inline] def safeGetUInt16BE (data : ByteArray) (offset : Nat) : Option UInt16 :=
  if h : offset + 1 < data.size then
    let hi := (data.get (offset)).toUInt16
    let lo := (data.get (offset + 1)).toUInt16
    some (hi <<< 8 ||| lo)
  else none

/-- Read a UInt32 big-endian from byte array at offset (safe) -/
@[inline] def safeGetUInt32BE (data : ByteArray) (offset : Nat) : Option UInt32 :=
  if h : offset + 3 < data.size then
    let b0 := (data.get (offset)).toUInt32
    let b1 := (data.get (offset + 1)).toUInt32
    let b2 := (data.get (offset + 2)).toUInt32
    let b3 := (data.get (offset + 3)).toUInt32
    some (b0 <<< 24 ||| b1 <<< 16 ||| b2 <<< 8 ||| b3)
  else none

/-- Read a UInt64 big-endian from byte array at offset (safe) -/
@[inline] def safeGetUInt64BE (data : ByteArray) (offset : Nat) : Option UInt64 :=
  if h : offset + 7 < data.size then
    let b0 := (data.get (offset)).toUInt64
    let b1 := (data.get (offset + 1)).toUInt64
    let b2 := (data.get (offset + 2)).toUInt64
    let b3 := (data.get (offset + 3)).toUInt64
    let b4 := (data.get (offset + 4)).toUInt64
    let b5 := (data.get (offset + 5)).toUInt64
    let b6 := (data.get (offset + 6)).toUInt64
    let b7 := (data.get (offset + 7)).toUInt64
    some (b0 <<< 56 ||| b1 <<< 48 ||| b2 <<< 40 ||| b3 <<< 32 |||
          b4 <<< 24 ||| b5 <<< 16 ||| b6 <<< 8 ||| b7)
  else none

/-- Safe extract — returns empty ByteArray if range is out of bounds -/
@[inline] def safeExtract (data : ByteArray) (start len : Nat) : Option ByteArray :=
  if start + len ≤ data.size then
    some (data.extract start (start + len))
  else none

/-- Verify minimum size before processing a network buffer -/
@[inline] def requireMinSize (data : ByteArray) (minSize : Nat) (context : String := "") : Except String Unit :=
  if data.size >= minSize then Except.ok ()
  else Except.error s!"buffer too small: expected ≥{minSize} bytes, got {data.size} ({context})"

/-- Extension for Option to convert to IO with error message -/
def Option.toIO {α : Type} (opt : Option α) (errMsg : String) : IO α :=
  match opt with
  | some v => pure v
  | none => throw (IO.Error.userError errMsg)

end LeanServer
