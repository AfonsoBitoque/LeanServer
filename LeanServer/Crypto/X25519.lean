namespace LeanServer.X25519

/-- Field P = 2^255 - 19 -/
def P : Nat := (2^255) - 19

def A24 : Nat := 121665

/-- Addition mod P -/
def add (a b : Nat) : Nat := (a + b) % P

/-- Subtraction mod P -/
def sub (a b : Nat) : Nat :=
  if a >= b then (a - b) % P
  else (a + P - b) % P

/-- Multiplication mod P -/
def mul (a b : Nat) : Nat := (a * b) % P

/-- Inverse mod P using Fermat's Little Theorem (a^(P-2) mod P) -/
def modPow (b e m : Nat) : Nat :=
  match e with
  | 0 => 1
  | e' + 1 =>
    let half := modPow b ((e' + 1) / 2) m
    let halfSq := (half * half) % m
    if (e' + 1) % 2 == 0 then halfSq
    else (halfSq * b) % m
termination_by e

def inv (x : Nat) : Nat := modPow x (P - 2) P

/-- X25519 Scalar Mult (Montgomery Ladder) -/
def scalarMultNat (n : Nat) (u : Nat) : Nat :=
  let rec loop (i : Nat) (x_1 x_2 z_2 x_3 z_3 : Nat) : Nat × Nat × Nat × Nat :=
    match i with
    | 0 => (x_2, z_2, x_3, z_3)
    | Nat.succ k =>
      let bit := (n >>> k) &&& 1
      let swap := bit == 1

      -- CSWAP
      let (x_2, x_3) := if swap then (x_3, x_2) else (x_2, x_3)
      let (z_2, z_3) := if swap then (z_3, z_2) else (z_2, z_3)

      -- Ladder step
      let A := add x_2 z_2
      let AA := mul A A
      let B := sub x_2 z_2
      let BB := mul B B
      let E := sub AA BB
      let C := add x_3 z_3
      let D := sub x_3 z_3
      let DA := mul D A
      let CB := mul C B

      let x_3_new := mul (add DA CB) (add DA CB)
      let z_3_new := mul x_1 (mul (sub DA CB) (sub DA CB))
      let x_2_new := mul AA BB
      let z_2_new := mul E (add AA (mul A24 E))

      -- CSWAP back
      let (x_2, x_3) := if swap then (x_3_new, x_2_new) else (x_2_new, x_3_new)
      let (z_2, z_3) := if swap then (z_3_new, z_2_new) else (z_2_new, z_3_new)

      loop k x_1 x_2 z_2 x_3 z_3

  let (x_2, z_2, _, _) := loop 255 u 1 0 u 1
  mul x_2 (inv z_2)

/-- ByteArray to Nat (Little Endian) -/
def decodeScalar (b : ByteArray) : Nat :=
  let rec aux (i : Nat) (acc : Nat) : Nat :=
    if _h : i >= b.size then acc
    else aux (i+1) (acc + (b[i]!.toNat <<< (8 * i)))
  termination_by b.size - i
  decreasing_by omega
  aux 0 0

/-- Nat to ByteArray (Little Endian, 32 bytes) -/
def encodeScalar (n : Nat) : ByteArray :=
  let rec aux (i : Nat) (acc : Array UInt8) : Array UInt8 :=
    if _h : i >= 32 then acc
    else
      let byte := (n >>> (8 * i)) &&& 0xFF
      aux (i+1) (acc.push byte.toUInt8)
  termination_by 32 - i
  decreasing_by omega
  ByteArray.mk (aux 0 #[])

/-- Clamp the scalar (as per X25519 spec) -/
def clamp (k : ByteArray) : ByteArray :=
  if k.size != 32 then k else
  let bytes := k.data
  let b0 := bytes[0]! &&& 248
  let b31 := (bytes[31]! &&& 127) ||| 64
  let newBytes := bytes.set! 0 b0 |>.set! 31 b31
  ByteArray.mk newBytes

/-- Main API: scalarMult -/
def scalarmult (scalar : ByteArray) (element : ByteArray) : ByteArray :=
  let s := decodeScalar (clamp scalar)
  let e := decodeScalar element
  let r := scalarMultNat s e
  encodeScalar r

/-- Base point multiplication (u = 9) -/
def scalarmult_base (scalar : ByteArray) : ByteArray :=
  let list : List UInt8 := (9 : UInt8) :: List.replicate 31 (0 : UInt8)
  let u9 := ByteArray.mk list.toArray
  scalarmult scalar u9

end LeanServer.X25519
