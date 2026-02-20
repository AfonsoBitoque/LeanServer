import LeanServer.Core.Basic


namespace LeanServer.RSA

/-- Modular Exponentiation: b^e mod n -/
def modPow (b e n : Nat) : Nat :=
  match e with
  | 0 => 1
  | e' + 1 =>
    if (e' + 1) % 2 == 0 then
      let half := modPow b ((e' + 1) / 2) n
      (half * half) % n
    else
      let half := modPow b ((e' + 1) / 2) n
      (half * half * b) % n
termination_by e

/-- Convert Integer to Octet String (I2OSP) -/
def i2osp (x : Nat) (len : Nat) : ByteArray :=
  let bytes := (List.range len).map (fun i =>
    let shift := (len - 1 - i) * 8
    ((x >>> shift) &&& 0xFF).toUInt8
  )
  ByteArray.mk bytes.toArray

/-- Convert Octet String to Integer (OS2IP) -/
def os2ip (bytes : ByteArray) : Nat :=
  bytes.data.foldl (fun acc b => (acc <<< 8) + b.toNat) 0

/-- RSA Sign Primitive: s = m^d mod n -/
def rsaep (n d m : Nat) : Nat :=
  modPow m d n

/-- MGF1 (Mask Generation Function) using SHA-256
    Takes a hashFunc parameter to avoid circular dependency with Crypto.lean -/
def mgf1 (hashFunc : ByteArray -> ByteArray) (seed : ByteArray) (maskLen : Nat) : ByteArray :=
  let hLen := 32 -- SHA256 length
  let count := (maskLen + hLen - 1) / hLen
  let (mask, _) := (List.range count).foldl (fun (acc, counter) _ =>
    let c := i2osp counter 4
    let h := hashFunc (seed ++ c)
    (acc ++ h, counter + 1)
  ) (ByteArray.empty, 0)
  mask.extract 0 maskLen

/-- XOR two ByteArrays -/
def xorBytes (a b : ByteArray) : ByteArray :=
  let len := if a.size < b.size then a.size else b.size
  let bytes := List.range len |>.map (fun i => a[i]! ^^^ b[i]!)
  ByteArray.mk bytes.toArray

/-- EMSA-PSS-ENCODE -/
def emsa_pss_encode (hashFunc : ByteArray -> ByteArray) (mHash : ByteArray) (emBits : Nat) (salt : ByteArray) : Option ByteArray :=
  let hLen := 32
  let sLen := salt.size
  let emLen := (emBits + 7) / 8

  if mHash.size != hLen then none else
  if emLen < hLen + sLen + 2 then none else

  let mPrime := ByteArray.mk (List.replicate 8 0).toArray ++ mHash ++ salt
  let h := hashFunc mPrime

  let ps := ByteArray.mk (List.replicate (emLen - sLen - hLen - 2) 0).toArray
  let db := ps ++ ByteArray.mk #[0x01] ++ salt
  let dbMask := mgf1 hashFunc h (emLen - hLen - 1)

  -- xor db and dbMask
  let maskedDB := xorBytes db dbMask

  -- Set leftmost bits to 0? (8*emLen - emBits)
  -- For RSA 2048, emBits = 2047? Or 2048?
  -- Usually emBits = modBits - 1.
  -- If modBits is 2048, emBits = 2047.
  -- emLen = 256.
  -- Leftmost bit of maskedDB[0] needs to be masked.
  -- 8*256 = 2048. 2048 - 2047 = 1 bit to clear.
  let bitMask := (0xFF >>> (8 * emLen - emBits)).toUInt8
  let maskedDB0 := maskedDB[0]! &&& bitMask
  let maskedDB := maskedDB.set! 0 maskedDB0

  let em := maskedDB ++ h ++ ByteArray.mk #[0xbc]
  some em

/-- RSASSA-PSS-SIGN (with random salt per RFC 8017 §8.1.1 / TLS 1.3 §4.2.3) -/
def rsassa_pss_sign (hashFunc : ByteArray -> ByteArray) (n d : Nat) (msgHash : ByteArray) : IO (Option ByteArray) := do
  let modBits := n.log2
  -- TLS 1.3 §4.2.3: salt length MUST equal hash output length (32 bytes for SHA-256)
  let salt ← IO.getRandomBytes 32

  match emsa_pss_encode hashFunc msgHash (modBits) salt with
  | some em =>
    let m := os2ip em
    let s := rsaep n d m
    let k := (modBits + 7) / 8
    pure (some (i2osp s k))
  | none => pure none

/-- EMSA-PSS-VERIFY (RFC 8017 §9.1.2)
    Verifies the PSS encoding of a message hash against the encoded message EM. -/
def emsa_pss_verify (hashFunc : ByteArray -> ByteArray) (mHash : ByteArray) (em : ByteArray) (emBits : Nat) (sLen : Nat) : Bool :=
  let hLen := 32  -- SHA-256 output length
  let emLen := (emBits + 7) / 8

  if mHash.size != hLen then false
  else if emLen < hLen + sLen + 2 then false
  else if em.size < emLen then false
  else if em[emLen - 1]! != 0xbc then false
  else
    -- Split EM into maskedDB || H || 0xbc
    let maskedDB := em.extract 0 (emLen - hLen - 1)
    let h := em.extract (emLen - hLen - 1) (emLen - 1)

    -- Check leftmost bits of maskedDB are zero
    let topBits := 8 * emLen - emBits
    let topMask := (0xFF <<< (8 - topBits)).toUInt8
    if topBits > 0 && (maskedDB[0]! &&& topMask) != 0 then false
    else
      -- dbMask = MGF1(H, emLen - hLen - 1)
      let dbMask := mgf1 hashFunc h (emLen - hLen - 1)
      -- DB = maskedDB XOR dbMask
      let db := xorBytes maskedDB dbMask
      -- Set leftmost bits of DB to zero
      let db := if topBits > 0 then
        let clearMask := (0xFF >>> topBits).toUInt8
        let db0 := db[0]! &&& clearMask
        db.set! 0 db0
      else db

      -- Check DB structure: (emLen - hLen - sLen - 2) zero bytes || 0x01 || salt
      let psLen := emLen - hLen - sLen - 2
      let zerosOk := (List.range psLen).all (fun i => db[i]! == 0)
      if !zerosOk then false
      else if db[psLen]! != 0x01 then false
      else
        -- Extract salt from DB
        let salt := db.extract (psLen + 1) (psLen + 1 + sLen)
        -- M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
        let mPrime := ByteArray.mk (List.replicate 8 0).toArray ++ mHash ++ salt
        let hPrime := hashFunc mPrime
        -- Compare H and H' (constant-time to prevent timing side-channel)
        constantTimeEqual h hPrime

/-- RSASSA-PSS-VERIFY (RFC 8017 §8.1.2)
    Verifies an RSA-PSS signature.
    - hashFunc: hash function (e.g., SHA-256)
    - n: RSA modulus
    - e: RSA public exponent
    - msgHash: hash of the message being verified
    - signature: the signature to verify
    Returns true if the signature is valid. -/
def rsassa_pss_verify (hashFunc : ByteArray -> ByteArray) (n e : Nat) (msgHash : ByteArray) (signature : ByteArray) : Bool :=
  let modBits := n.log2
  let k := (modBits + 7) / 8

  -- Step 1: Length checking
  if signature.size != k then false
  else
    -- Step 2: RSA verification primitive: m = s^e mod n
    let s := os2ip signature
    if s >= n then false
    else
      let m := modPow s e n

      -- Step 3: Convert integer to encoded message
      let emLen := (modBits - 1 + 7) / 8
      if m >= (1 <<< (emLen * 8)) then false
      else
        let em := i2osp m emLen

        -- Step 4: EMSA-PSS verification
        -- sLen = hLen (32 for SHA-256), standard for TLS 1.3
        emsa_pss_verify hashFunc msgHash em (modBits - 1) 32

end LeanServer.RSA
