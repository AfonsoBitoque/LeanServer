import LeanServer.Core.Basic

namespace LeanServer.Base64

def b64Index (c : Char) : Option UInt8 :=
  if c >= 'A' && c <= 'Z' then some (c.toNat - 'A'.toNat).toUInt8
  else if c >= 'a' && c <= 'z' then some (c.toNat - 'a'.toNat + 26).toUInt8
  else if c >= '0' && c <= '9' then some (c.toNat - '0'.toNat + 52).toUInt8
  else if c == '+' then some 62
  else if c == '/' then some 63
  else none

/-- Decode Base64 string to ByteArray. Ignores usage of padding '=' for length calc, just stops. -/
def decode (s : String) : Option ByteArray := do
  let chars := s.toList.filter (fun c => c != '=' && c != '\n' && c != '\r' && c != ' ')
  let mut res := ByteArray.mk (Array.mkEmpty (chars.length * 3 / 4))
  let mut buffer : Nat := 0
  let mut bits : Nat := 0
  
  for c in chars do
    let v ← b64Index c
    buffer := (buffer <<< 6) ||| v.toNat
    bits := bits + 6
    if bits >= 8 then
      bits := bits - 8
      let byte := (buffer >>> bits).toUInt8
      res := res.push byte
    
  some res

end LeanServer.Base64
