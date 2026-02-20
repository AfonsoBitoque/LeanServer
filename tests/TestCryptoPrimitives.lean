import LeanServer.Crypto.Crypto

open LeanServer

def main : IO Unit := do
  IO.println "🧪 Testing Cryptographic Primitives..."

  -- Test Vectors from RFC 4231 (HMAC-SHA256)
  -- Case 1: Key="0b"*20, Data="Hi There"
  let key1 := ByteArray.mk (List.replicate 20 0x0b).toArray
  let msg1 := "Hi There".toUTF8
  let expected1 := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
  let hmac1 := LeanServer.hmac_sha256 key1 msg1

  if hex hmac1 == expected1 then
    IO.println "✅ HMAC-SHA256 Test Case 1 Passed"
  else
    IO.println s!"❌ HMAC-SHA256 Test Case 1 Failed: {hex hmac1} != {expected1}"

  -- Test Vectors from RFC 5869 (HKDF-SHA256)
  -- Case 1: IKM=0x0b*22, Salt=0x00*13, Info=0xf0*10, L=42
  let ikm := ByteArray.mk (List.replicate 22 0x0b).toArray
  let salt := ByteArray.mk #[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]
  let info := ByteArray.mk #[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]
  let l := 42

  let prk := LeanServer.hkdf_extract salt ikm
  let okm := LeanServer.hkdf_expand prk info l

  -- Expected OKM from RFC 5869
  let expectedOKM := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

  if hex okm == expectedOKM then
    IO.println "✅ HKDF-Expand Test Case 1 Passed"
  else
    IO.println s!"❌ HKDF-Expand Test Case 1 Failed"
    IO.println s!"   Got: {hex okm}"
    IO.println s!"   Exp: {expectedOKM}"

  if (hex hmac1 == expected1) && (hex okm == expectedOKM) then
    IO.println "🎉 All Crypto Primitives Verified!"
  else
    IO.println "⚠️ Verification Failed"
    IO.Process.exit 1
