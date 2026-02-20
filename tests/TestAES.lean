import LeanServer.Crypto.AES
import LeanServer.Crypto.Crypto
import Init.System.IO

open LeanServer

def main : IO Unit := do
  IO.println "🧪 Testing AES Implementation..."
  IO.println ""

  -- ==========================================
  -- AES-128 ECB (FIPS 197 Appendix B)
  -- ==========================================

  -- FIPS 197 Appendix B - AES-128 Encryption (ECB Mode / Single Block)
  let key := fromHex "2b7e151628aed2a6abf7158809cf4f3c"
  let plain := fromHex "3243f6a8885a308d313198a2e0370734"
  let expected := "3925841d02dc09fbdc118597196a0b32"

  let expKey := LeanServer.AES.expandKey key
  let cipher := LeanServer.AES.encryptBlock expKey plain

  if hex cipher == expected then
    IO.println "✅ AES-128 Core Verified (FIPS 197)"
  else
    IO.println s!"❌ AES-128 Core Failed\n   Got: {hex cipher}\n   Exp: {expected}"

  IO.println ""
  IO.println "── AES-128-GCM (NIST SP 800-38D / GCM Spec) ──"
  IO.println ""

  -- ==========================================
  -- NIST GCM Test Case 1: Empty plaintext, Empty AAD
  -- K  = 00000000000000000000000000000000
  -- IV = 000000000000000000000000
  -- P  = (empty)
  -- AAD= (empty)
  -- C  = (empty)
  -- T  = 58e2fccefa7e3061367f1d57a4e7455a
  -- ==========================================

  let tc1Key := fromHex "00000000000000000000000000000000"
  let tc1IV := fromHex "000000000000000000000000"
  let tc1P := ByteArray.empty
  let tc1AAD := ByteArray.empty
  let tc1ExpC := ""
  let tc1ExpT := "58e2fccefa7e3061367f1d57a4e7455a"

  let (tc1C, tc1T) := LeanServer.AES.aesGCMEncrypt tc1Key tc1IV tc1P tc1AAD

  if hex tc1C == tc1ExpC && hex tc1T == tc1ExpT then
    IO.println "✅ GCM TC1: Empty P, Empty AAD"
  else
    IO.println "❌ GCM TC1 Failed (Empty P, Empty AAD)"
    IO.println s!"   Got C: '{hex tc1C}' (len={tc1C.size})"
    IO.println s!"   Exp C: '{tc1ExpC}'"
    IO.println s!"   Got T: {hex tc1T}"
    IO.println s!"   Exp T: {tc1ExpT}"

  -- ==========================================
  -- NIST GCM Test Case 2: 16-byte plaintext, Empty AAD
  -- K  = 00000000000000000000000000000000
  -- IV = 000000000000000000000000
  -- P  = 00000000000000000000000000000000
  -- AAD= (empty)
  -- C  = 0388dace60b6a392f328c2b971b2fe78
  -- T  = ab6e47d42cec13bdf53a67b21257bddf
  -- ==========================================

  let tc2Key := fromHex "00000000000000000000000000000000"
  let tc2IV := fromHex "000000000000000000000000"
  let tc2P := fromHex "00000000000000000000000000000000"
  let tc2AAD := ByteArray.empty
  let tc2ExpC := "0388dace60b6a392f328c2b971b2fe78"
  let tc2ExpT := "ab6e47d42cec13bdf53a67b21257bddf"

  let (tc2C, tc2T) := LeanServer.AES.aesGCMEncrypt tc2Key tc2IV tc2P tc2AAD

  if hex tc2C == tc2ExpC && hex tc2T == tc2ExpT then
    IO.println "✅ GCM TC2: 16B zero P, Empty AAD"
  else
    IO.println "❌ GCM TC2 Failed (16B zero P, Empty AAD)"
    IO.println s!"   Got C: {hex tc2C}"
    IO.println s!"   Exp C: {tc2ExpC}"
    IO.println s!"   Got T: {hex tc2T}"
    IO.println s!"   Exp T: {tc2ExpT}"

  -- ==========================================
  -- NIST GCM Test Case 3: 64-byte plaintext, Empty AAD
  -- K  = feffe9928665731c6d6a8f9467308308
  -- IV = cafebabefacedbaddecaf888
  -- P  = d9313225f88406e5a55909c5aff5269a
  --      86a7a9531534f7da2e4c303d8a318a72
  --      1c3c0c95956809532fcf0e2449a6b525
  --      b16aedf5aa0de657ba637b391aafd255 (64 bytes)
  -- AAD= (empty)
  -- C  = 42831ec2217774244b7221b784d0d49c
  --      e3aa212f2c02a4e035c17e2329aca12e
  --      21d514b25466931c7d8f6a5aac84aa05
  --      1ba30b396a0aac973d58e091473f5985 (64 bytes)
  -- T  = 4d5c2af327cd64a62cf35abd2ba6fab4
  -- ==========================================

  let tc3Key := fromHex "feffe9928665731c6d6a8f9467308308"
  let tc3IV := fromHex "cafebabefacedbaddecaf888"
  let tc3P := fromHex "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
  let tc3AAD := ByteArray.empty
  let tc3ExpC := "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
  let tc3ExpT := "4d5c2af327cd64a62cf35abd2ba6fab4"

  let (tc3C, tc3T) := LeanServer.AES.aesGCMEncrypt tc3Key tc3IV tc3P tc3AAD

  if hex tc3C == tc3ExpC && hex tc3T == tc3ExpT then
    IO.println "✅ GCM TC3: 64B P, Empty AAD"
  else
    IO.println "❌ GCM TC3 Failed (64B P, Empty AAD)"
    IO.println s!"   Got C: {hex tc3C}"
    IO.println s!"   Exp C: {tc3ExpC}"
    IO.println s!"   Got T: {hex tc3T}"
    IO.println s!"   Exp T: {tc3ExpT}"

  -- ==========================================
  -- NIST GCM Test Case 4: 60-byte plaintext, 20-byte AAD
  -- K  = feffe9928665731c6d6a8f9467308308
  -- IV = cafebabefacedbaddecaf888
  -- P  = d9313225f88406e5a55909c5aff5269a
  --      86a7a9531534f7da2e4c303d8a318a72
  --      1c3c0c95956809532fcf0e2449a6b525
  --      b16aedf5aa0de657ba637b39 (60 bytes)
  -- AAD= feedfacedeadbeeffeedfacedeadbeef
  --      abaddad2 (20 bytes)
  -- C  = 42831ec2217774244b7221b784d0d49c
  --      e3aa212f2c02a4e035c17e2329aca12e
  --      21d514b25466931c7d8f6a5aac84aa05
  --      1ba30b396a0aac973d58e091 (60 bytes)
  -- T  = 5bc94fbc3221a5db94fae95ae7121a47
  -- ==========================================

  let tc4Key := fromHex "feffe9928665731c6d6a8f9467308308"
  let tc4IV := fromHex "cafebabefacedbaddecaf888"
  let tc4P := fromHex "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
  let tc4AAD := fromHex "feedfacedeadbeeffeedfacedeadbeefabaddad2"
  let tc4ExpC := "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
  let tc4ExpT := "5bc94fbc3221a5db94fae95ae7121a47"

  let (tc4C, tc4T) := LeanServer.AES.aesGCMEncrypt tc4Key tc4IV tc4P tc4AAD

  if hex tc4C == tc4ExpC && hex tc4T == tc4ExpT then
    IO.println "✅ GCM TC4: 60B P, 20B AAD"
  else
    IO.println "❌ GCM TC4 Failed (60B P, 20B AAD)"
    IO.println s!"   Got C: {hex tc4C}"
    IO.println s!"   Exp C: {tc4ExpC}"
    IO.println s!"   Got T: {hex tc4T}"
    IO.println s!"   Exp T: {tc4ExpT}"

  -- ==========================================
  -- GCM Decrypt Test (roundtrip TC2)
  -- Encrypt then decrypt and verify plaintext recovered
  -- ==========================================

  let rt2CT := tc2C ++ tc2T  -- ciphertext ++ tag
  match LeanServer.AES.aesGCMDecrypt tc2Key tc2IV rt2CT tc2AAD with
  | some recovered =>
    if hex recovered == hex tc2P then
      IO.println "✅ GCM Decrypt Roundtrip TC2"
    else
      IO.println s!"❌ GCM Decrypt Roundtrip TC2 — wrong plaintext: {hex recovered}"
  | none =>
    IO.println "❌ GCM Decrypt Roundtrip TC2 — tag verification failed"

  -- ==========================================
  -- GCM Decrypt Test (roundtrip TC4 with AAD)
  -- ==========================================

  let rt4CT := tc4C ++ tc4T
  match LeanServer.AES.aesGCMDecrypt tc4Key tc4IV rt4CT tc4AAD with
  | some recovered =>
    if hex recovered == hex tc4P then
      IO.println "✅ GCM Decrypt Roundtrip TC4 (with AAD)"
    else
      IO.println s!"❌ GCM Decrypt Roundtrip TC4 — wrong plaintext: {hex recovered}"
  | none =>
    IO.println "❌ GCM Decrypt Roundtrip TC4 — tag verification failed"

  IO.println ""
  IO.println "🏁 AES test suite complete."
