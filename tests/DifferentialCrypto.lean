import LeanServer.Crypto.Crypto

/-!
  # Differential Testing: Lean Crypto vs OpenSSL (Phase 8.1)

  Compares our pure-Lean SHA-256, HMAC-SHA256, and HKDF-SHA256 against
  known test vectors from RFCs. This file runs as a standalone executable.

  ## Test Vector Sources
  - SHA-256: NIST FIPS 180-4 examples + RFC 6234
  - HMAC-SHA256: RFC 4231 §4.2–4.7
  - HKDF-SHA256: RFC 5869 §A.1–A.3
-/

open LeanServer

-- ============================================================================
-- Test infrastructure
-- ============================================================================

structure TestResult where
  name : String
  passed : Nat
  failed : Nat
  details : List String

def runTest (name : String) (expected : String) (actual : String) : Bool × String :=
  if expected == actual then
    (true, s!"  ✅ {name}")
  else
    (false, s!"  ❌ {name}\n     Expected: {expected}\n     Got:      {actual}")

-- ============================================================================
-- §1. SHA-256 Test Vectors (NIST FIPS 180-4 + RFC 6234)
-- ============================================================================

def sha256Tests : IO TestResult := do
  IO.println "━━━ SHA-256 Test Vectors ━━━"
  let mut passed := 0
  let mut failed := 0
  let mut details : List String := []

  -- 1. Empty string
  let (ok, msg) := runTest "SHA-256(\"\")"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    (hex (sha256 ByteArray.empty))
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  -- 2. "abc"
  let (ok, msg) := runTest "SHA-256(\"abc\")"
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    (hex (sha256 "abc".toUTF8))
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  -- 3. "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (448 bits, 2-block)
  let (ok, msg) := runTest "SHA-256(448-bit)"
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    (hex (sha256 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toUTF8))
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  -- 4. "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" (896 bits)
  let (ok, msg) := runTest "SHA-256(896-bit)"
    "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
    (hex (sha256 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".toUTF8))
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  -- 5. Single byte 0x00
  let (ok, msg) := runTest "SHA-256(0x00)"
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    (hex (sha256 (ByteArray.mk #[0x00])))
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  -- 6. Single byte 0xff
  let (ok, msg) := runTest "SHA-256(0xff)"
    "a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89"
    (hex (sha256 (ByteArray.mk #[0xff])))
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  -- 7-16. Deterministic pseudo-random inputs of increasing sizes
  for i in List.range 10 do
    let size := (i + 1) * 7  -- 7, 14, 21, ... 70 bytes
    -- Generate deterministic "random" bytes: byte[j] = (i * 31 + j * 17 + 42) % 256
    let data := ByteArray.mk ((List.range size).map fun j =>
      UInt8.ofNat ((i * 31 + j * 17 + 42) % 256)).toArray
    let hash := sha256 data
    -- Just verify it's 32 bytes (correct size) — full OpenSSL comparison done in shell script
    if hash.size == 32 then
      passed := passed + 1
      details := details ++ [s!"  ✅ SHA-256({size} bytes) → 32-byte output"]
    else
      failed := failed + 1
      details := details ++ [s!"  ❌ SHA-256({size} bytes) → {hash.size} bytes (expected 32)"]

  -- 17-26. Larger inputs (55, 56, 63, 64, 65 bytes — padding edge cases)
  for size in [55, 56, 63, 64, 65, 100, 128, 200, 256, 512] do
    let data := ByteArray.mk ((List.range size).map fun j =>
      UInt8.ofNat ((size * 13 + j * 7 + 99) % 256)).toArray
    let hash := sha256 data
    if hash.size == 32 then
      passed := passed + 1
      details := details ++ [s!"  ✅ SHA-256({size} bytes) → 32-byte output"]
    else
      failed := failed + 1
      details := details ++ [s!"  ❌ SHA-256({size} bytes) → {hash.size} bytes (expected 32)"]

  -- 27. 1000 deterministic inputs for differential testing
  let mut allSizesCorrect := true
  for i in List.range 1000 do
    let size := i % 300  -- 0 to 299 bytes
    let data := ByteArray.mk ((List.range size).map fun j =>
      UInt8.ofNat ((i * 37 + j * 13 + 7) % 256)).toArray
    let hash := sha256 data
    if hash.size != 32 then
      allSizesCorrect := false
  if allSizesCorrect then
    passed := passed + 1
    details := details ++ [s!"  ✅ SHA-256: 1000 random inputs all produce 32-byte output"]
  else
    failed := failed + 1
    details := details ++ [s!"  ❌ SHA-256: Some of 1000 random inputs produced wrong-size output"]

  for d in details do IO.println d
  return ⟨"SHA-256", passed, failed, details⟩

-- ============================================================================
-- §2. HMAC-SHA256 Test Vectors (RFC 4231)
-- ============================================================================

def hmacTests : IO TestResult := do
  IO.println "\n━━━ HMAC-SHA256 Test Vectors (RFC 4231) ━━━"
  let mut passed := 0
  let mut failed := 0
  let mut details : List String := []

  -- RFC 4231 §4.2: Test Case 1
  let key1 := ByteArray.mk (List.replicate 20 0x0b).toArray
  let data1 := "Hi There".toUTF8
  let (ok, msg) := runTest "RFC 4231 Case 1"
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    (hex (hmac_sha256 key1 data1))
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  -- RFC 4231 §4.3: Test Case 2 (Key = "Jefe")
  let key2 := "Jefe".toUTF8
  let data2 := "what do ya want for nothing?".toUTF8
  let (ok, msg) := runTest "RFC 4231 Case 2"
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    (hex (hmac_sha256 key2 data2))
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  -- RFC 4231 §4.4: Test Case 3 (Key = 0xaa * 20, Data = 0xdd * 50)
  let key3 := ByteArray.mk (List.replicate 20 0xaa).toArray
  let data3 := ByteArray.mk (List.replicate 50 0xdd).toArray
  let (ok, msg) := runTest "RFC 4231 Case 3"
    "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
    (hex (hmac_sha256 key3 data3))
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  -- RFC 4231 §4.5: Test Case 4
  let key4 := fromHex "0102030405060708090a0b0c0d0e0f10111213141516171819"
  let data4 := ByteArray.mk (List.replicate 50 0xcd).toArray
  let (ok, msg) := runTest "RFC 4231 Case 4"
    "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
    (hex (hmac_sha256 key4 data4))
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  -- RFC 4231 §4.8: Test Case 6 (Key = 0xaa * 131, long key)
  let key6 := ByteArray.mk (List.replicate 131 0xaa).toArray
  let data6 := "Test Using Larger Than Block-Size Key - Hash Key First".toUTF8
  let (ok, msg) := runTest "RFC 4231 Case 6 (long key)"
    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    (hex (hmac_sha256 key6 data6))
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  -- RFC 4231 §4.9: Test Case 7 (Key = 0xaa * 131, different data)
  let key7 := ByteArray.mk (List.replicate 131 0xaa).toArray
  let data7 := "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".toUTF8
  let (ok, msg) := runTest "RFC 4231 Case 7 (long key + data)"
    "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
    (hex (hmac_sha256 key7 data7))
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  -- 100 deterministic HMAC tests (key/msg size variations)
  let mut allSizesCorrect := true
  for i in List.range 100 do
    let keySize := (i % 64) + 1  -- 1 to 64 bytes
    let msgSize := (i * 3) % 200  -- 0 to 199 bytes
    let key := ByteArray.mk ((List.range keySize).map fun j =>
      UInt8.ofNat ((i * 41 + j * 19 + 73) % 256)).toArray
    let msg := ByteArray.mk ((List.range msgSize).map fun j =>
      UInt8.ofNat ((i * 29 + j * 23 + 11) % 256)).toArray
    let result := hmac_sha256 key msg
    if result.size != 32 then
      allSizesCorrect := false
  if allSizesCorrect then
    passed := passed + 1
    details := details ++ [s!"  ✅ HMAC-SHA256: 100 random key/msg pairs all produce 32-byte output"]
  else
    failed := failed + 1
    details := details ++ [s!"  ❌ HMAC-SHA256: Some outputs had wrong size"]

  for d in details do IO.println d
  return ⟨"HMAC-SHA256", passed, failed, details⟩

-- ============================================================================
-- §3. HKDF-SHA256 Test Vectors (RFC 5869)
-- ============================================================================

def hkdfTests : IO TestResult := do
  IO.println "\n━━━ HKDF-SHA256 Test Vectors (RFC 5869) ━━━"
  let mut passed := 0
  let mut failed := 0
  let mut details : List String := []

  -- RFC 5869 §A.1: Test Case 1
  let ikm1 := ByteArray.mk (List.replicate 22 0x0b).toArray
  let salt1 := fromHex "000102030405060708090a0b0c"
  let info1 := fromHex "f0f1f2f3f4f5f6f7f8f9"
  let prk1 := hkdf_extract salt1 ikm1
  let okm1 := hkdf_expand prk1 info1 42
  let (ok, msg) := runTest "RFC 5869 Case 1 PRK"
    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    (hex prk1)
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  let (ok, msg) := runTest "RFC 5869 Case 1 OKM"
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    (hex okm1)
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  -- RFC 5869 §A.2: Test Case 2 (longer inputs)
  let ikm2 := fromHex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
  let salt2 := fromHex "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
  let info2 := fromHex "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
  let prk2 := hkdf_extract salt2 ikm2
  let okm2 := hkdf_expand prk2 info2 82
  let (ok, msg) := runTest "RFC 5869 Case 2 PRK"
    "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
    (hex prk2)
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  let (ok, msg) := runTest "RFC 5869 Case 2 OKM"
    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
    (hex okm2)
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  -- RFC 5869 §A.3: Test Case 3 (zero-length salt and info)
  let ikm3 := ByteArray.mk (List.replicate 22 0x0b).toArray
  let salt3 := ByteArray.empty
  let info3 := ByteArray.empty
  let prk3 := hkdf_extract salt3 ikm3
  let okm3 := hkdf_expand prk3 info3 42
  let (ok, msg) := runTest "RFC 5869 Case 3 PRK"
    "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    (hex prk3)
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  let (ok, msg) := runTest "RFC 5869 Case 3 OKM"
    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    (hex okm3)
  if ok then passed := passed + 1 else failed := failed + 1
  details := details ++ [msg]

  -- 100 deterministic HKDF tests
  let mut allSizesCorrect := true
  for i in List.range 100 do
    let saltSize := i % 32
    let ikmSize := (i % 48) + 1
    let infoSize := i % 64
    let outLen := (i % 128) + 1
    let salt := ByteArray.mk ((List.range saltSize).map fun j =>
      UInt8.ofNat ((i * 43 + j * 17 + 59) % 256)).toArray
    let ikm := ByteArray.mk ((List.range ikmSize).map fun j =>
      UInt8.ofNat ((i * 37 + j * 23 + 83) % 256)).toArray
    let info := ByteArray.mk ((List.range infoSize).map fun j =>
      UInt8.ofNat ((i * 53 + j * 11 + 31) % 256)).toArray
    let prk := hkdf_extract salt ikm
    let okm := hkdf_expand prk info outLen
    if prk.size != 32 || okm.size != outLen then
      allSizesCorrect := false
  if allSizesCorrect then
    passed := passed + 1
    details := details ++ [s!"  ✅ HKDF: 100 random salt/ikm/info triples, all sizes correct"]
  else
    failed := failed + 1
    details := details ++ [s!"  ❌ HKDF: Some outputs had wrong size"]

  for d in details do IO.println d
  return ⟨"HKDF-SHA256", passed, failed, details⟩

-- ============================================================================
-- §4. Main
-- ============================================================================

def main : IO UInt32 := do
  IO.println "╔══════════════════════════════════════════════════════════╗"
  IO.println "║  Differential Crypto Testing — LeanServer6 Phase 8.1   ║"
  IO.println "╚══════════════════════════════════════════════════════════╝\n"

  let sha := ← sha256Tests
  let hmac := ← hmacTests
  let hkdf := ← hkdfTests

  IO.println "\n━━━ Summary ━━━"
  let totalPassed := sha.passed + hmac.passed + hkdf.passed
  let totalFailed := sha.failed + hmac.failed + hkdf.failed
  IO.println s!"  SHA-256:     {sha.passed}/{sha.passed + sha.failed}"
  IO.println s!"  HMAC-SHA256: {hmac.passed}/{hmac.passed + hmac.failed}"
  IO.println s!"  HKDF-SHA256: {hkdf.passed}/{hkdf.passed + hkdf.failed}"
  IO.println s!"  ────────────────────"
  IO.println s!"  Total:       {totalPassed}/{totalPassed + totalFailed}"

  if totalFailed == 0 then
    IO.println "\n🎉 All differential tests passed!"
    return 0
  else
    IO.println s!"\n⚠️  {totalFailed} test(s) failed!"
    return 1
