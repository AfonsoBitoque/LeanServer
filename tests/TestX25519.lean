import LeanServer.Crypto.X25519
import LeanServer.Crypto.Crypto

open LeanServer

def main : IO Unit := do
  IO.println "🧪 Testing X25519 with RFC 7748 Vectors..."

  -- RFC 7748 Section 6.1
  let alicePriv := hexToBytes "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
  let bobPriv   := hexToBytes "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"

  -- Expected Public Keys
  let alicePubExpected := hexToBytes "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
  let bobPubExpected   := hexToBytes "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"

  let alicePub := LeanServer.X25519.scalarmult_base alicePriv
  let bobPub   := LeanServer.X25519.scalarmult_base bobPriv

  if alicePub == alicePubExpected then
    IO.println "✅ Alice Public Key derivation matches"
  else
    IO.println s!"❌ Alice Public Key Mismatch!"
    -- IO.println s!"Expected: {alicePubExpected}"
    -- IO.println s!"Got:      {alicePub}"

  if bobPub == bobPubExpected then
    IO.println "✅ Bob Public Key derivation matches"
  else
    IO.println s!"❌ Bob Public Key Mismatch!"

  -- Shared Secret
  let sharedExpected := hexToBytes "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

  let shared1 := LeanServer.X25519.scalarmult alicePriv bobPub
  let shared2 := LeanServer.X25519.scalarmult bobPriv alicePub

  if shared1 == sharedExpected then
    IO.println "✅ Shared Secret (Alice Priv * Bob Pub) matches"
  else
    IO.println "❌ Shared Secret 1 Mismatch!"

  if shared2 == sharedExpected then
     IO.println "✅ Shared Secret (Bob Priv * Alice Pub) matches"
  else
     IO.println "❌ Shared Secret 2 Mismatch!"

  if shared1 == sharedExpected && shared2 == sharedExpected && alicePub == alicePubExpected then
    IO.println "🎉 X25519 Verified Successfully!"
  else
    IO.println "⚠️ Verification Failed."
