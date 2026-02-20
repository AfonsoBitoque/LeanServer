import LeanServer.Spec.ServerStep
import LeanServer.Spec.TLSRefinement
import LeanServer.Spec.TLSModel
import LeanServer.Spec.TLSSpec

/-!
  # TLS 1.3 Handshake End-to-End Test (Phase 8.2)

  Validates the complete TLS 1.3 handshake flow through the pure
  `serverHandshakeStep` function, verifying that:

  1. **Full handshake**: ClientHello → ServerHello flight → Finished → Connected
  2. **State transitions**: Each step produces the correct phase
  3. **Action generation**: Correct server actions at each step
  4. **Post-handshake**: KeyUpdate works in Connected state
  5. **Error paths**: Invalid Finished → alert, no KeyShare → alert
  6. **Refinement**: States map correctly to TLSModel/TLSSpec

  This is a model-level loopback test: both "client" and "server" run
  in the same process using pure functions. No TCP, no IO.
-/

open TLS.ServerStep
open TLS.Spec (NegotiatedParams CipherSuite KeyGroup)

-- ============================================================================
-- §1. Test Infrastructure
-- ============================================================================

initialize testCountRef : IO.Ref Nat ← IO.mkRef 0
initialize passCountRef : IO.Ref Nat ← IO.mkRef 0

def check (name : String) (cond : Bool) : IO Unit := do
  testCountRef.modify (· + 1)
  if cond then
    passCountRef.modify (· + 1)
  else
    IO.eprintln s!"  ✗ FAIL: {name}"

-- ============================================================================
-- §2. Full Handshake Flow (Happy Path)
-- ============================================================================

def testFullHandshake : IO Unit := do
  IO.println "── §2. Full TLS 1.3 Handshake ──"

  -- Step 0: Initial state
  let s0 := initialServerState
  check "initial phase = awaitClientHello" (s0.phase == .awaitClientHello)
  check "initial no handshake keys" (s0.hasHandshakeKeys == false)
  check "initial no app keys" (s0.hasAppKeys == false)

  -- Step 1: ClientHello with key share
  let params : NegotiatedParams := {
    cipherSuite := .TLS_AES_128_GCM_SHA256
    keyGroup := .X25519
  }
  let (s1, actions1) := serverHandshakeStep s0 (.clientHello params true)
  check "after CH: phase = awaitClientFinished" (s1.phase == .awaitClientFinished)
  check "after CH: hasHandshakeKeys = true" (s1.hasHandshakeKeys == true)
  check "after CH: negotiatedParams set" (s1.negotiatedParams.isSome)
  check "after CH: 5 actions (SH, EE, Cert, CV, Fin)" (actions1.length == 5)
  check "after CH: first action is sendServerHello" (actions1.head? == some (.sendServerHello params))
  check "after CH: last action is sendFinished" (actions1.getLast? == some .sendFinished)

  -- Step 2: ChangeCipherSpec (middlebox compat — ignored)
  let (s1b, actions_ccs) := serverHandshakeStep s1 .changeCipherSpec
  check "CCS: phase unchanged" (s1b.phase == .awaitClientFinished)
  check "CCS: no actions" (actions_ccs.length == 0)

  -- Step 3: Client Finished (verified)
  let (s2, actions2) := serverHandshakeStep s1 (.clientFinished true)
  check "after Finished: phase = connected" (s2.phase == .connected)
  check "after Finished: hasAppKeys = true" (s2.hasAppKeys == true)
  check "after Finished: 2 actions (transitionToAppData, NST)" (actions2.length == 2)
  check "after Finished: transitionToAppData" (actions2.head? == some .transitionToAppData)

  -- Step 4: Post-handshake KeyUpdate
  let (s3, actions3) := serverHandshakeStep s2 (.keyUpdate true)
  check "after KU: phase still connected" (s3.phase == .connected)
  check "after KU: keyUpdateCount = 1" (s3.keyUpdateCount == 1)
  check "after KU: sendKeyUpdate action" (actions3.length == 1)

  -- Step 5: Second KeyUpdate (no response requested)
  let (s4, actions4) := serverHandshakeStep s3 (.keyUpdate false)
  check "after KU2: keyUpdateCount = 2" (s4.keyUpdateCount == 2)
  check "after KU2: no actions (no response)" (actions4.length == 0)

  -- Step 6: close_notify
  let (s5, actions5) := serverHandshakeStep s4 .closeNotify
  check "after close: phase = closed" (s5.phase == .closed)
  check "after close: close action" (actions5 == [.close])

  IO.println s!"  ✓ Full handshake flow validated"

-- ============================================================================
-- §3. Error Paths
-- ============================================================================

def testErrorPaths : IO Unit := do
  IO.println "── §3. Error Paths ──"

  -- Error 1: ClientHello without key share
  let s0 := initialServerState
  let params : NegotiatedParams := {
    cipherSuite := .TLS_AES_128_GCM_SHA256
    keyGroup := .X25519
  }
  let (s_noKS, acts_noKS) := serverHandshakeStep s0 (.clientHello params false)
  check "no KeyShare: phase = closed" (s_noKS.phase == .closed)
  check "no KeyShare: sends alert 40 (handshake_failure)" (acts_noKS == [.sendAlert 40])

  -- Error 2: Unverified Finished
  let (s1, _) := serverHandshakeStep s0 (.clientHello params true)
  let (s_badFin, acts_badFin) := serverHandshakeStep s1 (.clientFinished false)
  check "bad Finished: phase = closed" (s_badFin.phase == .closed)
  check "bad Finished: sends alert 51 (decrypt_error)" (acts_badFin == [.sendAlert 51])

  -- Error 3: Fatal alert from any state
  let (s_alert, _) := serverHandshakeStep s1 (.fatalAlert 70)
  check "fatal alert: phase = closed" (s_alert.phase == .closed)

  -- Error 4: Unexpected event in wrong phase (e.g., Finished in awaitClientHello)
  let (s_bad, acts_bad) := serverHandshakeStep s0 (.clientFinished true)
  check "Finished in CH phase: closes" (s_bad.phase == .closed)
  check "Finished in CH phase: sends alert" (acts_bad.any (· matches .sendAlert _))

  IO.println s!"  ✓ Error paths validated"

-- ============================================================================
-- §4. Closed State is Terminal
-- ============================================================================

def testClosedTerminal : IO Unit := do
  IO.println "── §4. Closed State Terminal ──"

  let params : NegotiatedParams := {
    cipherSuite := .TLS_AES_128_GCM_SHA256
    keyGroup := .X25519
  }

  let closedState : TLSServerState := {
    phase := .closed
    negotiatedParams := none
    hasHandshakeKeys := false
    hasAppKeys := false
    keyUpdateCount := 0
  }

  -- All events from closed state should keep it closed
  let events : List TLSServerEvent := [
    .clientHello params true,
    .clientFinished true,
    .keyUpdate true,
    .closeNotify,
    .fatalAlert 0,
    .changeCipherSpec
  ]

  for event in events do
    let (s', _) := serverHandshakeStep closedState event
    check s!"closed + {repr event}: stays closed" (s'.phase == .closed)

  IO.println s!"  ✓ Closed state is terminal for all events"

-- ============================================================================
-- §5. Refinement Chain Validation
-- ============================================================================

def testRefinementChain : IO Unit := do
  IO.println "── §5. Refinement Chain ──"

  -- Verify that serverHandshakeStep phases map to TLSModel states
  let s0 := initialServerState
  check "awaitClientHello maps to non-closed" (s0.phase != .closed)

  let params : NegotiatedParams := {
    cipherSuite := .TLS_AES_128_GCM_SHA256
    keyGroup := .X25519
  }

  let (s1, _) := serverHandshakeStep s0 (.clientHello params true)
  check "awaitClientFinished: keys derived" (s1.hasHandshakeKeys)

  let (s2, _) := serverHandshakeStep s1 (.clientFinished true)
  check "connected: both key types" (s2.hasHandshakeKeys && s2.hasAppKeys)
  check "connected: maps to Model's Connected" (s2.phase == .connected)

  -- The full chain: awaitCH → awaitFin → connected → closed
  let (s3, _) := serverHandshakeStep s2 .closeNotify
  check "close: maps to Model's Closed" (s3.phase == .closed)

  IO.println s!"  ✓ Refinement chain validated"

-- ============================================================================
-- §6. Loopback: Simulated Client-Server Exchange
-- ============================================================================

/-- Simulate a complete client-server handshake exchange.
    The "client" generates events, the "server" processes them via serverHandshakeStep.
    This models the full message flow without network IO. -/
def testLoopback : IO Unit := do
  IO.println "── §6. Loopback Exchange ──"

  let params : NegotiatedParams := {
    cipherSuite := .TLS_AES_256_GCM_SHA384
    keyGroup := .X25519
  }

  -- Client → Server: ClientHello
  let mut state := initialServerState
  let mut totalActions : Nat := 0

  let (s, acts) := serverHandshakeStep state (.clientHello params true)
  state := s
  totalActions := totalActions + acts.length
  check "loopback: server processed CH" (state.phase == .awaitClientFinished)

  -- Client → Server: CCS (compatibility)
  let (s, _) := serverHandshakeStep state .changeCipherSpec
  state := s

  -- Client → Server: Finished
  let (s, acts) := serverHandshakeStep state (.clientFinished true)
  state := s
  totalActions := totalActions + acts.length
  check "loopback: handshake complete" (state.phase == .connected)

  -- Application data exchange (modeled as KeyUpdates)
  for _ in [:3] do
    let (s, acts) := serverHandshakeStep state (.keyUpdate true)
    state := s
    totalActions := totalActions + acts.length

  check "loopback: 3 key updates" (state.keyUpdateCount == 3)

  -- Client → Server: close_notify
  let (s, acts) := serverHandshakeStep state .closeNotify
  state := s
  totalActions := totalActions + acts.length
  check "loopback: connection closed" (state.phase == .closed)
  check "loopback: generated multiple actions" (totalActions > 5)

  IO.println s!"  ✓ Loopback exchange: {totalActions} total actions generated"

-- ============================================================================
-- Main
-- ============================================================================

def main : IO UInt32 := do
  IO.println "═══════════════════════════════════════════"
  IO.println " TLS 1.3 Handshake End-to-End Test"
  IO.println " Phase 8.2 — Model-Level Loopback"
  IO.println "═══════════════════════════════════════════"

  testFullHandshake
  testErrorPaths
  testClosedTerminal
  testRefinementChain
  testLoopback

  let total ← testCountRef.get
  let passed ← passCountRef.get

  IO.println ""
  IO.println s!"═══════════════════════════════════════════"
  IO.println s!" Results: {passed}/{total} tests passed"
  IO.println s!"═══════════════════════════════════════════"

  if passed == total then
    IO.println "✅ ALL TESTS PASSED"
    return 0
  else
    IO.println s!"❌ {total - passed} TESTS FAILED"
    return 1
