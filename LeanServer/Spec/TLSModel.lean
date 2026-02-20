import LeanServer.Spec.TLSSpec

/-!
  # TLS 1.3 Executable Model (Layer 2 — Model)

  ## Refinement Architecture (F2.0)
  This module provides a **deterministic executable model** of TLS 1.3.
  Unlike the abstract Spec (Layer 1, which uses inductive propositions),
  this layer uses computable functions: `step`, `canTransition`, etc.

  ### Key Guarantee:
  **Every step in the Model corresponds to a valid transition in the Spec.**
  This is proved by `model_refines_spec` — the central refinement theorem.

  ### Architecture:
  ```
  Spec (propositions)  ←——refines——  Model (functions)  ←——refines——  Impl (IO code)
       TLSSpec.lean                   TLSModel.lean                   Crypto.lean
  ```

  ### What This Module Provides:
  1. `step` — deterministic state transition function
  2. `canTransition` — decidable transition check
  3. `model_refines_spec` — proof that Model ⊆ Spec
  4. Key derivation model (abstract, without crypto primitives)
  5. Transcript ordering invariants
-/

namespace TLS.Model

open TLS.Spec

-- ============================================================================
-- Model State (richer than Spec, but still abstract)
-- ============================================================================

/-- Model-level connection state, enriched with transcript and keys. -/
structure ModelState where
  handshakeState : HandshakeState
  /-- Ordered list of messages exchanged (append-only transcript) -/
  transcript : List (HandshakeMsg × Direction)
  /-- Whether handshake keys have been derived (after ServerHello) -/
  hasHandshakeKeys : Bool
  /-- Whether application keys have been derived (after Finished) -/
  hasAppKeys : Bool
  /-- Number of key updates performed -/
  keyUpdateCount : Nat
  deriving Repr, DecidableEq

instance : Inhabited ModelState where
  default := {
    handshakeState := .Start
    transcript := []
    hasHandshakeKeys := false
    hasAppKeys := false
    keyUpdateCount := 0
  }

/-- Initial model state — no messages, no keys, Start state. -/
def initialState : ModelState := default

-- ============================================================================
-- Transition Function (Deterministic)
-- ============================================================================

/-- Check if a transition is valid for the current state.
    Returns the next state if valid, none otherwise. -/
def tryTransition (s : HandshakeState) (msg : HandshakeMsg) (dir : Direction)
    : Option HandshakeState :=
  match s, msg, dir with
  -- Normal handshake flow
  | .Start, .ClientHello, .ClientToServer => some .WaitServerHello
  | .WaitServerHello, .ServerHello, .ServerToClient => some .WaitEncExtensions
  | .WaitEncExtensions, .EncryptedExtensions, .ServerToClient => some .WaitCertReq
  | .WaitCertReq, .CertificateRequest, .ServerToClient => some .WaitCert
  | .WaitCertReq, .Certificate, .ServerToClient => some .WaitCertVerify
  | .WaitCert, .Certificate, .ServerToClient => some .WaitCertVerify
  | .WaitCertVerify, .CertificateVerify, .ServerToClient => some .WaitFinished
  | .WaitFinished, .Finished, .ServerToClient => some .Connected
  -- Post-handshake messages
  | .Connected, .NewSessionTicket, .ServerToClient => some .Connected
  | .Connected, .KeyUpdate, .ClientToServer => some .Connected
  | .Connected, .KeyUpdate, .ServerToClient => some .Connected
  -- Alert → Closed from any non-Closed state
  | .Start, .Alert, .ClientToServer => some .Closed
  | .WaitServerHello, .Alert, .ServerToClient => some .Closed
  | .WaitEncExtensions, .Alert, .ServerToClient => some .Closed
  | .WaitCertReq, .Alert, .ServerToClient => some .Closed
  | .WaitCert, .Alert, .ServerToClient => some .Closed
  | .WaitCertVerify, .Alert, .ServerToClient => some .Closed
  | .WaitFinished, .Alert, .ServerToClient => some .Closed
  | .Connected, .Alert, .ClientToServer => some .Closed
  | .Connected, .Alert, .ServerToClient => some .Closed
  | _, _, _ => none

/-- Step the model forward: process a message, update state + transcript.
    Returns the new ModelState if the transition is valid, none otherwise. -/
def step (state : ModelState) (msg : HandshakeMsg) (dir : Direction)
    : Option ModelState :=
  match tryTransition state.handshakeState msg dir with
  | none => none
  | some nextHS =>
    let newState := { state with
      handshakeState := nextHS
      transcript := state.transcript ++ [(msg, dir)]
      -- Derive handshake keys after ServerHello
      hasHandshakeKeys := state.hasHandshakeKeys ||
        (msg == .ServerHello && dir == .ServerToClient)
      -- Derive app keys after Finished
      hasAppKeys := state.hasAppKeys ||
        (msg == .Finished && dir == .ServerToClient)
      -- Count key updates
      keyUpdateCount := if msg == .KeyUpdate then state.keyUpdateCount + 1
                        else state.keyUpdateCount
    }
    some newState

-- ============================================================================
-- Decidable Transition Check
-- ============================================================================

/-- Check if a transition is possible from the current state. -/
def canTransition (state : ModelState) (msg : HandshakeMsg) (dir : Direction) : Bool :=
  (tryTransition state.handshakeState msg dir).isSome

-- ============================================================================
-- CENTRAL THEOREM: Model Refines Spec
-- ============================================================================

/-- Every valid tryTransition corresponds to a Spec.Transition.
    This is the core refinement theorem — it proves that the executable
    model is a faithful implementation of the abstract specification. -/
theorem model_refines_spec :
    ∀ s msg dir s',
    tryTransition s msg dir = some s' →
    Transition s msg dir s' := by
  intro s msg dir s' h
  -- Case-split on all finite enums; valid cases construct the proof,
  -- invalid cases lead to `none = some _` contradiction
  cases s <;> cases msg <;> cases dir <;> simp [tryTransition] at h <;>
    (first | (rw [← h]; constructor) | exact absurd h (by simp))

/-- Completeness: every Spec.Transition is also captured by tryTransition. -/
theorem spec_implies_model :
    ∀ s msg dir s',
    Transition s msg dir s' →
    tryTransition s msg dir = some s' := by
  intro s msg dir s' h
  cases h <;> simp [tryTransition]

-- ============================================================================
-- Multi-Step Execution
-- ============================================================================

/-- Execute a sequence of messages against the model. Returns final state or none. -/
def runTrace (messages : List (HandshakeMsg × Direction)) : Option ModelState :=
  messages.foldlM (fun state (msg, dir) => step state msg dir) initialState

-- ============================================================================
-- Model Invariants
-- ============================================================================

/-- After a complete handshake sequence, the state is Connected. -/
theorem complete_handshake_reaches_connected :
    (runTrace [
      (.ClientHello, .ClientToServer),
      (.ServerHello, .ServerToClient),
      (.EncryptedExtensions, .ServerToClient),
      (.Certificate, .ServerToClient),
      (.CertificateVerify, .ServerToClient),
      (.Finished, .ServerToClient)
    ]).bind (fun s => some s.handshakeState) = some .Connected := by
  native_decide

/-- After a complete handshake sequence, hasAppKeys is true. -/
theorem complete_handshake_has_app_keys :
    (runTrace [
      (.ClientHello, .ClientToServer),
      (.ServerHello, .ServerToClient),
      (.EncryptedExtensions, .ServerToClient),
      (.Certificate, .ServerToClient),
      (.CertificateVerify, .ServerToClient),
      (.Finished, .ServerToClient)
    ]).bind (fun s => some s.hasAppKeys) = some true := by
  native_decide

/-- After ServerHello, hasHandshakeKeys is true. -/
theorem after_server_hello_has_hs_keys :
    (runTrace [
      (.ClientHello, .ClientToServer),
      (.ServerHello, .ServerToClient)
    ]).bind (fun s => some s.hasHandshakeKeys) = some true := by
  native_decide

/-- The transcript is append-only — each step adds exactly one message. -/
theorem step_extends_transcript (state : ModelState) (msg : HandshakeMsg) (dir : Direction) :
    ∀ state', step state msg dir = some state' →
    state'.transcript = state.transcript ++ [(msg, dir)] := by
  intro state' h
  simp [step] at h
  match ht : tryTransition state.handshakeState msg dir with
  | none => simp [ht] at h
  | some s' =>
    simp [ht] at h
    rw [← h]

/-- Invalid transitions are rejected — step returns none. -/
theorem invalid_from_closed :
    ∀ state msg dir, state.handshakeState = .Closed →
    step state msg dir = none := by
  intro state msg dir hclosed
  simp [step]
  rw [show tryTransition state.handshakeState msg dir =
       tryTransition .Closed msg dir from by rw [hclosed]]
  cases msg <;> cases dir <;> simp [tryTransition]

/-- The standard TLS 1.3 full handshake trace succeeds. -/
theorem full_handshake_trace_succeeds :
    (runTrace [
      (.ClientHello, .ClientToServer),
      (.ServerHello, .ServerToClient),
      (.EncryptedExtensions, .ServerToClient),
      (.Certificate, .ServerToClient),
      (.CertificateVerify, .ServerToClient),
      (.Finished, .ServerToClient)
    ]).isSome = true := by
  native_decide

/-- A handshake with CertificateRequest also succeeds. -/
theorem full_handshake_with_cert_req_trace_succeeds :
    (runTrace [
      (.ClientHello, .ClientToServer),
      (.ServerHello, .ServerToClient),
      (.EncryptedExtensions, .ServerToClient),
      (.CertificateRequest, .ServerToClient),
      (.Certificate, .ServerToClient),
      (.CertificateVerify, .ServerToClient),
      (.Finished, .ServerToClient)
    ]).isSome = true := by
  native_decide

/-- Out-of-order messages are rejected. -/
theorem out_of_order_rejected :
    runTrace [
      (.ServerHello, .ServerToClient),  -- ServerHello before ClientHello
      (.ClientHello, .ClientToServer)
    ] = none := by
  native_decide

end TLS.Model
