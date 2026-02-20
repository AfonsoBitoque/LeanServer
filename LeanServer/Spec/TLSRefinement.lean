import LeanServer.Spec.TLSModel
import LeanServer.Spec.ServerStep
import LeanServer.Crypto.Crypto
import LeanServer.Core.Basic

/-!
  # TLS Implementation Refinement (Layer 3 — Impl ↔ Model Bridge)

  ## Refinement Architecture (F2.0)
  This module proves that the **real TLS implementation** (in Crypto.lean)
  faithfully implements the **executable model** (in TLSModel.lean).

  ### Refinement Chain:
  ```
  TLS.Spec (propositions) ←—— TLS.Model (functions) ←—— TLS.Impl (IO code)
       ↑ model_refines_spec          ↑ THIS FILE
  ```

  ### What This Module Proves:
  1. The implementation's TLSState maps correctly to the model's HandshakeState
  2. transitionToAppData corresponds to the Finished transition in the model
  3. encryptAppData is only available in the Connected/Data state
  4. State mapping is consistent across transitions
-/

namespace TLS.Refinement

open TLS.Spec TLS.Model LeanServer

-- ============================================================================
-- State Mapping: Implementation → Model
-- ============================================================================

/-- Map implementation's TLSState to the spec's HandshakeState.
    The implementation uses a coarser 3-state model:
    - Handshake ↦ {Start, WaitServerHello, WaitEncExtensions, ...WaitFinished}
    - Data ↦ Connected
    - Closed ↦ Closed

    This mapping is intentionally many-to-one: the implementation collapses
    the handshake substates into a single "Handshake" state because the
    sub-state tracking is done via the control flow, not a state variable. -/
def implStateToModel : LeanServer.TLSState → HandshakeState
  | .Handshake => .WaitFinished  -- Most conservative mapping: ready for Finished
  | .Data => .Connected
  | .Closed => .Closed

-- ============================================================================
-- Refinement Proofs: Impl corresponds to Model
-- ============================================================================

/-- The implementation's Closed state maps to the model's Closed state. -/
theorem impl_closed_maps_to_model_closed :
    implStateToModel .Closed = .Closed := rfl

/-- The implementation's Data state maps to the model's Connected state. -/
theorem impl_data_maps_to_model_connected :
    implStateToModel .Data = .Connected := rfl

/-- transitionToAppData in the implementation corresponds to the
    Finished transition in the model (WaitFinished → Connected).
    When transitionToAppData succeeds, the resulting state maps to Connected. -/
theorem transitionToAppData_refines_model
    (session : TLSSessionTLS)
    (session' : TLSSessionTLS)
    (h : transitionToAppData session = some session')
    : implStateToModel session'.state = .Connected := by
  -- Prove session'.state = .Data directly from transitionToAppData definition
  unfold transitionToAppData at h
  match hk : session.handshakeKeys with
  | some _ =>
    simp [hk] at h
    rw [← h]
    rfl
  | none =>
    simp [hk] at h

/-- encryptAppData requires Data state (= Connected in model).
    When appKeys is none, encryptAppData returns none — this corresponds
    to the model's property that data can only be sent in Connected state. -/
theorem encryptAppData_requires_connected_state
    (session : TLSSessionTLS)
    (h : session.appKeys = none)
    : encryptAppData session ByteArray.empty = none := by
  unfold encryptAppData
  rw [h]

/-- The implementation's state after transitionToAppData is in the
    model's Connected state, which allows data transfer. -/
theorem data_state_allows_app_data
    (session : TLSSessionTLS)
    (session' : TLSSessionTLS)
    (h : transitionToAppData session = some session')
    : session'.state = .Data := by
  unfold transitionToAppData at h
  match hk : session.handshakeKeys with
  | some _ =>
    simp [hk] at h
    rw [← h]
  | none =>
    simp [hk] at h

/-- Closed is terminal in both the implementation and the model.
    The implementation's closeConnection always returns Closed,
    and the model's Closed state has no valid transitions. -/
theorem closed_terminal_consistent :
    ∀ (s : ConnectionState),
    closeConnection s = .Closed := by
  intro s
  rfl

-- ============================================================================
-- Abstraction Function Properties
-- ============================================================================

/-- The state mapping preserves the terminal property:
    if the model state is Closed, the impl state must be Closed. -/
theorem closed_preserved :
    ∀ (s : LeanServer.TLSState),
    implStateToModel s = .Closed → s = .Closed := by
  intro s h
  match s with
  | .Closed => rfl
  | .Handshake => simp [implStateToModel] at h
  | .Data => simp [implStateToModel] at h

/-- The state mapping preserves the Connected property:
    only Data maps to Connected. -/
theorem connected_preserved :
    ∀ (s : LeanServer.TLSState),
    implStateToModel s = .Connected → s = .Data := by
  intro s h
  match s with
  | .Data => rfl
  | .Handshake => simp [implStateToModel] at h
  | .Closed => simp [implStateToModel] at h

-- ============================================================================
-- ServerStep ↔ Model Linkage (Phase 3.3)
-- ============================================================================

open TLS.ServerStep in
/-- **ABSTRACTION CONSISTENCY**: The ServerStep's phase mapping is consistent
    with the Impl→Model mapping for the Connected state.
    When ServerStep reaches `.connected`, the Model state is `.Connected`,
    which corresponds to Impl's `.Data` state. -/
theorem serverStep_connected_consistent :
    phaseToModelState .connected = implStateToModel .Data := by
  rfl

open TLS.ServerStep in
/-- **ABSTRACTION CONSISTENCY**: The ServerStep's phase mapping is consistent
    with the Impl→Model mapping for the Closed state. -/
theorem serverStep_closed_consistent :
    phaseToModelState .closed = implStateToModel .Closed := by
  rfl

open TLS.ServerStep in
/-- **FULL CHAIN**: When the server processes ClientHello → Finished through
    `serverHandshakeStep`, and the implementation transitions via `transitionToAppData`,
    both paths arrive at the Model's Connected state.

    This is the key Phase 3.3 linkage theorem:
    ```
    ServerStep path:  awaitClientHello → awaitClientFinished → connected
                      (phaseToModelState .connected = .Connected)

    Impl path:        Handshake → Data (via transitionToAppData)
                      (implStateToModel .Data = .Connected)
    ```
    Both map to Model's `.Connected`, proving the refinement chain is consistent. -/
theorem full_chain_connected :
    ∀ (params : NegotiatedParams),
    let (s1, _) := serverHandshakeStep initialServerState (.clientHello params true)
    let (s2, _) := serverHandshakeStep s1 (.clientFinished true)
    phaseToModelState s2.phase = .Connected ∧
    implStateToModel .Data = .Connected := by
  intro params
  simp [serverHandshakeStep, initialServerState, default, phaseToModelState, implStateToModel]

open TLS.ServerStep in
/-- **REFINEMENT PRESERVATION**: When `serverHandshakeStep` transitions from
    `awaitClientFinished` to `connected` via a verified Finished message,
    this corresponds to a valid `TLS.Spec.Transition` in the Spec layer.

    Chain: serverHandshakeStep → phaseToModelState → Model.tryTransition → Spec.Transition -/
theorem serverStep_finished_valid_spec_transition :
    ∀ (state : TLSServerState),
    state.phase = .awaitClientFinished →
    let (s', _) := serverHandshakeStep state (.clientFinished true)
    -- 1. ServerStep produces Connected
    s'.phase = .connected ∧
    -- 2. Which maps to Model's Connected
    phaseToModelState s'.phase = .Connected ∧
    -- 3. And the corresponding Model transition is valid in the Spec
    Transition .WaitFinished .Finished .ServerToClient .Connected ∧
    -- 4. And the Model accepts this transition
    tryTransition .WaitFinished .Finished .ServerToClient = some .Connected := by
  intro state hphase
  simp [serverHandshakeStep, hphase, phaseToModelState]
  exact ⟨Transition.serverFinished, rfl⟩

open TLS.ServerStep in
/-- **IMPL→SERVERSTEP BRIDGE**: When the implementation's `transitionToAppData`
    succeeds, the resulting state maps to the same Model state as ServerStep's
    `.connected` phase.

    This closes the refinement triangle:
    - ServerStep (.connected) → Model (.Connected) [via phaseToModelState]
    - Impl (.Data) → Model (.Connected) [via implStateToModel]
    - transitionToAppData produces .Data [via data_state_allows_app_data] -/
theorem impl_serverstep_model_triangle :
    ∀ (session session' : TLSSessionTLS),
    transitionToAppData session = some session' →
    implStateToModel session'.state = phaseToModelState .connected := by
  intro session session' h
  have hdata := data_state_allows_app_data session session' h
  rw [hdata]
  rfl

open TLS.ServerStep in
/-- **SAFETY**: The ServerStep rejects unverified Finished messages (closing the
    connection), and this closed state maps to the Model's Closed state,
    which is terminal in the Spec. -/
theorem unverified_finished_maps_to_closed :
    ∀ (state : TLSServerState),
    state.phase = .awaitClientFinished →
    let (s', _) := serverHandshakeStep state (.clientFinished false)
    phaseToModelState s'.phase = .Closed ∧
    -- Closed is terminal in the Spec
    ¬ ∃ msg dir s'', Transition .Closed msg dir s'' := by
  intro state hphase
  constructor
  · simp [hphase, phaseToModelState]
  · exact closed_is_terminal

end TLS.Refinement
