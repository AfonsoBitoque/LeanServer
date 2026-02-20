# Proof Guide — LeanServer6

This document describes the proof methodology, naming conventions, and tactics used in LeanServer6.

## Proof Architecture

LeanServer6 uses a **3-layer refinement architecture** inspired by seL4 and CertiKOS:

1. **Layer 1 — Abstract Specification** (`LeanServer/Spec/TLSSpec.lean`): Defines protocol behavior as inductive relations. No implementation.
2. **Layer 2 — Executable Model** (`LeanServer/Spec/TLSModel.lean`): Deterministic functions that refine the abstract spec. Proven: `model_refines_spec`.
3. **Layer 3 — Implementation Bridge** (`LeanServer/Spec/TLSRefinement.lean`): Maps real implementation types to model types. Proven: `impl_refines_model`.

## Proof Categories

### 1. Structural Proofs (constructive)
- **Tactics**: `cases`, `intro`, `simp`, `omega`, `rfl`, `split`, `contradiction`
- **Used for**: State machine impossibility, algebraic properties, universal quantifiers
- **Example**: `no_skip_handshake : ¬ ∃ msg dir, Transition .Start msg dir .Connected`

### 2. Protocol Invariant Proofs (constructive)
- **Tactics**: `unfold`, `simp only`, `split`, `omega`, `rfl`
- **Used for**: RFC-mandated invariants (HPACK table size, flow control bounds, QUIC packet number monotonicity)
- **Example**: `hpack_maxsize_preserved : (addToDynamicTable t f).size ≤ t.maxSize`

### 3. Universal Codec Proofs (constructive)
- **Tactics**: `intro`, `unfold`, `simp`, `omega`, `split`, `induction`
- **Used for**: Properties that hold for ALL inputs (parser bounds, progress, roundtrip)
- **Example**: `parser_bounded : ∀ bs pos result, run bs pos = some result → result.2 ≤ bs.size`

### 4. Specification Test Vectors (`native_decide`)
- **Tactics**: `native_decide`
- **Used for**: Concrete-value verification — verified unit tests
- **Example**: `varint_roundtrip_37 : decodeVarInt (encodeVarInt 37) 0 = some (37, 1)`

## `native_decide` Policy

### When to use `native_decide`
`native_decide` evaluates decidable propositions by compiling and running them natively. It is appropriate for:

1. **Table/constant size checks**: Verifying that lookup tables (AES S-Box, SHA-256 constants) have the correct number of entries. These cannot be proven constructively without listing every element.
   - `aes_sbox_complete : sbox.size = 256`
   - `sha256_k_size : sha256K.size = 64`

2. **Concrete roundtrip test vectors**: Verifying encode/decode roundtrips at specific values (RFC test vectors, boundary values). These serve as regression guards.
   - `varint_roundtrip_0`, `varint_roundtrip_63`, `varint_roundtrip_16383`, etc.
   - `frameHeader_roundtrip_data`, `frameHeader_roundtrip_headers`

3. **Concrete crypto output checks**: Verifying that cryptographic functions produce outputs of the correct size on specific inputs.
   - `sha256_empty_size : (sha256 ByteArray.empty).size = 32`
   - `hkdf_expand_size_32`, `hkdf_expand_size_16`

4. **TLS state machine trace evaluations**: Verifying that specific message sequences produce expected states. The traces are finite and concrete.
   - `complete_handshake_reaches_connected`
   - `out_of_order_rejected`
   - `alert_terminates_handshake`

### When NOT to use `native_decide`
- **Universal quantifiers** (`∀ x, P x`): Use `intro` + structural tactics
- **Algorithmic properties**: Use `simp`, `omega`, `induction`
- **Parser bounds/progress**: Use the verified parser combinator framework
- **Protocol invariants over symbolic inputs**: Use `unfold` + `simp only` + `split`

### Current Statistics
- **392 `native_decide` usages** across 14 files (Proofs.lean, TLSModel.lean, TLSStateMachineProofs.lean, ProtocolInvariants.lean, ContentNegotiation.lean, UniversalCodecProofs.lean, AdvancedProofs.lean, AdvancedProofs2.lean, AdvancedProofs3.lean, CompositionProofs.lean, AES.lean, SideChannel.lean, NonceManager.lean, SQLite.lean)
- **All are Category A** (concrete-value/table checks) — no algorithmic properties use `native_decide`
- **3 former `native_decide` usages** were replaced with constructive proofs:
  - `decodeVarInt_empty`: now `unfold decodeVarInt; simp`
  - `parseFrameHeader_empty`: now `exact parseFrameHeader_undersized _ (by simp [ByteArray.size])`
  - These had universal counterparts (`decodeVarInt_empty_none`, `parseFrameHeader_undersized`) that made the concrete instances derivable

### Comparison with Reference Projects
| Project | Approach | Equivalent to our `native_decide` |
|---------|----------|-----------------------------------|
| **HACL\*** (F*) | `normalize_term` for table checks | Same — evaluates concrete terms at verification time |
| **s2n-tls** (CBMC) | Bounded model checking on concrete inputs | Same — checks specific inputs, not universal |
| **seL4** (Isabelle/HOL) | `eval` for concrete computations | Same — evaluated by kernel for specific values |
| **CompCert** (Coq) | `reflexivity` + `compute` for tables | Same — reduces concrete terms |

## Naming Conventions

### Theorems
- `{module}_{property}`: e.g., `hpack_maxsize_preserved`, `quic_pn_monotonic`
- `{function}_roundtrip_{value}`: e.g., `varint_roundtrip_37`, `frameHeader_roundtrip_data`
- `{function}_{behavior}`: e.g., `parseFrameHeader_empty`, `sha256_empty_size`
- `no_{violation}`: e.g., `no_skip_handshake`, `no_send_after_close`

### Files
- `LeanServer/Spec/`: Formal specifications and proofs
- `LeanServer/Core/`: Core types and parser combinators
- `LeanServer/Proofs.lean`: Concrete test vector proofs

## Key Proof Techniques

### 1. Closed-form pattern for `native_decide`
`native_decide` requires NO free variables. Use `.bind` to avoid `∀`:
```lean
-- WRONG: ∀ ms, runTrace [...] = some ms → ms.hasAppKeys = true
-- RIGHT:
theorem handshake_produces_keys :
  (runTrace [...]).bind (fun s => some s.hasAppKeys) = some true := by native_decide
```

### 2. `simp only` vs `unfold` for `let` bindings
`unfold` preserves `let` bindings as `have` in the goal, blocking `split`. Use `simp only [defName]` to inline them:
```lean
-- WRONG: unfold updateConnectionWindow; split at h  -- fails
-- RIGHT:
  simp only [updateConnectionWindow]; split at h  -- works
```

### 3. Fuel pattern for totality
Convert `partial def` to total using explicit fuel:
```lean
def parseRSAPrivateKey (keyBytes : ByteArray) : Option (Nat × Nat) :=
  parseRSAPrivateKeyAux keyBytes 2  -- fuel=2: PKCS#8 wraps PKCS#1 at most once
where
  parseRSAPrivateKeyAux (data : ByteArray) (fuel : Nat) : Option (Nat × Nat) :=
    match fuel with
    | 0 => none
    | fuel' + 1 => ...  -- recursive call uses fuel'
```

### 4. Bool vs Prop
Functions returning `Bool` use `decide`. State theorems with `= decide (...)`:
```lean
-- For: def canSend (conn) (ds) : Bool := decide (conn.windowSize ≥ ds)
theorem h2_can_send_spec : canSendDataOnConnection conn ds = decide (conn.windowSize ≥ ds) := by rfl
```
