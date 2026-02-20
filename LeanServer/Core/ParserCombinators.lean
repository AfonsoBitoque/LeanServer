/-!
  # Verified Parser Combinators for Binary Protocols (F2.1)

  A library of parser combinators with built-in safety proofs.
  Every parser constructed from these combinators **inherits safety guarantees
  automatically** — no per-parser manual proofs needed.

  ## Guarantees (by construction):
  1. **Bounded**: Never reads past the end of the input buffer
  2. **Progress**: Always advances the position (no infinite loops)
  3. **Deterministic**: Same input always produces the same output
-/

namespace LeanServer.Parser

-- ============================================================================
-- Core Types
-- ============================================================================

/-- Result of a successful parse: the parsed value and the new position. -/
structure ParseResult (α : Type) where
  value : α
  pos : Nat
  deriving Repr

/-- A verified parser combinator. -/
structure Parser (α : Type) where
  run : (bs : ByteArray) → (pos : Nat) → Option (ParseResult α)
  bounded : ∀ bs pos result,
    run bs pos = some result → result.pos ≤ bs.size
  progress : ∀ bs pos result,
    run bs pos = some result → result.pos > pos

-- ============================================================================
-- Primitive Parsers
-- ============================================================================

/-- Read a single byte. -/
def readByte : Parser UInt8 where
  run bs pos :=
    if h : pos < bs.size then
      some ⟨bs.get pos h, pos + 1⟩
    else
      none
  bounded := by
    intro bs pos result h
    split at h
    · have := Option.some.inj h; rw [← this]; dsimp; omega
    · simp at h
  progress := by
    intro bs pos result h
    split at h
    · have := Option.some.inj h; rw [← this]; dsimp; omega
    · simp at h

/-- Read exactly `n` bytes. Requires n > 0 for progress. -/
def readBytes (n : Nat) (hn : n > 0) : Parser ByteArray where
  run bs pos :=
    if pos + n ≤ bs.size then
      some ⟨bs.extract pos (pos + n), pos + n⟩
    else
      none
  bounded := by
    intro bs pos result h
    split at h
    · have := Option.some.inj h; rw [← this]; dsimp; omega
    · simp at h
  progress := by
    intro bs pos result h
    split at h
    · have := Option.some.inj h; rw [← this]; dsimp; omega
    · simp at h

/-- Read a UInt16 in big-endian byte order (2 bytes). -/
def readUInt16BE : Parser UInt16 where
  run bs pos :=
    if h : pos + 1 < bs.size then
      let b0 := bs.get pos (by omega)
      let b1 := bs.get (pos + 1) h
      some ⟨(b0.toUInt16 <<< 8) ||| b1.toUInt16, pos + 2⟩
    else
      none
  bounded := by
    intro bs pos result h
    split at h
    · have := Option.some.inj h; rw [← this]; dsimp; omega
    · simp at h
  progress := by
    intro bs pos result h
    split at h
    · have := Option.some.inj h; rw [← this]; dsimp; omega
    · simp at h

/-- Read a UInt32 in big-endian byte order (4 bytes). -/
def readUInt32BE : Parser UInt32 where
  run bs pos :=
    if h : pos + 3 < bs.size then
      let b0 := bs.get pos (by omega)
      let b1 := bs.get (pos + 1) (by omega)
      let b2 := bs.get (pos + 2) (by omega)
      let b3 := bs.get (pos + 3) h
      some ⟨(b0.toUInt32 <<< 24) ||| (b1.toUInt32 <<< 16) |||
            (b2.toUInt32 <<< 8)  ||| b3.toUInt32, pos + 4⟩
    else
      none
  bounded := by
    intro bs pos result h
    split at h
    · have := Option.some.inj h; rw [← this]; dsimp; omega
    · simp at h
  progress := by
    intro bs pos result h
    split at h
    · have := Option.some.inj h; rw [← this]; dsimp; omega
    · simp at h

-- ============================================================================
-- Combinator: Sequence
-- ============================================================================

/-- Parse p1, then p2 starting where p1 left off. -/
def seq (p1 : Parser α) (p2 : Parser β) : Parser (α × β) where
  run bs pos :=
    match p1.run bs pos with
    | none => none
    | some r1 =>
      match p2.run bs r1.pos with
      | none => none
      | some r2 => some ⟨(r1.value, r2.value), r2.pos⟩
  bounded := by
    intro bs pos result h
    split at h
    · simp at h
    · next r1 _ =>
      split at h
      · simp at h
      · next r2 heq2 =>
        have := Option.some.inj h; rw [← this]; dsimp
        exact p2.bounded bs r1.pos r2 heq2
  progress := by
    intro bs pos result h
    split at h
    · simp at h
    · next r1 heq1 =>
      split at h
      · simp at h
      · next r2 heq2 =>
        have := Option.some.inj h; rw [← this]; dsimp
        have hp1 := p1.progress bs pos r1 heq1
        have hp2 := p2.progress bs r1.pos r2 heq2
        omega

-- ============================================================================
-- Combinator: Alternative
-- ============================================================================

/-- Try parser p1; if it fails, try p2 at the same position. -/
def orElse (p1 : Parser α) (p2 : Parser α) : Parser α where
  run bs pos :=
    match p1.run bs pos with
    | some result => some result
    | none => p2.run bs pos
  bounded := by
    intro bs pos result h
    split at h
    · next r heq =>
      have hh := Option.some.inj h; rw [← hh]
      exact p1.bounded bs pos r heq
    · exact p2.bounded bs pos result h
  progress := by
    intro bs pos result h
    split at h
    · next r heq =>
      have hh := Option.some.inj h; rw [← hh]
      exact p1.progress bs pos r heq
    · exact p2.progress bs pos result h

-- ============================================================================
-- Combinator: Skip
-- ============================================================================

/-- Parse using p but discard the value, returning Unit. -/
def skip (p : Parser α) : Parser Unit where
  run bs pos :=
    match p.run bs pos with
    | none => none
    | some result => some ⟨(), result.pos⟩
  bounded := by
    intro bs pos result h
    split at h
    · simp at h
    · next r heq =>
      have := Option.some.inj h; rw [← this]; dsimp
      exact p.bounded bs pos r heq
  progress := by
    intro bs pos result h
    split at h
    · simp at h
    · next r heq =>
      have := Option.some.inj h; rw [← this]; dsimp
      exact p.progress bs pos r heq

-- ============================================================================
-- Combinator: Guard
-- ============================================================================

/-- Parse using p, then check a predicate on the result. -/
def guard (p : Parser α) (pred : α → Bool) : Parser α where
  run bs pos :=
    match p.run bs pos with
    | none => none
    | some result =>
      if pred result.value then some result else none
  bounded := by
    intro bs pos result h
    split at h
    · simp at h
    · next r heq =>
      split at h
      · have := Option.some.inj h; rw [← this]
        exact p.bounded bs pos r heq
      · simp at h
  progress := by
    intro bs pos result h
    split at h
    · simp at h
    · next r heq =>
      split at h
      · have := Option.some.inj h; rw [← this]
        exact p.progress bs pos r heq
      · simp at h

-- ============================================================================
-- Combinator: Map
-- ============================================================================

/-- Apply a function to the parsed value. -/
def map (p : Parser α) (f : α → β) : Parser β where
  run bs pos :=
    match p.run bs pos with
    | none => none
    | some result => some ⟨f result.value, result.pos⟩
  bounded := by
    intro bs pos result h
    split at h
    · simp at h
    · next r heq =>
      have := Option.some.inj h; rw [← this]; dsimp
      exact p.bounded bs pos r heq
  progress := by
    intro bs pos result h
    split at h
    · simp at h
    · next r heq =>
      have := Option.some.inj h; rw [← this]; dsimp
      exact p.progress bs pos r heq

-- ============================================================================
-- Runner
-- ============================================================================

/-- Run a parser on a byte array from position 0. -/
def parse (p : Parser α) (bs : ByteArray) : Option α :=
  match p.run bs 0 with
  | none => none
  | some result => some result.value

/-- Run a parser and return both the value and the end position. -/
def parseWithPos (p : Parser α) (bs : ByteArray) : Option (α × Nat) :=
  match p.run bs 0 with
  | none => none
  | some result => some (result.value, result.pos)

-- ============================================================================
-- TLS Protocol Parsers
-- ============================================================================

/-- TLS ContentType: 20=CCS, 21=Alert, 22=Handshake, 23=AppData -/
def contentTypeParser : Parser UInt8 :=
  guard readByte (fun b => b == 20 || b == 21 || b == 22 || b == 23)

/-- TLS record header: ContentType (1) + ProtocolVersion (2) + Length (2) = 5 bytes -/
def tlsRecordHeader : Parser (UInt8 × UInt16 × UInt16) :=
  seq readByte (seq readUInt16BE readUInt16BE)

/-- HTTP/2 frame header: Length (3 bytes) + Type (1) + Flags (1) + StreamID (4) -/
def h2FrameHeader : Parser (ByteArray × UInt8 × UInt8 × UInt32) :=
  seq (readBytes 3 (by omega)) (seq readByte (seq readByte readUInt32BE))

-- ============================================================================
-- Properties (inherited from combinators for free)
-- ============================================================================

theorem tlsRecordHeader_bounded :
    ∀ bs pos result,
    tlsRecordHeader.run bs pos = some result →
    result.pos ≤ bs.size :=
  tlsRecordHeader.bounded

theorem tlsRecordHeader_progress :
    ∀ bs pos result,
    tlsRecordHeader.run bs pos = some result →
    result.pos > pos :=
  tlsRecordHeader.progress

theorem h2FrameHeader_bounded :
    ∀ bs pos result,
    h2FrameHeader.run bs pos = some result →
    result.pos ≤ bs.size :=
  h2FrameHeader.bounded

theorem h2FrameHeader_progress :
    ∀ bs pos result,
    h2FrameHeader.run bs pos = some result →
    result.pos > pos :=
  h2FrameHeader.progress

theorem contentType_bounded :
    ∀ bs pos result,
    contentTypeParser.run bs pos = some result →
    result.pos ≤ bs.size :=
  contentTypeParser.bounded

theorem readByte_succeeds_nonempty (bs : ByteArray) (h : 0 < bs.size) :
    (readByte.run bs 0).isSome = true := by
  simp [readByte, h]

theorem readBytes_fails_insufficient (n : Nat) (hn : n > 0) (bs : ByteArray) (pos : Nat)
    (h : pos + n > bs.size) :
    (readBytes n hn).run bs pos = none := by
  simp [readBytes]
  omega

end LeanServer.Parser
