import LeanServer.Server.HTTPServer

/-!
  # QPACK Encoder/Decoder — Re-export Module
  HTTP/3 QPACK header compression (RFC 9204).

  ## Key Functions
  - `encodeQPACKResponseHeaders` — Encode response headers with QPACK
  - `encodeQPACKSimple` — Simple QPACK encoding for common responses
  - `qpackDynamicTableLookup` — Dynamic table lookup
  - `qpackDynamicTableInsert` — Insert into dynamic table
  - `encodeQPACKEncoderInsertStaticRef` — Encoder stream: insert with static ref
  - `encodeQPACKEncoderInsertLiteral` — Encoder stream: insert literal
  - `encodeQPACKSectionAck` — Section acknowledgment
-/

namespace LeanServer.QPACK

/-- Encode response headers with QPACK (dynamic table aware) -/
@[inline] def encodeResponseHeaders (status : String) (headers : Array (String × String))
    (dynamicTable : Array (String × String) := #[]) : ByteArray × Array (String × String) :=
  LeanServer.encodeQPACKResponseHeaders status headers dynamicTable

/-- Simple QPACK encoding (static table only) -/
@[inline] def encodeSimple (status contentType : String) (contentLength : Nat)
    (extraHeaders : Array (String × String) := #[])
    (dynTable : Array (String × String) := #[]) : ByteArray × Array (String × String) :=
  LeanServer.encodeQPACKSimple status contentType contentLength extraHeaders dynTable

/-- Dynamic table lookup -/
@[inline] def lookup (table : Array (String × String)) (absIndex : Nat) : Option (String × String) :=
  LeanServer.qpackDynamicTableLookup table absIndex

/-- Dynamic table insert -/
@[inline] def insert (table : Array (String × String)) (name value : String) (maxEntries : Nat := 128) : Array (String × String) :=
  LeanServer.qpackDynamicTableInsert table name value maxEntries

end LeanServer.QPACK
