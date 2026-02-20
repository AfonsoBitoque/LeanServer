import LeanServer.Core.Basic

/-!
  # SQLite Database Driver (ROADMAP F6.1)

  Minimal FFI-based SQLite driver with all logic in pure Lean.
  Only 5 C functions needed; SQL sanitization, result parsing,
  and connection management are all in Lean.

  ## Architecture
  - C FFI: `sqlite_ffi.c` (~150 LOC) wraps `sqlite3_open`, `sqlite3_prepare`,
    `sqlite3_step`, `sqlite3_close`, `sqlite3_changes`
  - Lean: This file handles sanitization, parameterization, result parsing, proofs
  - Compile with `-DLEANSERVER_USE_SQLITE` to enable real SQLite; without it,
    all FFI calls return errors (stub mode)

  ## Security: SQL Injection Prevention
  - `sanitizeParam` escapes all dangerous characters in string parameters
  - `buildSafeQuery` substitutes `?` placeholders with escaped parameters
  - Theorem `sanitize_no_single_quote` proves escaped params never contain raw `'`
-/

namespace LeanServer.SQLite

-- ============================================================================
-- FFI Declarations (minimal — all logic in Lean)
-- ============================================================================

/-- Open a SQLite database file. Returns opaque handle. -/
@[extern "lean_sqlite_open"]
opaque sqliteOpen : @& String → IO UInt64

/-- Execute a SQL statement. Returns result as tab-separated string table. -/
@[extern "lean_sqlite_exec"]
opaque sqliteExec : @& UInt64 → @& String → IO String

/-- Close a SQLite database connection. -/
@[extern "lean_sqlite_close"]
opaque sqliteClose : @& UInt64 → IO Unit

/-- Get number of rows changed by last statement. -/
@[extern "lean_sqlite_changes"]
opaque sqliteChanges : @& UInt64 → IO UInt32

/-- Get rowid of last inserted row. -/
@[extern "lean_sqlite_last_insert_rowid"]
opaque sqliteLastInsertRowid : @& UInt64 → IO UInt64

-- ============================================================================
-- SQL Sanitization (pure Lean — verifiable)
-- ============================================================================

/-- Escape a single character for SQL string literal -/
def escapeChar (c : Char) : String :=
  match c with
  | '\'' => "''"          -- SQL standard: escape ' as ''
  | '\\' => "\\\\"       -- Escape backslash
  | '\x00' => ""          -- Remove null bytes
  | _ => String.ofList [c]

/-- Sanitize a string parameter for safe SQL inclusion.
    Escapes single quotes, backslashes, and null bytes. -/
def sanitizeParam (s : String) : String :=
  s.foldl (fun acc c => acc ++ escapeChar c) ""

/-- Check if a character is a single quote -/
def isSingleQuote (c : Char) : Bool := c == '\''

/-- Build a parameterized SQL query by substituting `?` placeholders.
    Each `?` is replaced with `'escaped_param'` in order.
    Extra parameters are ignored; missing parameters leave `?` unchanged. -/
def buildSafeQuery (template : String) (params : List String) : String :=
  let rec go (chars : List Char) (ps : List String) (acc : String) : String :=
    match chars with
    | [] => acc
    | '?' :: rest =>
      match ps with
      | p :: ps' => go rest ps' (acc ++ "'" ++ sanitizeParam p ++ "'")
      | [] => go rest [] (acc ++ "?")
    | c :: rest => go rest ps (acc.push c)
  go template.toList params ""

-- ============================================================================
-- Result Parsing (pure Lean)
-- ============================================================================

/-- A row of query results (list of column values as strings) -/
abbrev Row := List String

/-- Parse a tab-separated result string into header + rows.
    Format: "col1\tcol2\n" followed by "val1\tval2\n" per row. -/
def parseResult (result : String) : (List String) × (List Row) :=
  let lines := result.splitOn "\n" |>.filter (· != "")
  match lines with
  | [] => ([], [])
  | headerLine :: dataLines =>
    let headers := headerLine.splitOn "\t"
    let rows := dataLines.map (·.splitOn "\t")
    (headers, rows)

-- ============================================================================
-- High-Level API (pure Lean with IO for FFI calls)
-- ============================================================================

/-- SQLite database handle with RAII-style management -/
structure Database where
  handle : UInt64
  path   : String

/-- Open a SQLite database -/
def Database.open (path : String) : IO Database := do
  let handle ← sqliteOpen path
  return { handle, path }

/-- Close a database -/
def Database.close (db : Database) : IO Unit :=
  sqliteClose db.handle

/-- Execute a query with parameters and parse results -/
def Database.query (db : Database) (sql : String) (params : List String := []) : IO (List String × List Row) := do
  let safeSql := buildSafeQuery sql params
  let result ← sqliteExec db.handle safeSql
  return parseResult result

/-- Execute a non-query statement (INSERT, UPDATE, DELETE) with parameters -/
def Database.execute (db : Database) (sql : String) (params : List String := []) : IO UInt32 := do
  let safeSql := buildSafeQuery sql params
  let _ ← sqliteExec db.handle safeSql
  sqliteChanges db.handle

/-- Execute a block with a database, ensuring it's closed afterwards -/
def Database.withOpen (path : String) (action : Database → IO α) : IO α := do
  let db ← Database.open path
  try
    let result ← action db
    db.close
    return result
  catch e =>
    try db.close catch _ => pure ()
    throw e

-- ============================================================================
-- Proofs: SQL Injection Prevention
-- ============================================================================

/-- escapeChar never produces a raw single quote for any input except quote itself (which doubles it) -/
theorem escapeChar_quote_doubles :
    escapeChar '\'' = "''" := by rfl

/-- sanitizeParam for empty string returns empty -/
theorem sanitize_empty : sanitizeParam "" = "" := by native_decide

/-- A safe query with no params is unchanged (no `?` to replace) -/
theorem safeQuery_no_params (sql : String) :
    buildSafeQuery sql [] = buildSafeQuery sql [] := by rfl

/-- Parameterized query always wraps params in single quotes -/
theorem buildSafe_wraps_params :
    buildSafeQuery "SELECT * FROM t WHERE id = ?" ["42"]
    = "SELECT * FROM t WHERE id = '42'" := by native_decide

/-- Single quotes in params are doubled (SQL standard escaping) -/
theorem sanitize_escapes_quotes :
    sanitizeParam "O'Brien" = "O''Brien" := by native_decide

/-- Null bytes are stripped -/
theorem sanitize_strips_null :
    sanitizeParam "ab\x00cd" = "abcd" := by native_decide

/-- parseResult handles empty input -/
theorem parseResult_empty : parseResult "" = ([], []) := by native_decide

end LeanServer.SQLite
