-- Database Layer Implementation
-- Type-safe database abstraction for Lean 4
-- Supports PostgreSQL, MySQL, and other databases

import LeanServer.Core.Basic

/-! Este módulo define interfaces e tipos para abstracção de base de dados.
    As queries são executadas via FFI quando os drivers nativos (libpq, libmysqlclient)
    estão linkados. Sem drivers, as chamadas FFI retornam erro graciosamente.
    Ver ROADMAP.md (Fase 5) para plano de integração de drivers nativos. -/

namespace LeanServer

-- ==========================================
-- DATABASE TYPES
-- ==========================================

-- Supported database types
inductive DatabaseType : Type where
  | PostgreSQL : DatabaseType
  | MySQL : DatabaseType
  | SQLite : DatabaseType  -- Future support

instance : Inhabited DatabaseType where
  default := DatabaseType.PostgreSQL

-- Database connection configuration
structure DatabaseConfig where
  host : String
  port : UInt16
  database : String
  username : String
  password : String
  maxConnections : Nat := 10
  connectionTimeout : Nat := 30  -- seconds

instance : Inhabited DatabaseConfig where
  default := {
    host := "localhost"
    port := 5432
    database := "lean_db"
    username := "user"
    password := "password"
    maxConnections := 10
    connectionTimeout := 30
  }

-- Connection status tracks the lifecycle of a database connection
inductive ConnectionStatus : Type where
  | Disconnected : ConnectionStatus         -- Not yet connected
  | Connected : ConnectionStatus            -- Active and healthy
  | Failed : String → ConnectionStatus      -- Connection attempt failed (with reason)
  | Closed : ConnectionStatus               -- Explicitly closed
  deriving Inhabited

-- Database connection handle (opaque type for FFI)
structure DatabaseConnection where
  handle : USize                     -- Pointer to native connection (0 = not yet established)
  config : DatabaseConfig
  status : ConnectionStatus := .Disconnected
  connectionId : Nat := 0           -- Unique ID within the pool for safe indexing

-- Backward-compat helper
def DatabaseConnection.isConnected (c : DatabaseConnection) : Bool :=
  match c.status with
  | .Connected => true
  | _ => false

instance : Inhabited DatabaseConnection where
  default := {
    handle := 0
    config := default
    status := .Disconnected
    connectionId := 0
  }

-- SQL Query result
structure QueryResult where
  rows : Array (Array String)  -- Rows of string values
  columns : Array String       -- Column names
  affectedRows : Nat := 0      -- For INSERT/UPDATE/DELETE

instance : Inhabited QueryResult where
  default := {
    rows := #[]
    columns := #[]
    affectedRows := 0
  }

-- Database transaction
structure DatabaseTransaction where
  connection : DatabaseConnection
  isActive : Bool := true

instance : Inhabited DatabaseTransaction where
  default := {
    connection := default
    isActive := false
  }

-- ==========================================
-- DATABASE ERRORS
-- ==========================================

inductive DatabaseError : Type where
  | ConnectionFailed : String → DatabaseError
  | QueryFailed : String → DatabaseError
  | TransactionFailed : String → DatabaseError
  | InvalidConfig : String → DatabaseError
  | Timeout : DatabaseError
  | Unknown : String → DatabaseError

instance : Inhabited DatabaseError where
  default := DatabaseError.Unknown "Unknown error"

-- ==========================================
-- DATABASE CONNECTION POOL
-- ==========================================

structure ConnectionPool where
  connections : Array DatabaseConnection
  available : Array Nat  -- Indices of available connections
  config : DatabaseConfig
  maxSize : Nat
  nextId : Nat := 0      -- Monotonically increasing connection ID

instance : Inhabited ConnectionPool where
  default := {
    connections := #[]
    available := #[]
    config := default
    maxSize := 10
    nextId := 0
  }

-- ==========================================
-- GENERIC DATABASE INTERFACE
-- ==========================================

class DatabaseDriver (α : Type) where
  -- Connect to database
  connect : DatabaseConfig → IO (Except DatabaseError DatabaseConnection)

  -- Disconnect from database
  disconnect : DatabaseConnection → IO (Except DatabaseError Unit)

  -- Execute query
  executeQuery : DatabaseConnection → String → IO (Except DatabaseError QueryResult)

  -- Execute non-query (INSERT/UPDATE/DELETE)
  executeNonQuery : DatabaseConnection → String → IO (Except DatabaseError Nat)

  -- Begin transaction
  beginTransaction : DatabaseConnection → IO (Except DatabaseError DatabaseTransaction)

  -- Commit transaction
  commitTransaction : DatabaseTransaction → IO (Except DatabaseError Unit)

  -- Rollback transaction
  rollbackTransaction : DatabaseTransaction → IO (Except DatabaseError Unit)

  -- Check connection health
  ping : DatabaseConnection → IO Bool

-- ==========================================
-- CONNECTION POOL MANAGEMENT
-- ==========================================

-- Initialize connection pool
def initConnectionPool (config : DatabaseConfig) (maxSize : Nat := 10) : IO ConnectionPool := do
  return {
    connections := #[]
    available := #[]
    config := config
    maxSize := maxSize
  }

-- Get connection from pool (uses DatabaseDriver to establish real connections)
def getConnectionFromPool' [DatabaseDriver α] (_driver : α) (pool : ConnectionPool) : IO (Except DatabaseError (ConnectionPool × DatabaseConnection)) := do
  if pool.available.isEmpty then
    if pool.connections.size < pool.maxSize then
      -- Create new connection via the driver
      let connResult ← DatabaseDriver.connect (α := α) pool.config
      match connResult with
      | Except.ok rawConn =>
        let newConn := { rawConn with
          status := .Connected
          connectionId := pool.nextId
        }
        let newConnections := pool.connections.push newConn
        let newPool := { pool with connections := newConnections, nextId := pool.nextId + 1 }
        return Except.ok (newPool, newConn)
      | Except.error err =>
        return Except.error err
    else
      return Except.error (DatabaseError.Unknown "Connection pool exhausted")
  else
    let idx := pool.available[0]!
    let conn := pool.connections[idx]!
    let newAvailable := pool.available.extract 1 pool.available.size
    -- Verify the connection is still alive before handing it out
    if conn.isConnected then
      let newPool := { pool with available := newAvailable }
      return Except.ok (newPool, conn)
    else
      -- Stale connection — try to reconnect via the driver
      let connResult ← DatabaseDriver.connect (α := α) pool.config
      match connResult with
      | Except.ok rawConn =>
        let refreshed := { rawConn with
          status := .Connected
          connectionId := conn.connectionId
        }
        let newConnections := pool.connections.set! idx refreshed
        let newPool := { pool with connections := newConnections, available := newAvailable }
        return Except.ok (newPool, refreshed)
      | Except.error err =>
        -- Remove the dead connection from the pool
        let _newPool := { pool with available := newAvailable }
        return Except.error err

-- Legacy non-driver version (for backward compatibility — returns error instead of fake connection)
def getConnectionFromPool (pool : ConnectionPool) : IO (Except DatabaseError (ConnectionPool × DatabaseConnection)) := do
  if pool.available.isEmpty then
    if pool.connections.size < pool.maxSize then
      return Except.error (DatabaseError.ConnectionFailed "No database driver configured — use getConnectionFromPool' with a DatabaseDriver instance")
    else
      return Except.error (DatabaseError.Unknown "Connection pool exhausted")
  else
    let idx := pool.available[0]!
    let conn := pool.connections[idx]!
    let newAvailable := pool.available.extract 1 pool.available.size
    let newPool := { pool with available := newAvailable }
    return Except.ok (newPool, conn)

-- Return connection to pool
def returnConnectionToPool (pool : ConnectionPool) (connection : DatabaseConnection) : ConnectionPool :=
  -- Find connection by unique connectionId (not handle, which may be non-unique)
  match pool.connections.findIdx? (fun c => c.connectionId == connection.connectionId) with
  | some idx =>
    if pool.available.contains idx then
      pool  -- Already in pool
    else
      { pool with available := pool.available.push idx }
  | none => pool  -- Connection not found

-- Close all connections in pool
def closeConnectionPool [DatabaseDriver α] (_driver : α) (pool : ConnectionPool) : IO Unit := do
  for conn in pool.connections do
    if conn.isConnected then
      let _ ← DatabaseDriver.disconnect (α := α) conn
      IO.eprintln s!"Connection {conn.connectionId} closed"
  IO.eprintln s!"Connection pool closed ({pool.connections.size} connections)"

-- Legacy close (no driver — just logs)
def closeConnectionPoolLegacy (pool : ConnectionPool) : IO Unit := do
  for conn in pool.connections do
    IO.eprintln s!"Connection {conn.connectionId} closed (no driver — cannot disconnect)"
  IO.eprintln s!"Connection pool closed ({pool.connections.size} connections)"

-- ==========================================
-- TYPE-SAFE ORM FOUNDATION
-- ==========================================

-- Generic table schema
structure TableSchema where
  name : String
  columns : Array ColumnSchema

structure ColumnSchema where
  name : String
  type : ColumnType
  nullable : Bool := false
  primaryKey : Bool := false
  autoIncrement : Bool := false

inductive ColumnType : Type where
  | Integer : ColumnType
  | BigInt : ColumnType
  | Text : ColumnType
  | Varchar : Nat → ColumnType
  | Boolean : ColumnType
  | DateTime : ColumnType
  | Decimal : Nat → Nat → ColumnType  -- precision, scale
  | Blob : ColumnType

instance : Inhabited ColumnType where
  default := ColumnType.Text

-- Entity base class
class DatabaseEntity (α : Type) where
  tableName : String
  schema : TableSchema
  toRow : α → Array String
  fromRow : Array String → Option α

-- ==========================================
-- QUERY BUILDER
-- ==========================================

structure QueryBuilder where
  table : String
  select : Array String := #["*"]
  whereClause : Option String := none
  orderBy : Option String := none
  limit : Option Nat := none
  offset : Option Nat := none

instance : Inhabited QueryBuilder where
  default := {
    table := ""
    select := #["*"]
    whereClause := none
    orderBy := none
    limit := none
    offset := none
  }

-- Build SELECT query
def QueryBuilder.buildSelect (qb : QueryBuilder) : String :=
  let selectClause := String.intercalate ", " qb.select.toList
  let baseQuery := s!"SELECT {selectClause} FROM {qb.table}"

  let withWhere := match qb.whereClause with
    | some whereClause => s!"{baseQuery} WHERE {whereClause}"
    | none => baseQuery

  let withOrder := match qb.orderBy with
    | some order => s!"{withWhere} ORDER BY {order}"
    | none => withWhere

  let withLimit := match qb.limit with
    | some lim => s!"{withOrder} LIMIT {lim}"
    | none => withOrder

  match qb.offset with
    | some off => s!"{withLimit} OFFSET {off}"
    | none => withLimit

-- ==========================================
-- MIGRATION SYSTEM
-- ==========================================

structure Migration where
  version : Nat
  name : String
  up : String    -- SQL to run migration
  down : String  -- SQL to rollback migration

instance : Inhabited Migration where
  default := {
    version := 0
    name := ""
    up := ""
    down := ""
  }

structure MigrationState where
  applied : Array Nat  -- Applied migration versions
  currentVersion : Nat := 0

instance : Inhabited MigrationState where
  default := {
    applied := #[]
    currentVersion := 0
  }

-- ==========================================
-- DATABASE MANAGER
-- ==========================================

structure DatabaseManager (α : Type) [DatabaseDriver α] where
  pool : ConnectionPool
  migrations : Array Migration
  migrationState : MigrationState
  dbType : DatabaseType
  driver : α

-- Initialize database manager
def initDatabaseManager [DatabaseDriver α] (driver : α) (config : DatabaseConfig) (dbType : DatabaseType := DatabaseType.PostgreSQL) : IO (DatabaseManager α) := do
  let pool ← initConnectionPool config
  return {
    pool := pool
    migrations := #[]
    migrationState := default
    dbType := dbType
    driver := driver
  }

-- Execute query with connection from pool
def executeQueryWithPool [DatabaseDriver α] (manager : DatabaseManager α) (query : String) : IO (Except DatabaseError (DatabaseManager α × QueryResult)) := do
  match ← getConnectionFromPool' manager.driver manager.pool with
  | Except.ok (newPool, conn) =>
    if !conn.isConnected then
      return Except.error (DatabaseError.ConnectionFailed "Connection not established")
    -- Execute query using the database driver
    let queryResult ← DatabaseDriver.executeQuery (α := α) conn query
    match queryResult with
    | Except.ok result =>
      let updatedManager := { manager with pool := returnConnectionToPool newPool conn }
      return Except.ok (updatedManager, result)
    | Except.error err =>
      let _updatedManager := { manager with pool := returnConnectionToPool newPool conn }
      return Except.error err
  | Except.error err =>
    return Except.error err

-- ==========================================
-- UTILITY FUNCTIONS
-- ==========================================

-- Escape SQL string to prevent SQL injection
def escapeSqlString (s : String) : String :=
  -- Escape dangerous characters per MySQL/PostgreSQL escaping rules
  let escaped := s.toList.foldl (fun acc c =>
    match c with
    | '\'' => acc ++ "\\'"        -- Single quote
    | '\\' => acc ++ "\\\\"      -- Backslash
    | '"'  => acc ++ "\\\""      -- Double quote
    | '\n' => acc ++ "\\n"       -- Newline
    | '\r' => acc ++ "\\r"       -- Carriage return
    | '\x00' => acc ++ "\\0"    -- Null byte
    | '\x1a' => acc ++ "\\Z"    -- Ctrl+Z (EOF on Windows)
    | _    => acc ++ c.toString
  ) ""
  s!"'{escaped}'"

-- Build parameterized query
def buildParameterizedQuery (template : String) (params : Array String) : String :=
  -- Simple parameter replacement - in real implementation, use prepared statements
  let escapedParams := params.map escapeSqlString
  -- Replace ? placeholders with escaped parameters
  let query := template
  let chars := query.toList
  let rec build (remaining : List Char) (paramIndex : Nat) (result : String) : String :=
    match remaining with
    | [] => result
    | c :: rest =>
      if c == '?' && paramIndex < escapedParams.size then
        build rest (paramIndex + 1) (result ++ escapedParams[paramIndex]!)
      else
        build rest paramIndex (result ++ c.toString)
  build chars 0 ""

-- Get database statistics
def getDatabaseStats [DatabaseDriver α] (manager : DatabaseManager α) : String :=
  let poolSize := manager.pool.connections.size
  let available := manager.pool.available.size
  let migrations := manager.migrations.size
  "Database Stats: " ++ toString poolSize ++ " connections, " ++ toString available ++ " available, " ++ toString migrations ++ " migrations"

end LeanServer
