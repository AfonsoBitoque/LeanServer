/-!
  # Structured Logging System
  Provides structured, JSON-compatible logging with timestamps, log levels,
  request IDs, and component tagging.

  ## Features
  - Log levels: ERROR, WARN, INFO, DEBUG, TRACE
  - Structured JSON output (optional)
  - Monotonic timestamps
  - Request/correlation ID tracking
  - Component tagging
  - Configurable minimum log level

  ## Usage
  ```lean
  let logger ← Logger.create .INFO
  logger.info "Server" "Listening on port 4433"
  logger.error "TLS" "Handshake failed" (some reqId)
  logger.withContext "HTTP2" reqId (fun log => do
    log .INFO "Processing stream 5"
    log .DEBUG "HPACK decoded 12 headers")
  ```
-/

namespace LeanServer

/-- Log severity levels (ordered from most to least severe) -/
inductive LogLevel where
  | FATAL | ERROR | WARN | INFO | DEBUG | TRACE
  deriving Inhabited, BEq, Repr

instance : ToString LogLevel where
  toString
    | .FATAL => "FATAL"
    | .ERROR => "ERROR"
    | .WARN  => "WARN"
    | .INFO  => "INFO"
    | .DEBUG => "DEBUG"
    | .TRACE => "TRACE"

/-- Numeric priority for filtering (lower = more severe) -/
def LogLevel.priority : LogLevel → Nat
  | .FATAL => 0 | .ERROR => 1 | .WARN => 2
  | .INFO  => 3 | .DEBUG => 4 | .TRACE => 5

/-- Parse a log level from string -/
def LogLevel.parse (s : String) : LogLevel :=
  match s.toUpper with
  | "FATAL" => .FATAL | "ERROR" => .ERROR | "WARN" => .WARN
  | "INFO" => .INFO   | "DEBUG" => .DEBUG | "TRACE" => .TRACE
  | _ => .INFO

/-- A single structured log entry -/
structure LogEntry where
  level     : LogLevel
  component : String
  message   : String
  timestamp : UInt64       -- monotonic ms
  requestId : Option String := none
  extra     : List (String × String) := []
  deriving Inhabited

/-- Format a log entry as human-readable text -/
def LogEntry.toText (e : LogEntry) : String :=
  let ts := toString e.timestamp
  let rid := match e.requestId with
    | some id => s!" req={id}"
    | none => ""
  let extras := if e.extra.isEmpty then ""
    else " " ++ String.intercalate " " (e.extra.map fun (k, v) => s!"{k}={v}")
  s!"[{ts}ms] [{e.level}] [{e.component}]{rid} {e.message}{extras}"

/-- Format a log entry as JSON -/
def LogEntry.toJSON (e : LogEntry) : String :=
  let ridField := match e.requestId with
    | some id => s!",\"request_id\":\"{id}\""
    | none => ""
  let extFields := if e.extra.isEmpty then ""
    else String.intercalate "" (e.extra.map fun (k, v) => s!",\"{k}\":\"{v}\"")
  s!"\{\"ts\":{e.timestamp},\"level\":\"{e.level}\",\"component\":\"{e.component}\",\"msg\":\"{e.message}\"{ridField}{extFields}}"

/-- Log output format -/
inductive LogFormat where
  | text | json
  deriving Inhabited, BEq

/-- Logger configuration -/
structure LoggerConfig where
  minLevel  : LogLevel  := .INFO
  format    : LogFormat  := .text
  deriving Inhabited

/-- The Logger: holds config and writes to stderr -/
structure Logger where
  config : LoggerConfig
  deriving Inhabited

/-- Create a new logger with the specified minimum level -/
def Logger.create (minLevel : LogLevel := .INFO) (format : LogFormat := .text) : IO Logger := do
  return { config := { minLevel, format } }

/-- Internal: format and emit a log entry -/
private def Logger.emit (logger : Logger) (entry : LogEntry) : IO Unit := do
  let output := match logger.config.format with
    | .text => entry.toText
    | .json => entry.toJSON
  IO.eprintln output

/-- Get current monotonic time in milliseconds -/
private def getMonoMs : IO UInt64 := do
  let ns ← IO.monoNanosNow
  return (ns / 1000000).toUInt64

/-- Log a message at the given level -/
def Logger.log (logger : Logger) (level : LogLevel) (component : String)
    (msg : String) (requestId : Option String := none)
    (extra : List (String × String) := []) : IO Unit := do
  if level.priority ≤ logger.config.minLevel.priority then
    let ts ← getMonoMs
    logger.emit { level, component, message := msg, timestamp := ts, requestId, extra }

/-- Convenience: log at FATAL level -/
def Logger.fatal (logger : Logger) (component : String) (msg : String)
    (requestId : Option String := none) : IO Unit :=
  logger.log .FATAL component msg requestId

/-- Convenience: log at ERROR level -/
def Logger.error (logger : Logger) (component : String) (msg : String)
    (requestId : Option String := none) : IO Unit :=
  logger.log .ERROR component msg requestId

/-- Convenience: log at WARN level -/
def Logger.warn (logger : Logger) (component : String) (msg : String)
    (requestId : Option String := none) : IO Unit :=
  logger.log .WARN component msg requestId

/-- Convenience: log at INFO level -/
def Logger.info (logger : Logger) (component : String) (msg : String)
    (requestId : Option String := none) : IO Unit :=
  logger.log .INFO component msg requestId

/-- Convenience: log at DEBUG level -/
def Logger.debug (logger : Logger) (component : String) (msg : String)
    (requestId : Option String := none) : IO Unit :=
  logger.log .DEBUG component msg requestId

/-- Convenience: log at TRACE level -/
def Logger.trace (logger : Logger) (component : String) (msg : String)
    (requestId : Option String := none) : IO Unit :=
  logger.log .TRACE component msg requestId

/-- Convert a nibble (0-15) to a hex character -/
private def nibbleToHex (n : Nat) : String :=
  match n % 16 with
  | 0 => "0" | 1 => "1" | 2 => "2" | 3 => "3"
  | 4 => "4" | 5 => "5" | 6 => "6" | 7 => "7"
  | 8 => "8" | 9 => "9" | 10 => "a" | 11 => "b"
  | 12 => "c" | 13 => "d" | 14 => "e" | _ => "f"

/-- Generate a short hex request ID (8 chars = 4 bytes) -/
def generateRequestId : IO String := do
  let bytes ← IO.getRandomBytes 4
  let mut result := ""
  for b in bytes.toList do
    result := result ++ nibbleToHex (b.toNat / 16) ++ nibbleToHex (b.toNat % 16)
  return result

/-- Context-bound logger: pre-fills component and requestId -/
structure ScopedLogger where
  logger    : Logger
  component : String
  requestId : Option String
  deriving Inhabited

/-- Create a scoped logger for a specific component/request -/
def Logger.scoped (logger : Logger) (component : String) (requestId : Option String := none) : ScopedLogger :=
  { logger, component, requestId }

/-- Log with pre-filled context -/
def ScopedLogger.log (sl : ScopedLogger) (level : LogLevel) (msg : String)
    (extra : List (String × String) := []) : IO Unit :=
  sl.logger.log level sl.component msg sl.requestId extra

def ScopedLogger.error (sl : ScopedLogger) (msg : String) : IO Unit := sl.log .ERROR msg
def ScopedLogger.warn  (sl : ScopedLogger) (msg : String) : IO Unit := sl.log .WARN msg
def ScopedLogger.info  (sl : ScopedLogger) (msg : String) : IO Unit := sl.log .INFO msg
def ScopedLogger.debug (sl : ScopedLogger) (msg : String) : IO Unit := sl.log .DEBUG msg
def ScopedLogger.trace (sl : ScopedLogger) (msg : String) : IO Unit := sl.log .TRACE msg

-- ==========================================
-- Global Logger Instance
-- ==========================================

/-- Global logger, initialized at startup -/
initialize globalLoggerRef : IO.Ref Logger ← do
  let logger ← Logger.create .DEBUG .text
  IO.mkRef logger

/-- Get the global logger -/
def getLogger : IO Logger := globalLoggerRef.get

/-- Set the global logger's level and format -/
def configureLogger (level : LogLevel) (format : LogFormat := .text) : IO Unit := do
  let logger ← Logger.create level format
  globalLoggerRef.set logger

/-- Quick global log function (uses global logger) -/
def glog (level : LogLevel) (component : String) (msg : String)
    (requestId : Option String := none) : IO Unit := do
  let logger ← getLogger
  logger.log level component msg requestId

end LeanServer
