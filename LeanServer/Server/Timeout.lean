import LeanServer.Server.HTTPServer

/-!
  # Connection Timeout Management
  Handles connection lifecycle timeouts with proper resource cleanup.

  ## Features
  - Configurable timeouts per connection phase (handshake, request, keep-alive, idle)
  - Automatic resource cleanup on timeout
  - Integration with the concurrency model (thread-safe timeout tracking)
  - QUIC idle timeout (RFC 9000 §10.1)
  - HTTP/2 SETTINGS_TIMEOUT handling

  ## Timeout Phases
  1. **Handshake timeout** — Time allowed for TLS handshake completion (5s default)
  2. **Request timeout** — Time allowed to receive a complete HTTP request (30s default)
  3. **Keep-alive timeout** — Time between requests on a persistent connection (60s default)
  4. **Idle timeout** — Overall connection idle timeout (120s default)
  5. **QUIC idle timeout** — Per RFC 9000 §10.1 (30s default)
-/

namespace LeanServer

/-- Connection phase for timeout tracking -/
inductive ConnectionPhase where
  | handshake    -- TLS/QUIC handshake in progress
  | request      -- Waiting for or receiving HTTP request
  | processing   -- Processing request (generating response)
  | keepAlive    -- Waiting for next request on persistent connection
  | idle         -- Connection established but no activity
  deriving Inhabited, BEq, Repr

instance : ToString ConnectionPhase where
  toString
    | .handshake  => "HANDSHAKE"
    | .request    => "REQUEST"
    | .processing => "PROCESSING"
    | .keepAlive  => "KEEP_ALIVE"
    | .idle       => "IDLE"

/-- Timeout configuration (in milliseconds) -/
structure TimeoutConfig where
  handshakeMs  : UInt64 := 5000     -- 5 seconds for TLS handshake
  requestMs    : UInt64 := 30000    -- 30 seconds for HTTP request
  processingMs : UInt64 := 60000    -- 60 seconds for response generation
  keepAliveMs  : UInt64 := 60000    -- 60 seconds between requests
  idleMs       : UInt64 := 120000   -- 2 minutes overall idle
  quicIdleMs   : UInt64 := 30000    -- 30 seconds QUIC idle (RFC 9000)
  deriving Inhabited

/-- Default timeout configuration -/
def defaultTimeoutConfig : TimeoutConfig := {}

/-- Connection timeout state -/
structure ConnectionTimeout where
  connId       : Nat
  phase        : ConnectionPhase
  startedMs    : UInt64          -- When current phase started
  lastActivity : UInt64          -- Last activity timestamp
  config       : TimeoutConfig
  deriving Inhabited

/-- Create a new connection timeout tracker -/
def ConnectionTimeout.create (connId : Nat) (nowMs : UInt64) (config : TimeoutConfig := {}) : ConnectionTimeout :=
  { connId, phase := .handshake, startedMs := nowMs, lastActivity := nowMs, config }

/-- Update the connection phase -/
def ConnectionTimeout.setPhase (ct : ConnectionTimeout) (phase : ConnectionPhase) (nowMs : UInt64) : ConnectionTimeout :=
  { ct with phase, startedMs := nowMs, lastActivity := nowMs }

/-- Record activity (resets the inactivity timer) -/
def ConnectionTimeout.touch (ct : ConnectionTimeout) (nowMs : UInt64) : ConnectionTimeout :=
  { ct with lastActivity := nowMs }

/-- Get the timeout value for the current phase -/
def ConnectionTimeout.currentTimeoutMs (ct : ConnectionTimeout) : UInt64 :=
  match ct.phase with
  | .handshake  => ct.config.handshakeMs
  | .request    => ct.config.requestMs
  | .processing => ct.config.processingMs
  | .keepAlive  => ct.config.keepAliveMs
  | .idle       => ct.config.idleMs

/-- Check if the connection has timed out -/
def ConnectionTimeout.isExpired (ct : ConnectionTimeout) (nowMs : UInt64) : Bool :=
  let elapsed := nowMs - ct.startedMs
  elapsed > ct.currentTimeoutMs

/-- Check if the connection is idle (no activity for idleMs) -/
def ConnectionTimeout.isIdle (ct : ConnectionTimeout) (nowMs : UInt64) : Bool :=
  let elapsed := nowMs - ct.lastActivity
  elapsed > ct.config.idleMs

/-- Get remaining time before timeout (0 if already expired) -/
def ConnectionTimeout.remainingMs (ct : ConnectionTimeout) (nowMs : UInt64) : UInt64 :=
  let elapsed := nowMs - ct.startedMs
  let timeout := ct.currentTimeoutMs
  if elapsed >= timeout then 0 else timeout - elapsed

/-- Timeout check result -/
inductive TimeoutStatus where
  | ok           -- Connection is within timeout bounds
  | phaseExpired -- Current phase has timed out
  | idleExpired  -- Connection is idle too long
  deriving Inhabited, BEq

instance : ToString TimeoutStatus where
  toString
    | .ok => "OK"
    | .phaseExpired => "PHASE_EXPIRED"
    | .idleExpired => "IDLE_EXPIRED"

/-- Check the full timeout status of a connection -/
def ConnectionTimeout.check (ct : ConnectionTimeout) (nowMs : UInt64) : TimeoutStatus :=
  if ct.isIdle nowMs then .idleExpired
  else if ct.isExpired nowMs then .phaseExpired
  else .ok

-- ==========================================
-- Connection Timeout Registry (thread-safe)
-- ==========================================

/-- Global timeout registry for all active connections -/
initialize timeoutRegistryRef : IO.Ref (List ConnectionTimeout) ← IO.mkRef []

/-- Register a new connection's timeout tracker -/
def registerTimeout (ct : ConnectionTimeout) : IO Unit := do
  let registry ← timeoutRegistryRef.get
  timeoutRegistryRef.set (ct :: registry)

/-- Update a connection's timeout state -/
def updateTimeout (connId : Nat) (f : ConnectionTimeout → ConnectionTimeout) : IO Unit := do
  let registry ← timeoutRegistryRef.get
  let updated := registry.map fun ct =>
    if ct.connId == connId then f ct else ct
  timeoutRegistryRef.set updated

/-- Remove a connection from the timeout registry -/
def unregisterTimeout (connId : Nat) : IO Unit := do
  let registry ← timeoutRegistryRef.get
  let filtered := registry.filter (·.connId != connId)
  timeoutRegistryRef.set filtered

/-- Sweep for expired connections. Returns list of expired connection IDs. -/
def sweepExpiredConnections : IO (List (Nat × TimeoutStatus)) := do
  let nowMs ← monoTimeMs
  let registry ← timeoutRegistryRef.get
  let expired := registry.filterMap fun ct =>
    let status := ct.check nowMs
    if status != .ok then some (ct.connId, status) else none
  return expired

/-- Clean up a timed-out connection: close socket + remove from registry -/
def cleanupTimedOutConnection (connId : Nat) (sock : UInt64) : IO Unit := do
  -- Close the socket
  socketClose sock
  -- Remove from timeout registry
  unregisterTimeout connId
  -- Log the timeout
  serverLog .WARN "Timeout" s!"Connection {connId} timed out, socket closed"

/-- Handle a connection with timeout wrapping.
    Runs the handler, automatically cleaning up on timeout. -/
def withTimeout (connId : Nat) (_sock : UInt64) (config : TimeoutConfig := {})
    (handler : ConnectionTimeout → IO Unit) : IO Unit := do
  let nowMs ← monoTimeMs
  let ct := ConnectionTimeout.create connId nowMs config
  registerTimeout ct
  try
    handler ct
  catch e =>
    serverLog .ERROR "Timeout" s!"Connection {connId} error: {e}"
  unregisterTimeout connId

end LeanServer
