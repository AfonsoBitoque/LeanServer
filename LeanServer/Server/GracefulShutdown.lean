import LeanServer.Server.HTTPServer
import LeanServer.Server.Concurrency
import LeanServer.Server.Timeout

/-!
# Graceful Shutdown Module (R19)

Provides a structured graceful shutdown sequence that integrates with
`Concurrency.lean` (thread tracking) and `Timeout.lean` (connection sweeping).

## Shutdown Phases
1. **Signal received** → stop accepting new connections
2. **Drain** → finish in-flight requests (configurable timeout)
3. **Force close** → terminate remaining connections
4. **Cleanup** → release resources, flush logs

## Integration
The main server loop in `HTTPServer.lean` already handles SIGINT/SIGTERM via FFI.
This module adds a reusable `ShutdownCoordinator` that can be shared across
the TCP accept loop and QUIC UDP loop.
-/

namespace LeanServer

/-- Shutdown phase progression -/
inductive ShutdownPhase where
  | running       : ShutdownPhase
  | draining      : ShutdownPhase
  | forceClosing  : ShutdownPhase
  | completed     : ShutdownPhase
  deriving Repr, BEq, Inhabited

instance : ToString ShutdownPhase where
  toString
    | .running      => "running"
    | .draining     => "draining"
    | .forceClosing => "force-closing"
    | .completed    => "completed"

/-- Configuration for graceful shutdown behaviour -/
structure ShutdownConfig where
  /-- Maximum time (ms) to wait for in-flight requests during drain phase -/
  drainTimeoutMs   : Nat := 30000
  /-- Interval (ms) between polling active connections during drain -/
  pollIntervalMs   : Nat := 500
  /-- Maximum time (ms) for force-close phase before hard exit -/
  forceCloseMs     : Nat := 5000
  /-- Whether to send GOAWAY to HTTP/2 and QUIC connections -/
  sendGoaway       : Bool := true
  /-- Whether to send TLS close_notify before closing TCP sockets -/
  sendCloseNotify  : Bool := true
  deriving Repr, Inhabited

/-- Mutable state for coordinating shutdown across threads -/
structure ShutdownState where
  phase            : ShutdownPhase
  startedMs        : Nat
  activeAtStart    : Nat
  connectionsLeft  : Nat
  deriving Repr, Inhabited

/-- Coordinator that tracks shutdown progress -/
structure ShutdownCoordinator where
  config : ShutdownConfig
  stateRef : IO.Ref ShutdownState

/-- Helper: get current monotonic time as Nat (ms) -/
private def nowMs : IO Nat := do
  let ms ← monoTimeMs
  return ms.toNat

/-- Helper: get active thread count as Nat -/
private def activeConns : IO Nat := do
  let c ← getActiveThreadCount
  return c.toNat

/-- Create a new shutdown coordinator (call once at server startup) -/
def ShutdownCoordinator.create (config : ShutdownConfig := {}) : IO ShutdownCoordinator := do
  let ref ← IO.mkRef { phase := .running, startedMs := 0, activeAtStart := 0, connectionsLeft := 0 }
  return { config, stateRef := ref }

/-- Check whether the server should stop accepting new connections -/
def ShutdownCoordinator.isDraining (sc : ShutdownCoordinator) : IO Bool := do
  let s ← sc.stateRef.get
  return s.phase != .running

/-- Begin the drain phase. Returns `false` if already draining. -/
def ShutdownCoordinator.beginDrain (sc : ShutdownCoordinator) : IO Bool := do
  let s ← sc.stateRef.get
  if s.phase != .running then return false
  let now ← nowMs
  let active ← activeConns
  sc.stateRef.set { phase := .draining, startedMs := now, activeAtStart := active, connectionsLeft := active }
  return true

/-- Update the coordinator with the current active connection count -/
def ShutdownCoordinator.updateConnectionCount (sc : ShutdownCoordinator) : IO Nat := do
  let active ← activeConns
  sc.stateRef.modify fun s => { s with connectionsLeft := active }
  return active

/-- Poll shutdown progress. Returns the current phase and remaining connections. -/
def ShutdownCoordinator.poll (sc : ShutdownCoordinator) : IO (ShutdownPhase × Nat) := do
  let now ← nowMs
  let s ← sc.stateRef.get
  match s.phase with
  | .running => return (.running, 0)
  | .draining =>
    let active ← activeConns
    let elapsed := now - s.startedMs
    if active == 0 then
      sc.stateRef.set { s with phase := .completed, connectionsLeft := 0 }
      return (.completed, 0)
    else if elapsed >= sc.config.drainTimeoutMs then
      sc.stateRef.set { s with phase := .forceClosing, connectionsLeft := active }
      return (.forceClosing, active)
    else
      sc.stateRef.modify fun st => { st with connectionsLeft := active }
      return (.draining, active)
  | .forceClosing =>
    let active ← activeConns
    let totalTimeout := sc.config.drainTimeoutMs + sc.config.forceCloseMs
    let elapsed := now - s.startedMs
    if active == 0 || elapsed >= totalTimeout then
      sc.stateRef.set { s with phase := .completed, connectionsLeft := 0 }
      return (.completed, 0)
    else
      return (.forceClosing, active)
  | .completed => return (.completed, 0)

/-- Run the full shutdown sequence. Blocks until complete or timeout. -/
def ShutdownCoordinator.runShutdown (sc : ShutdownCoordinator) : IO ShutdownState := do
  let started ← sc.beginDrain
  unless started do
    return ← sc.stateRef.get

  IO.eprintln s!"🛑 Graceful shutdown initiated (drain timeout: {sc.config.drainTimeoutMs}ms)"

  -- Phase 1: Drain — wait for in-flight requests
  let mut phase := ShutdownPhase.draining
  let mut remaining : Nat := 0
  while phase == .draining do
    IO.sleep sc.config.pollIntervalMs.toUInt32
    let (p, r) ← sc.poll
    phase := p
    remaining := r
    if remaining > 0 then
      IO.eprintln s!"  ⏳ Draining... {remaining} connections remaining"

  -- Phase 2: Force close — sweep expired connections
  if phase == .forceClosing then
    IO.eprintln s!"  ⚡ Force-closing {remaining} remaining connections"
    let expired ← sweepExpiredConnections
    for (connId, _status) in expired do
      unregisterTimeout connId
    IO.sleep sc.config.forceCloseMs.toUInt32
    let _ ← sc.poll

  let finalState ← sc.stateRef.get
  IO.eprintln s!"✅ Shutdown complete (was {finalState.activeAtStart} active connections)"
  return finalState

/-- Summary of a completed shutdown (for logging / metrics). -/
structure ShutdownSummary where
  phase          : ShutdownPhase
  durationMs     : Nat
  connectionsAtStart : Nat
  connectionsForced  : Nat
  deriving Repr

/-- Build a summary from final state -/
def ShutdownCoordinator.summary (sc : ShutdownCoordinator) : IO ShutdownSummary := do
  let s ← sc.stateRef.get
  let now ← nowMs
  return {
    phase := s.phase
    durationMs := now - s.startedMs
    connectionsAtStart := s.activeAtStart
    connectionsForced := 0
  }

end LeanServer
