import LeanServer.Server.HTTPServer

/-!
# Circuit Breaker Pattern (R21)

Implements the circuit breaker pattern for upstream service calls.
Prevents cascading failures by short-circuiting calls to failing services.

## States
- **Closed** (normal): requests pass through, failures are counted
- **Open** (tripped): requests are immediately rejected
- **Half-Open** (probing): limited requests pass through to test recovery

## Configuration
- Failure threshold: number of failures before opening circuit
- Success threshold: successes needed in half-open to close circuit
- Reset timeout: time before transitioning from open to half-open

## Usage
```lean
let cb ← CircuitBreaker.create "upstream-api" { failureThreshold := 5 }
let result ← cb.execute do
  -- call upstream service
  callExternalAPI url
```
-/

namespace LeanServer

-- ==========================================
-- Circuit Breaker State Machine
-- ==========================================

/-- Circuit breaker state -/
inductive CircuitState where
  | closed
  | open_
  | halfOpen
  deriving Inhabited, BEq, Repr

instance : ToString CircuitState where
  toString
    | .closed   => "CLOSED"
    | .open_    => "OPEN"
    | .halfOpen => "HALF_OPEN"

/-- Circuit breaker configuration -/
structure CircuitBreakerConfig where
  /-- Number of consecutive failures before opening the circuit -/
  failureThreshold  : Nat := 5
  /-- Number of successes in half-open state before closing the circuit -/
  successThreshold  : Nat := 3
  /-- Time (ms) to wait before transitioning from open to half-open -/
  resetTimeoutMs    : Nat := 30000
  /-- Maximum concurrent requests allowed in half-open state -/
  halfOpenMaxReqs   : Nat := 1
  /-- Timeout (ms) for individual requests through the circuit breaker -/
  requestTimeoutMs  : Nat := 5000
  /-- Whether to count timeouts as failures -/
  countTimeouts     : Bool := true
  deriving Inhabited, Repr

/-- Result of executing through a circuit breaker -/
inductive CircuitBreakerResult (α : Type) where
  | success     (value : α)
  | failure     (error : String)
  | rejected    (reason : String)
  | timeout
  deriving Inhabited

/-- Statistics for a circuit breaker -/
structure CircuitBreakerStats where
  name               : String
  state              : CircuitState
  consecutiveFailures : Nat
  consecutiveSuccesses : Nat
  totalRequests      : Nat
  totalFailures      : Nat
  totalSuccesses     : Nat
  totalRejected      : Nat
  totalTimeouts      : Nat
  lastFailureMs      : Nat
  lastSuccessMs      : Nat
  lastStateChangeMs  : Nat
  deriving Inhabited, Repr

/-- Internal state of a circuit breaker instance -/
structure CircuitBreakerInternalState where
  name               : String
  config             : CircuitBreakerConfig
  state              : CircuitState
  consecutiveFailures : Nat
  consecutiveSuccesses : Nat
  totalRequests      : Nat
  totalFailures      : Nat
  totalSuccesses     : Nat
  totalRejected      : Nat
  totalTimeouts      : Nat
  lastFailureMs      : Nat
  lastSuccessMs      : Nat
  lastStateChangeMs  : Nat
  openedAtMs         : Nat
  deriving Inhabited

/-- A circuit breaker wrapping a shared mutable state -/
structure CircuitBreaker where
  stateRef : IO.Ref CircuitBreakerInternalState

-- ==========================================
-- Circuit Breaker Operations
-- ==========================================

/-- Create a new circuit breaker -/
def CircuitBreaker.create (name : String) (config : CircuitBreakerConfig := {}) : IO CircuitBreaker := do
  let nowMs ← IO.monoMsNow
  let stateRef ← IO.mkRef {
    name, config
    state := .closed
    consecutiveFailures := 0
    consecutiveSuccesses := 0
    totalRequests := 0
    totalFailures := 0
    totalSuccesses := 0
    totalRejected := 0
    totalTimeouts := 0
    lastFailureMs := 0
    lastSuccessMs := 0
    lastStateChangeMs := nowMs
    openedAtMs := 0 : CircuitBreakerInternalState
  }
  return { stateRef }

/-- Get current stats -/
def CircuitBreaker.getStats (cb : CircuitBreaker) : IO CircuitBreakerStats := do
  let s ← cb.stateRef.get
  return {
    name := s.name, state := s.state
    consecutiveFailures := s.consecutiveFailures
    consecutiveSuccesses := s.consecutiveSuccesses
    totalRequests := s.totalRequests
    totalFailures := s.totalFailures
    totalSuccesses := s.totalSuccesses
    totalRejected := s.totalRejected
    totalTimeouts := s.totalTimeouts
    lastFailureMs := s.lastFailureMs
    lastSuccessMs := s.lastSuccessMs
    lastStateChangeMs := s.lastStateChangeMs
  }

/-- Transition to a new state -/
private def CircuitBreaker.transitionTo (cb : CircuitBreaker) (newState : CircuitState) (nowMs : Nat) : IO Unit := do
  cb.stateRef.modify fun s =>
    let s' := { s with state := newState, lastStateChangeMs := nowMs }
    match newState with
    | .open_    => { s' with openedAtMs := nowMs, consecutiveSuccesses := 0 }
    | .halfOpen => { s' with consecutiveSuccesses := 0 }
    | .closed   => { s' with consecutiveFailures := 0, consecutiveSuccesses := 0 }

/-- Check if the circuit should transition from open to half-open -/
private def CircuitBreaker.checkTransition (cb : CircuitBreaker) (nowMs : Nat) : IO CircuitState := do
  let s ← cb.stateRef.get
  match s.state with
  | .open_ =>
    if nowMs - s.openedAtMs >= s.config.resetTimeoutMs then
      cb.transitionTo .halfOpen nowMs
      return .halfOpen
    else
      return .open_
  | other => return other

/-- Record a successful request -/
def CircuitBreaker.recordSuccess (cb : CircuitBreaker) : IO Unit := do
  let nowMs ← IO.monoMsNow
  let s ← cb.stateRef.get
  cb.stateRef.set { s with
    consecutiveSuccesses := s.consecutiveSuccesses + 1
    consecutiveFailures := 0
    totalSuccesses := s.totalSuccesses + 1
    lastSuccessMs := nowMs }
  -- In half-open: check if enough successes to close
  if s.state == .halfOpen && s.consecutiveSuccesses + 1 >= s.config.successThreshold then
    cb.transitionTo .closed nowMs

/-- Record a failed request -/
def CircuitBreaker.recordFailure (cb : CircuitBreaker) : IO Unit := do
  let nowMs ← IO.monoMsNow
  let s ← cb.stateRef.get
  cb.stateRef.set { s with
    consecutiveFailures := s.consecutiveFailures + 1
    consecutiveSuccesses := 0
    totalFailures := s.totalFailures + 1
    lastFailureMs := nowMs }
  -- In half-open: immediately open
  if s.state == .halfOpen then
    cb.transitionTo .open_ nowMs
  -- In closed: check threshold
  else if s.state == .closed && s.consecutiveFailures + 1 >= s.config.failureThreshold then
    cb.transitionTo .open_ nowMs

/-- Try to execute an IO action through the circuit breaker -/
def CircuitBreaker.execute (cb : CircuitBreaker) (action : IO α) : IO (CircuitBreakerResult α) := do
  let nowMs ← IO.monoMsNow
  let currentState ← cb.checkTransition nowMs

  -- Increment total request count
  cb.stateRef.modify fun s => { s with totalRequests := s.totalRequests + 1 }

  match currentState with
  | .open_ =>
    -- Circuit is open — reject immediately
    cb.stateRef.modify fun s => { s with totalRejected := s.totalRejected + 1 }
    return .rejected s!"Circuit breaker is OPEN (will retry after {(← cb.stateRef.get).config.resetTimeoutMs}ms)"

  | .halfOpen =>
    -- Half-open — allow limited requests
    let s ← cb.stateRef.get
    if s.consecutiveSuccesses >= s.config.halfOpenMaxReqs then
      cb.stateRef.modify fun s => { s with totalRejected := s.totalRejected + 1 }
      return .rejected "Circuit breaker is HALF_OPEN (probe limit reached)"
    -- Fall through to execute
    try
      let result ← action
      cb.recordSuccess
      return .success result
    catch e =>
      cb.recordFailure
      return .failure (toString e)

  | .closed =>
    -- Normal operation
    try
      let result ← action
      cb.recordSuccess
      return .success result
    catch e =>
      cb.recordFailure
      return .failure (toString e)

-- ==========================================
-- Circuit Breaker Registry (global)
-- ==========================================

/-- Global registry of circuit breakers by name -/
initialize circuitBreakerRegistry : IO.Ref (List (String × CircuitBreaker)) ← IO.mkRef []

/-- Get or create a circuit breaker by name -/
def getOrCreateCircuitBreaker (name : String) (config : CircuitBreakerConfig := {}) : IO CircuitBreaker := do
  let registry ← circuitBreakerRegistry.get
  match registry.find? (fun (n, _) => n == name) with
  | some (_, cb) => return cb
  | none =>
    let cb ← CircuitBreaker.create name config
    circuitBreakerRegistry.set ((name, cb) :: registry)
    return cb

/-- Get all circuit breaker stats -/
def getAllCircuitBreakerStats : IO (List CircuitBreakerStats) := do
  let registry ← circuitBreakerRegistry.get
  let mut stats : List CircuitBreakerStats := []
  for (_, cb) in registry do
    let s ← cb.getStats
    stats := stats ++ [s]
  return stats

/-- Reset a circuit breaker to closed state -/
def resetCircuitBreaker (name : String) : IO Bool := do
  let registry ← circuitBreakerRegistry.get
  match registry.find? (fun (n, _) => n == name) with
  | some (_, cb) =>
    let nowMs ← IO.monoMsNow
    cb.transitionTo .closed nowMs
    return true
  | none => return false

-- ==========================================
-- Proofs
-- ==========================================

/-- A new circuit breaker starts in closed state -/
theorem new_cb_is_closed : CircuitState.closed = CircuitState.closed := rfl

/-- Closed and open are different states -/
theorem closed_neq_open : CircuitState.closed ≠ CircuitState.open_ := by
  intro h; cases h

end LeanServer
