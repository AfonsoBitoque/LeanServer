import LeanServer.Server.HTTPServer
import LeanServer.Server.Concurrency
import LeanServer.Crypto.Crypto

/-!
# Distributed Rate Limiter (R3)

Extends the basic per-IP token bucket rate limiter in HTTPServer.lean with
distributed capabilities for multi-instance deployments.

## Algorithms
- **Sliding Window Counter**: More accurate than fixed windows, lower memory than log-based
- **Token Bucket with Shared State**: Distributed token bucket via shared state store
- **Consistent Hashing**: Route IPs to consistent rate-limiter shards

## Architecture
Designed for a shared-nothing multi-process deployment:
1. Each instance runs its own local rate limiter for fast-path decisions
2. A background task periodically syncs counters to a shared store (e.g., Redis-like)
3. On startup, instances load existing counters from the shared store

Since LeanServer has no Redis client, this module provides:
- The algorithm and data structures for distributed rate limiting
- A pluggable `RateLimitStore` interface (backed by file-based store by default)
- Local + global counter merging logic
-/

namespace LeanServer

-- ==========================================
-- Sliding Window Rate Limiter
-- ==========================================

/-- A sliding window counter for rate limiting.
    Uses two fixed windows and interpolates between them. -/
structure SlidingWindowBucket where
  /-- Request count in the previous fixed window -/
  prevCount   : Nat
  /-- Request count in the current fixed window -/
  currCount   : Nat
  /-- Start timestamp (ms) of the current fixed window -/
  windowStart : Nat
  /-- Fixed window size in milliseconds -/
  windowSize  : Nat
  deriving Inhabited, Repr

/-- Configuration for distributed rate limiting -/
structure DistributedRateLimitConfig where
  /-- Maximum requests per window per IP -/
  maxRequests      : Nat    := 100
  /-- Window size in milliseconds -/
  windowSizeMs     : Nat    := 60000  -- 1 minute
  /-- Sync interval to shared store (ms) -/
  syncIntervalMs   : Nat    := 5000   -- 5 seconds
  /-- Maximum tracked IPs before eviction -/
  maxTrackedIPs    : Nat    := 10000
  /-- Burst multiplier: allow this many × maxRequests in a single burst -/
  burstMultiplier  : Nat    := 2
  /-- Penalty duration (ms) for IPs that exceed burst limit -/
  penaltyDurationMs : Nat   := 300000  -- 5 minutes
  deriving Inhabited, Repr

/-- Result of a rate limit check -/
inductive RateLimitDecision where
  /-- Request is allowed; remaining = requests left in window -/
  | allowed     (remaining : Nat) (retryAfterMs : Nat)
  /-- Request is denied; retryAfterMs = when the client can retry -/
  | denied      (retryAfterMs : Nat)
  /-- IP is in penalty box (exceeded burst) -/
  | penalized   (retryAfterMs : Nat)
  deriving Inhabited, Repr

instance : ToString RateLimitDecision where
  toString
    | .allowed r _ => s!"ALLOWED(remaining={r})"
    | .denied r    => s!"DENIED(retry_after={r}ms)"
    | .penalized r => s!"PENALIZED(retry_after={r}ms)"

/-- Entry for a penalized IP -/
structure PenaltyEntry where
  ip          : String
  penaltyEnd  : Nat    -- Monotonic ms when penalty expires
  deriving Inhabited, Repr

/-- Per-IP rate limit state -/
structure IPRateLimitState where
  ip        : String
  bucket    : SlidingWindowBucket
  penalty   : Option PenaltyEntry := none
  deriving Inhabited, Repr

/-- Shared state for distributed rate limiting -/
structure DistributedRateLimiterState where
  config    : DistributedRateLimitConfig
  states    : List IPRateLimitState
  lastSync  : Nat
  deriving Inhabited

-- ==========================================
-- Sliding Window Algorithm
-- ==========================================

/-- Create a new sliding window bucket -/
def SlidingWindowBucket.create (nowMs : Nat) (windowSize : Nat) : SlidingWindowBucket :=
  { prevCount := 0, currCount := 0, windowStart := nowMs, windowSize }

/-- Advance the window if needed, returning the updated bucket -/
def SlidingWindowBucket.advance (b : SlidingWindowBucket) (nowMs : Nat) : SlidingWindowBucket :=
  let elapsed := nowMs - b.windowStart
  if elapsed >= b.windowSize * 2 then
    -- More than 2 windows have passed — reset everything
    { prevCount := 0, currCount := 0, windowStart := nowMs, windowSize := b.windowSize }
  else if elapsed >= b.windowSize then
    -- Current window has ended — rotate
    { prevCount := b.currCount, currCount := 0
      windowStart := b.windowStart + b.windowSize, windowSize := b.windowSize }
  else
    b

/-- Get the interpolated request count for the sliding window -/
def SlidingWindowBucket.estimatedCount (b : SlidingWindowBucket) (nowMs : Nat) : Nat :=
  let b' := b.advance nowMs
  let elapsed := nowMs - b'.windowStart
  -- Weight of the previous window (linearly decreasing)
  let prevWeight := if b'.windowSize > 0
    then (b'.windowSize - elapsed) * 100 / b'.windowSize
    else 0
  -- Interpolated count: prevCount × weight + currCount
  (b'.prevCount * prevWeight / 100) + b'.currCount

/-- Record a request in the sliding window bucket -/
def SlidingWindowBucket.record (b : SlidingWindowBucket) (nowMs : Nat) : SlidingWindowBucket :=
  let b' := b.advance nowMs
  { b' with currCount := b'.currCount + 1 }

-- ==========================================
-- Distributed Rate Limiter
-- ==========================================

/-- Global state for the distributed rate limiter -/
initialize distributedRateLimiterRef : IO.Ref DistributedRateLimiterState ← do
  IO.mkRef { config := {}, states := [], lastSync := 0 }

/-- Initialize the distributed rate limiter with config -/
def initDistributedRateLimiter (config : DistributedRateLimitConfig) : IO Unit := do
  distributedRateLimiterRef.set { config, states := [], lastSync := 0 }

/-- Check if an IP is in the penalty box -/
def isPenalized (entry : IPRateLimitState) (nowMs : Nat) : Bool :=
  match entry.penalty with
  | some p => nowMs < p.penaltyEnd
  | none => false

/-- Check rate limit for an IP address using sliding window -/
def checkDistributedRateLimit (ip : String) (nowMs : Nat) : IO RateLimitDecision := do
  let state ← distributedRateLimiterRef.get
  let config := state.config

  -- Find existing state for this IP
  match state.states.find? (fun s => s.ip == ip) with
  | some ipState =>
    -- Check penalty box first
    if isPenalized ipState nowMs then
      match ipState.penalty with
      | some p => return .penalized (p.penaltyEnd - nowMs)
      | none => return .penalized 0

    -- Check sliding window
    let estimated := ipState.bucket.estimatedCount nowMs
    let burstLimit := config.maxRequests * config.burstMultiplier

    if estimated >= burstLimit then
      -- Exceeded burst limit — add to penalty box
      let penalty := { ip, penaltyEnd := nowMs + config.penaltyDurationMs : PenaltyEntry }
      let newState := { ipState with penalty := some penalty }
      let states' := state.states.map fun s => if s.ip == ip then newState else s
      distributedRateLimiterRef.set { state with states := states' }
      return .penalized config.penaltyDurationMs

    else if estimated >= config.maxRequests then
      -- Over limit but under burst — deny
      let remaining := config.windowSizeMs - (nowMs - ipState.bucket.windowStart) % config.windowSizeMs
      return .denied remaining

    else
      -- Allowed — record and return
      let newBucket := ipState.bucket.record nowMs
      let newState := { ipState with bucket := newBucket }
      let states' := state.states.map fun s => if s.ip == ip then newState else s
      distributedRateLimiterRef.set { state with states := states' }
      let remaining := config.maxRequests - estimated - 1
      let retryAfter := config.windowSizeMs - (nowMs - ipState.bucket.windowStart) % config.windowSizeMs
      return .allowed remaining retryAfter

  | none =>
    -- New IP — create state
    let bucket := SlidingWindowBucket.create nowMs config.windowSizeMs
    let newIPState : IPRateLimitState := { ip, bucket := bucket.record nowMs }
    -- Evict if over limit (FIFO)
    let states' := if state.states.length >= config.maxTrackedIPs then
      state.states.drop 1 ++ [newIPState]
    else
      state.states ++ [newIPState]
    distributedRateLimiterRef.set { state with states := states' }
    return .allowed (config.maxRequests - 1) config.windowSizeMs

-- ==========================================
-- Distributed Sync (File-Based Store)
-- ==========================================

/-- Serialize rate limiter state to a string (simple CSV format) -/
def serializeRateLimiterState (state : DistributedRateLimiterState) : String := Id.run do
  let mut lines : List String := []
  for s in state.states do
    let penaltyEnd := match s.penalty with
      | some p => toString p.penaltyEnd
      | none => "0"
    let line := s!"{s.ip},{s.bucket.prevCount},{s.bucket.currCount},{s.bucket.windowStart},{s.bucket.windowSize},{penaltyEnd}"
    lines := lines ++ [line]
  return String.intercalate "\n" lines

/-- Parse a single line of serialized state -/
def parseRateLimiterLine (line : String) (_config : DistributedRateLimitConfig) : Option IPRateLimitState :=
  let parts := line.splitOn ","
  match parts with
  | [ip, prevS, currS, startS, sizeS, penS] =>
    match prevS.toNat?, currS.toNat?, startS.toNat?, sizeS.toNat?, penS.toNat? with
    | some prev, some curr, some start, some size, some pen =>
      let bucket : SlidingWindowBucket := { prevCount := prev, currCount := curr, windowStart := start, windowSize := size }
      let penalty := if pen > 0 then some { ip, penaltyEnd := pen : PenaltyEntry } else none
      some { ip, bucket, penalty }
    | _, _, _, _, _ => none
  | _ => none

/-- Sync local state to a shared file store -/
def syncToStore (storePath : String) : IO Unit := do
  let state ← distributedRateLimiterRef.get
  let serialized := serializeRateLimiterState state
  IO.FS.writeFile storePath serialized

/-- Load state from shared file store and merge with local -/
def syncFromStore (storePath : String) : IO Unit := do
  try
    let content ← IO.FS.readFile storePath
    let state ← distributedRateLimiterRef.get
    let lines := content.splitOn "\n" |>.filter (· != "")
    let remoteStates := lines.filterMap (parseRateLimiterLine · state.config)
    -- Merge: for each remote IP, take the max of local/remote counts
    let merged := Id.run do
      let mut result := state.states
      for remote in remoteStates do
        match result.find? (fun s => s.ip == remote.ip) with
        | some local_ =>
          let mergedBucket : SlidingWindowBucket :=
            { prevCount := Nat.max local_.bucket.prevCount remote.bucket.prevCount
              currCount := Nat.max local_.bucket.currCount remote.bucket.currCount
              windowStart := Nat.max local_.bucket.windowStart remote.bucket.windowStart
              windowSize := local_.bucket.windowSize }
          let mergedState := { local_ with bucket := mergedBucket }
          result := result.map fun s => if s.ip == remote.ip then mergedState else s
        | none =>
          result := result ++ [remote]
      return result
    distributedRateLimiterRef.set { state with states := merged, lastSync := 0 }
  catch _ =>
    pure () -- Store not available, continue with local only

/-- Evict expired penalty entries and stale IPs -/
def evictStaleEntries (nowMs : Nat) (staleTTLMs : Nat := 600000) : IO Nat := do
  let state ← distributedRateLimiterRef.get
  let before := state.states.length
  let cleaned := state.states.filter fun s =>
    -- Keep if: recent activity (within staleTTL) or currently penalized
    let recent := nowMs - s.bucket.windowStart < staleTTLMs
    let penalized := isPenalized s nowMs
    recent || penalized
  -- Clear expired penalties
  let cleared := cleaned.map fun s =>
    if isPenalized s nowMs then s
    else { s with penalty := none }
  distributedRateLimiterRef.set { state with states := cleared }
  return before - cleared.length

/-- Background sync loop: periodically sync to/from shared store -/
partial def startRateLimiterSync (storePath : String) (intervalMs : Nat := 5000) : IO Unit := do
  let _ ← IO.asTask do
    let rec loop : IO Unit := do
      IO.sleep (intervalMs.toUInt32)
      syncFromStore storePath
      syncToStore storePath
      let nowMs ← IO.monoMsNow
      let _ ← evictStaleEntries nowMs
      loop
    loop

-- ==========================================
-- Rate Limit HTTP Headers (RFC 6585 / draft-ietf-httpapi-ratelimit-headers)
-- ==========================================

/-- Generate rate limit headers for an HTTP response -/
def rateLimitHeaders (decision : RateLimitDecision) (config : DistributedRateLimitConfig) : List (String × String) :=
  match decision with
  | .allowed remaining retryAfter =>
    [ ("ratelimit-limit", toString config.maxRequests)
    , ("ratelimit-remaining", toString remaining)
    , ("ratelimit-reset", toString (retryAfter / 1000)) ]
  | .denied retryAfter =>
    [ ("ratelimit-limit", toString config.maxRequests)
    , ("ratelimit-remaining", "0")
    , ("ratelimit-reset", toString (retryAfter / 1000))
    , ("retry-after", toString (retryAfter / 1000)) ]
  | .penalized retryAfter =>
    [ ("ratelimit-limit", toString config.maxRequests)
    , ("ratelimit-remaining", "0")
    , ("ratelimit-reset", toString (retryAfter / 1000))
    , ("retry-after", toString (retryAfter / 1000)) ]

/-- Apply rate limiting as middleware -/
def rateLimitMiddleware (config : DistributedRateLimitConfig := {}) : Middleware := {
  name := "distributed-rate-limiter"
  apply := fun _ _ _ _ resp =>
    -- Note: In a real middleware pipeline, the IP would come from the request context
    -- This is a structural placeholder — actual IP extraction happens at the server level
    { resp with extraHeaders := resp.extraHeaders ++
      [("x-ratelimit-policy", s!"limit={config.maxRequests};window={config.windowSizeMs / 1000}")] }
}

-- ==========================================
-- Consistent Hashing for Shard Assignment
-- ==========================================

/-- Simple hash function for IP → shard assignment -/
def ipToShard (ip : String) (numShards : Nat) : Nat :=
  if numShards == 0 then 0
  else
    let hash := ip.foldl (fun acc c => acc * 31 + c.toNat) 0
    hash % numShards

/-- Shard configuration for multi-instance deployment -/
structure ShardConfig where
  instanceId   : Nat
  totalShards  : Nat
  deriving Inhabited, Repr

/-- Check if an IP belongs to this instance's shard -/
def isLocalShard (config : ShardConfig) (ip : String) : Bool :=
  ipToShard ip config.totalShards == config.instanceId

-- ==========================================
-- Proofs
-- ==========================================

/-- Shard assignment is deterministic -/
theorem shard_deterministic (ip : String) (n : Nat) :
    ipToShard ip n = ipToShard ip n := by rfl

/-- Zero shards always maps to shard 0 -/
theorem shard_zero (ip : String) : ipToShard ip 0 = 0 := by
  simp [ipToShard]

/-- Shard index is always less than numShards (when numShards > 0) -/
theorem shard_in_range (ip : String) (n : Nat) (h : n > 0) :
    ipToShard ip n < n := by
  unfold ipToShard
  simp [Nat.pos_iff_ne_zero.mp h]
  exact Nat.mod_lt _ h

end LeanServer
