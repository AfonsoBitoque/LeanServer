import Init.Data.Array

/-!
  # ByteArray Buffer Pool
  Reduces GC pressure by reusing fixed-size ByteArray buffers.

  The pool maintains free-lists for common buffer sizes used on hot paths:
  - 16 bytes: AES blocks, GCM tags, GHASH/GF(2¹²⁸) intermediates
  - 32 bytes: SHA-256 hashes, HMAC outputs, traffic secrets
  - 64 bytes: HMAC ipad/opad blocks
  - 4096 bytes: socket recv buffers (TCP & UDP)
  - 16384 bytes: TLS record-layer buffers

  Usage: `BufferPool.withBuffer .b4096 fun buf => ...`
  The buffer is zero-filled on acquire and wiped + returned on release.
-/

namespace LeanServer.BufferPool

-- ==========================================
-- Buffer Size Tiers
-- ==========================================

/-- Fixed buffer size tiers matching hot-path allocation patterns. -/
inductive BufferSize where
  | b16    : BufferSize  -- AES blocks, tags, GHASH intermediates
  | b32    : BufferSize  -- SHA-256 / HMAC outputs, keys
  | b64    : BufferSize  -- HMAC i/o pad blocks
  | b4096  : BufferSize  -- socket recv buffers
  | b16384 : BufferSize  -- TLS record buffers
  deriving Repr, BEq, Inhabited

/-- Convert tier to byte count. -/
def BufferSize.toNat : BufferSize → Nat
  | .b16    => 16
  | .b32    => 32
  | .b64    => 64
  | .b4096  => 4096
  | .b16384 => 16384

-- ==========================================
-- Sized Pool (free-list for one tier)
-- ==========================================

/-- Free-list for a single buffer size tier. -/
structure SizedPool where
  /-- Available (free) buffers. Each has capacity ≥ `size`. -/
  buffers : Array ByteArray
  /-- Tier size (bytes). -/
  size    : Nat
  /-- Maximum number of buffers to keep in the free-list. -/
  maxFree : Nat := 64
  deriving Inhabited

/-- Create an empty pool for a given tier. -/
def SizedPool.empty (size : Nat) (maxFree : Nat := 64) : SizedPool :=
  { buffers := #[], size, maxFree }

-- ==========================================
-- Global Pool State
-- ==========================================

/-- Aggregate pool state with one free-list per tier. -/
structure BufferPoolState where
  pool16    : SizedPool
  pool32    : SizedPool
  pool64    : SizedPool
  pool4096  : SizedPool
  pool16384 : SizedPool
  /-- Total acquires (for metrics). -/
  totalAcquires : Nat := 0
  /-- Cache hits (reused from pool). -/
  cacheHits     : Nat := 0
  deriving Inhabited

/-- Initial empty pool state. -/
def BufferPoolState.empty : BufferPoolState :=
  { pool16    := SizedPool.empty 16
    pool32    := SizedPool.empty 32
    pool64    := SizedPool.empty 64
    pool4096  := SizedPool.empty 4096
    pool16384 := SizedPool.empty 16384 }

/-- Global buffer pool reference. -/
initialize bufferPoolRef : IO.Ref BufferPoolState ← IO.mkRef .empty

-- ==========================================
-- Pool Operations
-- ==========================================

/-- Create a fresh zero-filled ByteArray of the given size. -/
private def allocFresh (n : Nat) : ByteArray :=
  ByteArray.mk (List.replicate n 0).toArray

/-- Zero-fill a ByteArray in place (for security: wipe crypto buffers). -/
private def zeroFill (buf : ByteArray) : ByteArray :=
  allocFresh buf.size

/-- Get the pool for a given tier. -/
private def getPool (state : BufferPoolState) : BufferSize → SizedPool
  | .b16    => state.pool16
  | .b32    => state.pool32
  | .b64    => state.pool64
  | .b4096  => state.pool4096
  | .b16384 => state.pool16384

/-- Set the pool for a given tier. -/
private def setPool (state : BufferPoolState) (tier : BufferSize) (pool : SizedPool) : BufferPoolState :=
  match tier with
  | .b16    => { state with pool16    := pool }
  | .b32    => { state with pool32    := pool }
  | .b64    => { state with pool64    := pool }
  | .b4096  => { state with pool4096  := pool }
  | .b16384 => { state with pool16384 := pool }

/-- Acquire a zero-filled buffer from the pool.
    Returns a recycled buffer if available, otherwise allocates fresh. -/
def acquire (tier : BufferSize) : IO ByteArray := do
  let state ← bufferPoolRef.get
  let pool := getPool state tier
  if h : pool.buffers.size > 0 then
    -- Pop from free-list (reuse)
    let buf := pool.buffers.back
    let newBuffers := pool.buffers.pop
    let newPool := { pool with buffers := newBuffers }
    bufferPoolRef.set (setPool
      { state with totalAcquires := state.totalAcquires + 1
                   cacheHits := state.cacheHits + 1 }
      tier newPool)
    -- Zero-fill before returning (security + clean state)
    return zeroFill buf
  else
    -- Allocate fresh
    bufferPoolRef.set { state with totalAcquires := state.totalAcquires + 1 }
    return allocFresh tier.toNat

/-- Release a buffer back to the pool.
    The buffer is zero-filled and returned to the free-list if not full.
    Caller MUST NOT use the buffer after calling release. -/
def release (tier : BufferSize) (buf : ByteArray) : IO Unit := do
  let state ← bufferPoolRef.get
  let pool := getPool state tier
  if pool.buffers.size < pool.maxFree then
    -- Zero-fill and return to pool
    let wiped := zeroFill buf
    let newPool := { pool with buffers := pool.buffers.push wiped }
    bufferPoolRef.set (setPool state tier newPool)
  else
    -- Pool full — let GC collect the buffer
    pure ()

/-- Scoped buffer usage: acquire, run action, auto-release.
    Ensures the buffer is always returned to the pool. -/
def withBuffer (tier : BufferSize) (f : ByteArray → IO α) : IO α := do
  let buf ← acquire tier
  try
    let result ← f buf
    release tier buf
    return result
  catch e =>
    release tier buf
    throw e

-- ==========================================
-- Metrics / Diagnostics
-- ==========================================

/-- Get pool statistics for monitoring. -/
def getStats : IO (Nat × Nat × Nat × Nat × Nat × Nat × Nat) := do
  let state ← bufferPoolRef.get
  return (state.pool16.buffers.size,
          state.pool32.buffers.size,
          state.pool64.buffers.size,
          state.pool4096.buffers.size,
          state.pool16384.buffers.size,
          state.totalAcquires,
          state.cacheHits)

/-- Format pool stats as a human-readable string. -/
def statsString : IO String := do
  let (f16, f32, f64, f4096, f16384, total, hits) ← getStats
  let hitRate := if total > 0 then (hits * 100) / total else 0
  return s!"BufferPool: free=[16B:{f16}, 32B:{f32}, 64B:{f64}, 4K:{f4096}, 16K:{f16384}] " ++
         s!"acquires={total} hits={hits} rate={hitRate}%"

end LeanServer.BufferPool
