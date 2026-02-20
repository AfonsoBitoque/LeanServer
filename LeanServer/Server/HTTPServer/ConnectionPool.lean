import LeanServer.Server.HTTPServer

/-!
  # Connection Pool — Re-export Module
  TCP connection pool for connection reuse and management.

  ## Key Types
  - `TCPPoolEntry` — Individual pool entry
  - `TCPConnectionPool` — Pool state

  ## Key Functions
  - `poolAdmit` — Add a connection to the pool
  - `poolRelease` — Release a connection from the pool
  - `getPoolStats` — Get pool statistics (total, active, idle)
  - `incrementConnections` / `decrementConnections` — Connection counter
-/

namespace LeanServer.ConnPool

/-- Admit a connection to the pool -/
@[inline] def admit (sock : UInt64) (connId : Nat) : IO Bool :=
  LeanServer.poolAdmit sock connId

/-- Release a connection from the pool -/
@[inline] def release (connId : Nat) : IO Unit :=
  LeanServer.poolRelease connId

/-- Get pool stats: (total, active, idle) -/
@[inline] def stats : IO (Nat × Nat × Nat) :=
  LeanServer.getPoolStats

/-- Increment the active connection count -/
@[inline] def incr : IO Nat :=
  LeanServer.incrementConnections

/-- Decrement the active connection count -/
@[inline] def decr : IO Nat :=
  LeanServer.decrementConnections

end LeanServer.ConnPool
