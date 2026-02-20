-- Load Balancing Implementation
-- Multiple algorithms: Round Robin, Least Connections, IP Hash, Weighted Round Robin

import LeanServer.Core.Basic
import LeanServer.Protocol.HTTP2

namespace LeanServer

-- Backend Server representation
structure BackendServer where
  host : String
  port : UInt16
  weight : UInt32
  connections : UInt32
  healthy : Bool

instance : Inhabited BackendServer where
  default := {
    host := "localhost"
    port := 8080
    weight := 1
    connections := 0
    healthy := true
  }

instance : ToString BackendServer where
  toString s := s!"{s.host}:{s.port} (weight: {s.weight}, connections: {s.connections}, healthy: {s.healthy})"

-- Load Balancing Algorithms
inductive LoadBalancingAlgorithm where
  | ROUND_ROBIN : LoadBalancingAlgorithm
  | LEAST_CONNECTIONS : LoadBalancingAlgorithm
  | IP_HASH : LoadBalancingAlgorithm
  | WEIGHTED_ROUND_ROBIN : LoadBalancingAlgorithm

instance : ToString LoadBalancingAlgorithm where
  toString := fun
    | .ROUND_ROBIN => "Round Robin"
    | .LEAST_CONNECTIONS => "Least Connections"
    | .IP_HASH => "IP Hash"
    | .WEIGHTED_ROUND_ROBIN => "Weighted Round Robin"

-- Load Balancer State
structure LoadBalancerState where
  algorithm : LoadBalancingAlgorithm
  backends : Array BackendServer
  currentIndex : UInt32
  ipHashMap : Array (String × UInt32)

instance : Inhabited LoadBalancerState where
  default := {
    algorithm := .ROUND_ROBIN
    backends := #[]
    currentIndex := 0
    ipHashMap := #[]
  }

-- Create load balancer with algorithm
def createLoadBalancer (algorithm : LoadBalancingAlgorithm) : LoadBalancerState := {
  algorithm := algorithm
  backends := #[]
  currentIndex := 0
  ipHashMap := #[]
}

-- Add backend server to load balancer
def addBackend (lb : LoadBalancerState) (backend : BackendServer) : LoadBalancerState := {
  lb with backends := lb.backends.push backend
}

-- Get healthy backends
def getHealthyBackends (lb : LoadBalancerState) : Array BackendServer :=
  lb.backends.filter (fun b => b.healthy)

-- Round Robin Algorithm
def selectBackendRoundRobin (lb : LoadBalancerState) : Option (BackendServer × LoadBalancerState) :=
  let healthyBackends := getHealthyBackends lb
  if healthyBackends.size == 0 then
    none
  else
    let index := lb.currentIndex.toNat % healthyBackends.size
    let selected := healthyBackends[index]!
    let nextIndex := if lb.currentIndex.toNat + 1 >= healthyBackends.size then 0 else lb.currentIndex + 1
    some (selected, { lb with currentIndex := nextIndex })

-- Least Connections Algorithm
def selectBackendLeastConnections (lb : LoadBalancerState) : Option (BackendServer × LoadBalancerState) :=
  let healthyBackends := getHealthyBackends lb
  if healthyBackends.size == 0 then
    none
  else
    -- Find backend with minimum connections using fold
    let result := healthyBackends.foldl (fun (acc : BackendServer × Nat) b =>
      let (minBackend, minIndex) := acc
      if b.connections < minBackend.connections then (b, minIndex + 1) else acc
    ) (healthyBackends[0]!, 0)
    some (result.1, lb)

-- IP Hash Algorithm
def selectBackendIPHash (lb : LoadBalancerState) (clientIP : String) : Option (BackendServer × LoadBalancerState) :=
  let healthyBackends := getHealthyBackends lb
  if healthyBackends.size == 0 then
    none
  else
    -- Check if we have a cached mapping for this IP
    let cachedIndex := lb.ipHashMap.find? (fun (ip, _) => ip == clientIP)
    match cachedIndex with
    | some (_, index) =>
      if index.toNat < healthyBackends.size then
        some (healthyBackends[index.toNat]!, lb)
      else
        -- Cached index is invalid, recalculate
        let hash := clientIP.hash
        let newIndex := hash % healthyBackends.size
        let updatedMap := lb.ipHashMap.filter (fun (ip, _) => ip != clientIP) ++ #[(clientIP, newIndex.toUInt32)]
        some (healthyBackends[newIndex.toNat]!, { lb with ipHashMap := updatedMap })
    | none =>
      -- Calculate hash and store mapping
      let hash := clientIP.hash
      let index := hash % healthyBackends.size
      let updatedMap := lb.ipHashMap.push (clientIP, index.toUInt32)
      some (healthyBackends[index.toNat]!, { lb with ipHashMap := updatedMap })

-- Weighted Round Robin Algorithm (simplified)
def selectBackendWeightedRoundRobin (lb : LoadBalancerState) : Option (BackendServer × LoadBalancerState) :=
  let healthyBackends := getHealthyBackends lb
  if healthyBackends.size == 0 then
    none
  else
    -- Calculate total weight
    let totalWeight := healthyBackends.foldl (fun acc b => acc + b.weight) 0
    if totalWeight == 0 then
      -- Fallback to regular round robin if all weights are 0
      selectBackendRoundRobin lb
    else
      -- Simple weighted selection based on current index
      let result := healthyBackends.foldl (fun (acc : Option (BackendServer × UInt32)) b =>
        match acc with
        | some (selected, remainingWeight) =>
          if lb.currentIndex < remainingWeight then
            some (selected, remainingWeight)
          else
            some (b, remainingWeight - lb.currentIndex)
        | none =>
          if lb.currentIndex < b.weight then
            some (b, b.weight)
          else
            none
      ) none

      match result with
      | some (backend, _) =>
        let nextIndex := (lb.currentIndex + 1) % totalWeight
        some (backend, { lb with currentIndex := nextIndex })
      | none =>
        -- Fallback
        selectBackendRoundRobin lb

-- Main load balancing function
def selectBackend (lb : LoadBalancerState) (clientIP : Option String := none) : Option (BackendServer × LoadBalancerState) :=
  match lb.algorithm with
  | .ROUND_ROBIN => selectBackendRoundRobin lb
  | .LEAST_CONNECTIONS => selectBackendLeastConnections lb
  | .IP_HASH =>
    match clientIP with
    | some ip => selectBackendIPHash lb ip
    | none => selectBackendRoundRobin lb  -- Fallback
  | .WEIGHTED_ROUND_ROBIN => selectBackendWeightedRoundRobin lb

-- Get load balancer statistics
def getLoadBalancerStats (lb : LoadBalancerState) : String :=
  let healthyCount := getHealthyBackends lb |>.size
  let totalCount := lb.backends.size
  s!"Load Balancer Stats - Algorithm: {lb.algorithm}, Healthy: {healthyCount}/{totalCount}, Current Index: {lb.currentIndex}"

-- ==========================================
-- Reverse Proxy (TCP connect + forward)
-- ==========================================

/-- Connect to a remote host:port. Returns a connected TCP socket fd. -/
@[extern "lean_socket_connect"]
opaque socketConnect (host : @& String) (port : UInt32) : IO UInt64

-- Re-declare send/recv/close for self-contained usage
-- (These are also declared in HTTPServer; opaque allows multiple declarations.)
@[extern "lean_send"]
private opaque proxySend (sock : UInt64) (buf : @& ByteArray) (len : UInt32) (flags : UInt32) : IO UInt32

@[extern "lean_recv"]
private opaque proxyRecv (sock : UInt64) (buf : @& ByteArray) (len : UInt32) (flags : UInt32) : IO UInt32

@[extern "lean_closesocket"]
private opaque proxyClose (sock : UInt64) : IO Unit

/-- Forward a client request to a backend and relay the response.
    `clientSock` = the downstream connection
    `backend` = the selected upstream backend
    `requestData` = raw bytes of the client's request (HTTP/1.1)
    Returns the number of response bytes relayed. -/
def proxyPass (clientSock : UInt64) (backend : BackendServer) (requestData : ByteArray) : IO Nat := do
  -- Connect to upstream
  let upstreamSock ← socketConnect backend.host backend.port.toUInt32
  try
    -- Forward the request
    let _ ← proxySend upstreamSock requestData requestData.size.toUInt32 0

    -- Relay the response back in chunks
    let bufSize : Nat := 4096
    let mut totalRelayed : Nat := 0
    let mut done := false
    while !done do
      let recvBuf := ByteArray.mk (List.replicate bufSize 0).toArray
      let n ← proxyRecv upstreamSock recvBuf bufSize.toUInt32 0
      if n == 0 then
        done := true
      else
        let chunk := recvBuf.extract 0 n.toNat
        let _ ← proxySend clientSock chunk chunk.size.toUInt32 0
        totalRelayed := totalRelayed + n.toNat

    -- Close upstream
    proxyClose upstreamSock
    return totalRelayed
  catch e =>
    try proxyClose upstreamSock catch _ => pure ()
    throw e

end LeanServer
