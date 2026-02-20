-- Production Configuration and Logging
-- Simplified production features for LeanServer

import LeanServer
import LeanServer.Protocol.HTTP2
import LeanServer.Protocol.HTTP3
import LeanServer.Protocol.WebSocketOverHTTP2

/-! Este módulo implementa configuração de produção, logging estruturado,
    connection pooling, rate limiting e health checks.
    Pode ser integrado com HTTPServer.lean para funcionalidades avançadas.
    Ver ROADMAP.md (Fase 2) para plano de integração completa. -/

namespace LeanServer

-- LogLevel is imported from LeanServer.Core.Logger
-- (FATAL, ERROR, WARN, INFO, DEBUG, TRACE)

-- Production Configuration Structure (distinct from HTTPServer.ServerConfig)
structure ProdServerConfig where
  host : String
  port : UInt16
  tlsEnabled : Bool
  maxConnections : Nat
  logLevel : LogLevel
  enableWebSocket : Bool
  healthCheckPath : String
  metricsPath : String

instance : Inhabited ProdServerConfig where
  default := {
    host := "0.0.0.0"
    port := 8443
    tlsEnabled := true
    maxConnections := 1000
    logLevel := LogLevel.INFO
    enableWebSocket := true
    healthCheckPath := "/health"
    metricsPath := "/metrics"
  }

-- Connection Pool Entry
structure ConnectionPoolEntry where
  connection : HTTP2ConnectionWithWebSocket
  lastUsed : Nat  -- timestamp
  inUse : Bool

instance : Inhabited ConnectionPoolEntry where
  default := {
    connection := default
    lastUsed := 0
    inUse := false
  }

-- HTTP/2 Connection Pool (distinct from Db.Database.ConnectionPool)
structure HttpConnectionPool where
  available : Array ConnectionPoolEntry
  inUse : Array ConnectionPoolEntry
  maxSize : Nat
  maxIdleTime : Nat  -- seconds
  createdCount : Nat

instance : Inhabited HttpConnectionPool where
  default := {
    available := #[]
    inUse := #[]
    maxSize := 100
    maxIdleTime := 300  -- 5 minutes
    createdCount := 0
  }

-- Connection Pool Statistics
structure ConnectionPoolStats where
  available : Nat
  inUse : Nat
  total : Nat
  maxSize : Nat
  createdCount : Nat

instance : Inhabited ConnectionPoolStats where
  default := {
    available := 0
    inUse := 0
    total := 0
    maxSize := 100
    createdCount := 0
  }

-- Rate Limiting Structures

-- Rate Limit Entry for tracking requests per IP/endpoint
structure RateLimitEntry where
  key : String  -- IP address or endpoint
  requestCount : Nat
  windowStart : Nat  -- timestamp when window started
  lastRequest : Nat  -- timestamp of last request

instance : Inhabited RateLimitEntry where
  default := {
    key := ""
    requestCount := 0
    windowStart := 0
    lastRequest := 0
  }

-- Rate Limit Configuration
structure RateLimitConfig where
  requestsPerMinute : Nat
  requestsPerHour : Nat
  burstLimit : Nat
  windowSizeSeconds : Nat  -- sliding window size

instance : Inhabited RateLimitConfig where
  default := {
    requestsPerMinute := 60
    requestsPerHour := 1000
    burstLimit := 10
    windowSizeSeconds := 60
  }

-- Rate Limiter State
structure RateLimiter where
  entries : Array RateLimitEntry
  config : RateLimitConfig
  maxEntries : Nat  -- maximum number of tracked entries

instance : Inhabited RateLimiter where
  default := {
    entries := #[]
    config := default
    maxEntries := 10000
  }

-- Session Management Structures

-- Session Data - flexible key-value storage
structure SessionData where
  data : Array (String × String)  -- key-value pairs

instance : Inhabited SessionData where
  default := { data := #[] }

-- Session Entry with expiration
structure SessionEntry where
  sessionId : String
  data : SessionData
  createdAt : Nat
  lastAccessed : Nat
  expiresAt : Nat

instance : Inhabited SessionEntry where
  default := {
    sessionId := ""
    data := default
    createdAt := 0
    lastAccessed := 0
    expiresAt := 0
  }

-- Session Configuration
structure SessionConfig where
  sessionTimeoutSeconds : Nat  -- session timeout
  maxSessions : Nat  -- maximum concurrent sessions
  cookieName : String  -- session cookie name
  secureCookie : Bool  -- HTTPS only cookies

instance : Inhabited SessionConfig where
  default := {
    sessionTimeoutSeconds := 1800  -- 30 minutes
    maxSessions := 10000
    cookieName := "leanserver_session"
    secureCookie := true
  }

-- Session Manager State
structure SessionManager where
  sessions : Array SessionEntry
  config : SessionConfig
  nextSessionId : Nat  -- for generating unique IDs

instance : Inhabited SessionManager where
  default := {
    sessions := #[]
    config := default
    nextSessionId := 1
  }

-- Create Connection Pool
def createConnectionPool (maxSize : Nat := 100) (maxIdleTime : Nat := 300) : HttpConnectionPool := {
  available := #[]
  inUse := #[]
  maxSize := maxSize
  maxIdleTime := maxIdleTime
  createdCount := 0
}

-- Get Current Timestamp
def getCurrentTimestamp : IO Nat := do
  -- Use monotonic clock for real timestamps (milliseconds → seconds)
  let ms ← IO.monoMsNow
  return ms / 1000

-- Check if Connection is Expired
def isConnectionExpired (entry : ConnectionPoolEntry) (currentTime : Nat) (maxIdleTime : Nat) : Bool :=
  currentTime - entry.lastUsed > maxIdleTime

-- Borrow Connection from Pool
def borrowConnection (pool : HttpConnectionPool) : IO (HttpConnectionPool × Option HTTP2ConnectionWithWebSocket) := do
  let currentTime ← getCurrentTimestamp

  -- Clean up expired connections
  let available := pool.available.filter (fun entry => !isConnectionExpired entry currentTime pool.maxIdleTime)

  if h : available.size > 0 then
    -- Return first available connection
    let entry := available[0]'h
    let updatedEntry := { entry with lastUsed := currentTime, inUse := true }
    let remainingAvailable := available.extract 1 available.size
    let updatedPool := {
      pool with
      available := remainingAvailable
      inUse := pool.inUse.push updatedEntry
    }
    return (updatedPool, some entry.connection)
  else
    -- No available connections, check if we can create new one
    if pool.createdCount < pool.maxSize then
      -- Create new connection
      let newConnection := initHTTP2ConnectionWithWebSocket
      let newEntry : ConnectionPoolEntry := {
        connection := newConnection
        lastUsed := currentTime
        inUse := true
      }
      let updatedPool := {
        pool with
        inUse := pool.inUse.push newEntry
        createdCount := pool.createdCount + 1
      }
      return (updatedPool, some newConnection)
    else
      -- Pool is full
      return (pool, none)

-- Return Connection to Pool
def returnConnection (pool : HttpConnectionPool) (connection : HTTP2ConnectionWithWebSocket) : IO HttpConnectionPool := do
  let currentTime ← getCurrentTimestamp

  -- Find the connection in inUse
  let inUseIndex := pool.inUse.findIdx? (fun entry => entry.connection == connection)
  match inUseIndex with
  | some idx =>
    let entry := pool.inUse[idx]!
    let updatedEntry := { entry with lastUsed := currentTime, inUse := false }
    let remainingInUse := pool.inUse.eraseIdx! idx
    let updatedPool := {
      pool with
      inUse := remainingInUse
      available := pool.available.push updatedEntry
    }
    return updatedPool
  | none =>
    -- Connection not found in pool, just return original pool
    return pool

-- Clean Up Expired Connections
def cleanupExpiredConnections (pool : HttpConnectionPool) : IO HttpConnectionPool := do
  let currentTime ← getCurrentTimestamp

  let available := pool.available.filter (fun entry => !isConnectionExpired entry currentTime pool.maxIdleTime)
  let _expiredCount := pool.available.size - available.size

  let updatedPool := { pool with available := available }
  return updatedPool

-- Get Pool Statistics
def getPoolStats (pool : HttpConnectionPool) : ConnectionPoolStats :=
  {
    available := pool.available.size
    inUse := pool.inUse.size
    total := pool.available.size + pool.inUse.size
    maxSize := pool.maxSize
    createdCount := pool.createdCount
  }

-- Rate Limiting Functions

-- Check if request is within rate limits
def checkRateLimit (limiter : RateLimiter) (key : String) : IO (RateLimiter × Bool) := do
  let currentTime ← getCurrentTimestamp
  let config := limiter.config

  -- Find existing entry or create new one
  let entryIndex := limiter.entries.findIdx? (fun entry => entry.key == key)

  match entryIndex with
  | some idx =>
    let entry := limiter.entries[idx]!
    let timeDiff := currentTime - entry.windowStart

    -- Check if we need to reset the window
    if timeDiff >= config.windowSizeSeconds then
      -- Reset window
      let newEntry := {
        entry with
        requestCount := 1
        windowStart := currentTime
        lastRequest := currentTime
      }
      let updatedEntries := limiter.entries.set! idx newEntry
      let updatedLimiter := { limiter with entries := updatedEntries }
      return (updatedLimiter, true)
    else
      -- Check limits
      let withinBurst := entry.requestCount < config.burstLimit
      let withinMinute := (entry.requestCount * 60) / config.windowSizeSeconds < config.requestsPerMinute
      let withinHour := (entry.requestCount * 3600) / config.windowSizeSeconds < config.requestsPerHour

      if withinBurst && withinMinute && withinHour then
        -- Allow request, increment counter
        let updatedEntry := {
          entry with
          requestCount := entry.requestCount + 1
          lastRequest := currentTime
        }
        let updatedEntries := limiter.entries.set! idx updatedEntry
        let updatedLimiter := { limiter with entries := updatedEntries }
        return (updatedLimiter, true)
      else
        -- Rate limit exceeded
        return (limiter, false)
  | none =>
    -- Create new entry
    if limiter.entries.size < limiter.maxEntries then
      let newEntry : RateLimitEntry := {
        key := key
        requestCount := 1
        windowStart := currentTime
        lastRequest := currentTime
      }
      let updatedLimiter := { limiter with entries := limiter.entries.push newEntry }
      return (updatedLimiter, true)
    else
      -- Too many entries, allow request but don't track
      return (limiter, true)

-- Clean up expired rate limit entries
def cleanupRateLimiter (limiter : RateLimiter) : IO RateLimiter := do
  let currentTime ← getCurrentTimestamp
  let config := limiter.config

  -- Remove entries older than 2x window size
  let maxAge := config.windowSizeSeconds * 2
  let activeEntries := limiter.entries.filter (fun entry =>
    currentTime - entry.lastRequest < maxAge
  )

  return { limiter with entries := activeEntries }

-- Get rate limiter statistics
def getRateLimiterStats (limiter : RateLimiter) : String :=
  let totalEntries := limiter.entries.size
  let totalRequests := limiter.entries.foldl (fun acc entry => acc + entry.requestCount) 0
  s!"RateLimiter: {totalEntries} entries, {totalRequests} total requests, limits: {limiter.config.requestsPerMinute}/min, {limiter.config.requestsPerHour}/hour"

-- Session Management Functions

-- Generate a cryptographically random session ID (16 bytes = 128 bits of entropy)
def generateSessionId (_manager : SessionManager) : IO String := do
  let bytes ← IO.getRandomBytes 16
  return LeanServer.hex bytes

-- Create a new session
def createSession (manager : SessionManager) : IO (SessionManager × String) := do
  let currentTime ← getCurrentTimestamp
  let config := manager.config

  -- Check if we can create more sessions
  if manager.sessions.size >= config.maxSessions then
    return (manager, "")  -- Session limit reached

  let sessionId ← generateSessionId manager
  let expiresAt := currentTime + config.sessionTimeoutSeconds

  let newSession : SessionEntry := {
    sessionId := sessionId
    data := default
    createdAt := currentTime
    lastAccessed := currentTime
    expiresAt := expiresAt
  }

  let updatedManager := {
    manager with
    sessions := manager.sessions.push newSession
    nextSessionId := manager.nextSessionId + 1
  }

  return (updatedManager, sessionId)

-- Get session by ID
def getSession (manager : SessionManager) (sessionId : String) : IO (SessionManager × Option SessionEntry) := do
  let currentTime ← getCurrentTimestamp

  -- Find the session
  let sessionIndex := manager.sessions.findIdx? (fun session => session.sessionId == sessionId)

  match sessionIndex with
  | some idx =>
    let session := manager.sessions[idx]!
    -- Check if session is expired
    if currentTime > session.expiresAt then
      -- Remove expired session
      let updatedSessions := manager.sessions.eraseIdx! idx
      let updatedManager := { manager with sessions := updatedSessions }
      return (updatedManager, none)
    else
      -- Update last accessed time and extend expiration
      let config := manager.config
      let newExpiresAt := currentTime + config.sessionTimeoutSeconds
      let updatedSession := {
        session with
        lastAccessed := currentTime
        expiresAt := newExpiresAt
      }
      let updatedSessions := manager.sessions.set! idx updatedSession
      let updatedManager := { manager with sessions := updatedSessions }
      return (updatedManager, some updatedSession)
  | none =>
    return (manager, none)

-- Update session data
def updateSessionData (manager : SessionManager) (sessionId : String) (key : String) (value : String) : IO SessionManager := do
  let (updatedManager, maybeSession) ← getSession manager sessionId

  match maybeSession with
  | some session =>
    let sessionIndex := updatedManager.sessions.findIdx? (fun s => s.sessionId == sessionId)
    match sessionIndex with
    | some idx =>
      -- Update or add the key-value pair
      let _ := updatedManager.sessions[idx]!
      let currentData := session.data.data
      let existingIndex := currentData.findIdx? (fun (k, _) => k == key)

      let newData := match existingIndex with
      | some dataIdx => currentData.set! dataIdx (key, value)
      | none => currentData.push (key, value)

      let updatedSessionData := { session.data with data := newData }
      let updatedSession := { session with data := updatedSessionData }
      let updatedSessions := updatedManager.sessions.set! idx updatedSession
      return { updatedManager with sessions := updatedSessions }
    | none => return updatedManager
  | none => return updatedManager

-- Get session data value
def getSessionData (manager : SessionManager) (sessionId : String) (key : String) : IO (SessionManager × Option String) := do
  let (updatedManager, maybeSession) ← getSession manager sessionId

  match maybeSession with
  | some session =>
    let dataPair := session.data.data.find? (fun (k, _) => k == key)
    match dataPair with
    | some (_, value) => return (updatedManager, some value)
    | none => return (updatedManager, none)
  | none => return (updatedManager, none)

-- Delete session
def deleteSession (manager : SessionManager) (sessionId : String) : SessionManager :=
  let sessionIndex := manager.sessions.findIdx? (fun session => session.sessionId == sessionId)
  match sessionIndex with
  | some idx =>
    let updatedSessions := manager.sessions.eraseIdx! idx
    { manager with sessions := updatedSessions }
  | none => manager

-- Cleanup expired sessions
def cleanupExpiredSessions (manager : SessionManager) : IO SessionManager := do
  let currentTime ← getCurrentTimestamp

  let activeSessions := manager.sessions.filter (fun session =>
    currentTime <= session.expiresAt
  )

  return { manager with sessions := activeSessions }

-- Get session manager statistics
def getSessionManagerStats (manager : SessionManager) : IO String := do
  let totalSessions := manager.sessions.size
  let currentTime ← getCurrentTimestamp
  let activeSessions := manager.sessions.filter (fun session => currentTime <= session.expiresAt)
  return s!"SessionManager: {totalSessions} total sessions, {activeSessions.size} active, max: {manager.config.maxSessions}, timeout: {manager.config.sessionTimeoutSeconds}s"

-- Production Log Entry (distinct from Core.Logger.LogEntry)
structure ProdLogEntry where
  timestamp : Nat
  level : LogLevel
  component : String
  message : String

instance : Inhabited ProdLogEntry where
  default := {
    timestamp := 0
    level := LogLevel.INFO
    component := "unknown"
    message := ""
  }

-- Production Logger (distinct from Core.Logger.Logger)
structure ProdLogger where
  config : ProdServerConfig
  entries : Array ProdLogEntry
  logFile : Option String  -- Optional log file path

instance : Inhabited ProdLogger where
  default := {
    config := default
    entries := #[]
    logFile := none
  }

-- Metrics Structure
structure ServerMetrics where
  totalRequests : Nat
  totalConnections : Nat
  activeConnections : Nat
  bytesSent : Nat
  bytesReceived : Nat
  errorCount : Nat

instance : Inhabited ServerMetrics where
  default := {
    totalRequests := 0
    totalConnections := 0
    activeConnections := 0
    bytesSent := 0
    bytesReceived := 0
    errorCount := 0
  }

-- Production Server State
structure ProductionServerState where
  config : ProdServerConfig
  logger : ProdLogger
  metrics : ServerMetrics
  http2Connections : Array HTTP2ConnectionWithWebSocket
  connectionPool : HttpConnectionPool
  rateLimiter : RateLimiter
  sessionManager : SessionManager
  http3Server : H3ServerState

instance : Inhabited ProductionServerState where
  default := {
    config := default
    logger := default
    metrics := default
    http2Connections := #[]
    connectionPool := default
    rateLimiter := default
    sessionManager := default
    http3Server := default
  }

-- Create Logger
def createLogger (config : ProdServerConfig) (logFile : Option String := none) : ProdLogger := {
  config := config
  entries := #[]
  logFile := logFile
}

-- Check if message should be logged based on level
def shouldLog (configLevel : LogLevel) (messageLevel : LogLevel) : Bool :=
  messageLevel.priority ≤ configLevel.priority

-- Format Log Entry for Display
def formatLogEntry (entry : ProdLogEntry) : String :=
  s!"[{entry.timestamp}] {entry.level} [{entry.component}] {entry.message}"

-- Log Message
def logMessage (logger : ProdLogger) (level : LogLevel) (component : String) (message : String) : IO ProdLogger := do
  if shouldLog logger.config.logLevel level then
    let timestamp ← getCurrentTimestamp
    let entry : ProdLogEntry := {
      timestamp := timestamp
      level := level
      component := component
      message := message
    }
    let updatedEntries := logger.entries.push entry
    let updatedLogger := { logger with entries := updatedEntries }

    -- Write to log file if configured
    match logger.logFile with
    | some filename =>
      let logLine := formatLogEntry entry
      IO.FS.withFile filename IO.FS.Mode.append (fun handle => do
        handle.putStrLn logLine
        handle.flush
      )
      return updatedLogger
    | none =>
      return updatedLogger
  else
    return logger

-- Display Recent Logs
def displayRecentLogs (logger : ProdLogger) (count : Nat := 10) : IO Unit := do
  let entries := logger.entries
  let start := if entries.size > count then entries.size - count else 0
  let recentEntries := entries.extract start entries.size
  IO.eprintln "📋 Recent Log Entries:"
  for entry in recentEntries do
    IO.eprintln s!"  {formatLogEntry entry}"

-- Initialize Production Server (shared builder — takes resolved config)
private def buildProductionServer (config : ProdServerConfig) (logFile : Option String := none) : IO ProductionServerState := do
  let logger := createLogger config logFile
  let metrics : ServerMetrics := default
  let connectionPool := createConnectionPool config.maxConnections 300
  let rateLimiter : RateLimiter := default
  let sessionManager : SessionManager := default
  let http3Server : H3ServerState := initH3Server config.maxConnections.toUInt64

  let serverState : ProductionServerState := {
    config := config
    logger := logger
    metrics := metrics
    http2Connections := #[]
    connectionPool := connectionPool
    rateLimiter := rateLimiter
    sessionManager := sessionManager
    http3Server := http3Server
  }

  IO.eprintln s!"🚀 Production HTTPS Server initialized on {config.host}:{config.port}"
  IO.eprintln s!"📋 Configuration: TLS={config.tlsEnabled}, WebSocket={config.enableWebSocket}, LogLevel={config.logLevel}"
  IO.eprintln s!"🔗 Connection Pool: Max {config.maxConnections} connections"
  IO.eprintln s!"🛡️  Rate Limiter: {rateLimiter.config.requestsPerMinute}/min, {rateLimiter.config.requestsPerHour}/hour"
  IO.eprintln s!"🌐 HTTP/3 Server: Ready for QUIC connections"
  match logFile with
  | some file => IO.eprintln s!"📝 Persistent logging enabled: {file}"
  | none => IO.eprintln "📝 Logging to console only"
  return serverState

/-- Initialize server with default configuration. -/
def initProductionServer : IO ProductionServerState :=
  buildProductionServer default

-- Parse log level from string
def parseLogLevel (level : String) : LogLevel :=
  LogLevel.parse level

-- Extract value from config line (format: key = "value")
def extractValue (line : String) : String :=
  let parts := line.splitOn "="
  if parts.length >= 2 then
    let valuePart := parts[1]!
    -- Very simple: just return the part after = as-is
    valuePart
  else
    ""

-- Parse Configuration File
def prodParseConfigLine (line : String) : Option (String × String) :=
  let trimmed := line.trimAscii.toString
  if trimmed.isEmpty || trimmed.startsWith "#" then
    none
  else
    match trimmed.splitOn "=" with
    | [key, value] => some (key.trimAscii.toString, value.trimAscii.toString.replace "\"" "")
    | _ => none

-- Parse Boolean from String
def prodParseBool (boolStr : String) : Bool :=
  match boolStr.toLower with
  | "true" | "1" | "yes" | "on" => true
  | _ => false

-- Parse Nat from String
def prodParseNat (natStr : String) : Nat :=
  match natStr.toNat? with
  | some n => n
  | none => 0

-- Load Configuration from File Content
def loadConfigFromContent (content : String) : ProdServerConfig :=
  let lines := content.splitOn "\n"
  let configMap := lines.filterMap prodParseConfigLine

  -- Start from default configuration (see Inhabited ProdServerConfig)
  let config : ProdServerConfig := default

  -- Apply configuration from file
  let config := List.foldl (fun acc (key, value) =>
    match key with
    | "host" => { acc with host := value }
    | "port" => { acc with port := UInt16.ofNat (prodParseNat value) }
    | "tls_enabled" => { acc with tlsEnabled := prodParseBool value }
    | "max_connections" => { acc with maxConnections := prodParseNat value }
    | "log_level" => { acc with logLevel := parseLogLevel value }
    | "enable_websocket" => { acc with enableWebSocket := prodParseBool value }
    | "health_check_path" => { acc with healthCheckPath := value }
    | "metrics_path" => { acc with metricsPath := value }
    | _ => acc  -- Ignore unknown keys
  ) config configMap

  config

def loadConfigFromFile (filename : String) : IO ProdServerConfig := do
  let fileExists ← System.FilePath.pathExists filename
  if fileExists then
    let content ← IO.FS.readFile filename
    let config := loadConfigFromContent content
    IO.eprintln s!"📄 Configuration loaded from {filename}"
    return config
  else
    IO.eprintln s!"⚠️  Configuration file {filename} not found, using defaults"
    return default

-- Initialize Production Server with file configuration
/-- Initialize server from a config file (defaults to "server.config"). -/
def initProductionServerFromFile (configFile : String := "server.config") (logFile : Option String := some "server.log") : IO ProductionServerState := do
  let config ← loadConfigFromFile configFile
  buildProductionServer config logFile

-- Log Server Event
def logServerEvent (server : ProductionServerState) (level : LogLevel) (component : String) (message : String) : IO ProductionServerState := do
  let updatedLogger ← logMessage server.logger level component message
  return { server with logger := updatedLogger }

-- Update Metrics
def updateMetrics (server : ProductionServerState) (newRequest : Bool := false) (newConnection : Bool := false) (bytesSent : Nat := 0) (bytesReceived : Nat := 0) : ProductionServerState :=
  let currentMetrics := server.metrics
  let updatedMetrics := {
    currentMetrics with
    totalRequests := if newRequest then currentMetrics.totalRequests + 1 else currentMetrics.totalRequests
    totalConnections := if newConnection then currentMetrics.totalConnections + 1 else currentMetrics.totalConnections
    activeConnections := server.http2Connections.size
    bytesSent := currentMetrics.bytesSent + bytesSent
    bytesReceived := currentMetrics.bytesReceived + bytesReceived
  }
  { server with metrics := updatedMetrics }

-- Get Metrics Response
def getMetricsResponse (server : ProductionServerState) : String :=
  let m := server.metrics
  s!"# HELP lean_server_total_requests Total number of HTTP requests
# TYPE lean_server_total_requests counter
lean_server_total_requests {m.totalRequests}

# HELP lean_server_total_connections Total number of connections
# TYPE lean_server_total_connections counter
lean_server_total_connections {m.totalConnections}

# HELP lean_server_active_connections Current active connections
# TYPE lean_server_active_connections gauge
lean_server_active_connections {m.activeConnections}

# HELP lean_server_bytes_sent Total bytes sent
# TYPE lean_server_bytes_sent counter
lean_server_bytes_sent {m.bytesSent}

# HELP lean_server_bytes_received Total bytes received
# TYPE lean_server_bytes_received counter
lean_server_bytes_received {m.bytesReceived}

# HELP lean_server_error_count Total errors
# TYPE lean_server_error_count counter
lean_server_error_count {m.errorCount}
"

-- Handle Health Check Request
def handleHealthCheck (server : ProductionServerState) : String :=
  let m := server.metrics
  "{\n" ++
  s!"  \"status\": \"healthy\",\n" ++
  s!"  \"uptime\": 3600,\n" ++
  s!"  \"total_connections\": {m.totalConnections},\n" ++
  s!"  \"active_connections\": {m.activeConnections},\n" ++
  s!"  \"total_requests\": {m.totalRequests},\n" ++
  s!"  \"error_count\": {m.errorCount}\n" ++
  "}"

-- Session Management Helper Functions for Server Integration

-- Create session for server
def createSessionForServer (server : ProductionServerState) (_ : String) : IO (ProductionServerState × Except String String) := do
  let (updatedManager, sessionId) ← createSession server.sessionManager
  return ({ server with sessionManager := updatedManager }, Except.ok sessionId)

-- Update session data for server
def updateSessionDataForServer (server : ProductionServerState) (sessionId : String) (key : String) (value : String) : IO (ProductionServerState × Except String Unit) := do
  let updatedManager ← updateSessionData server.sessionManager sessionId key value
  return ({ server with sessionManager := updatedManager }, Except.ok ())

-- Get session data for server
def getSessionDataForServer (server : ProductionServerState) (sessionId : String) (key : String) : IO (ProductionServerState × Except String (Option String)) := do
  let (updatedManager, result) ← getSessionData server.sessionManager sessionId key
  return ({ server with sessionManager := updatedManager }, Except.ok result)

-- Cleanup expired sessions for server
def cleanupExpiredSessionsForServer (server : ProductionServerState) : IO ProductionServerState := do
  let updatedManager ← cleanupExpiredSessions server.sessionManager
  return { server with sessionManager := updatedManager }

-- Get session statistics for server
def getServerSessionStats (server : ProductionServerState) : IO String :=
  getSessionManagerStats server.sessionManager

-- Get HTTP/3 server statistics for server
def getServerHTTP3Stats (server : ProductionServerState) : String :=
  getH3ServerStats server.http3Server

-- Graceful Shutdown
def gracefulShutdown (server : ProductionServerState) : IO Unit := do
  IO.eprintln "🛑 Initiating graceful shutdown..."

  -- Log shutdown event
  let server ← logServerEvent server LogLevel.INFO "server" "Graceful shutdown initiated"

  -- Close all connections
  for _ in server.http2Connections do
    -- Connection cleanup (no FFI close needed for pure Lean connections)
    IO.eprintln "✓ Closed connection"

  -- Display final metrics
  IO.eprintln "📊 Final Server Metrics:"
  IO.eprintln s!"  Total Requests: {server.metrics.totalRequests}"
  IO.eprintln s!"  Total Connections: {server.metrics.totalConnections}"
  IO.eprintln s!"  Bytes Sent: {server.metrics.bytesSent}"
  IO.eprintln s!"  Bytes Received: {server.metrics.bytesReceived}"
  IO.eprintln s!"  Errors: {server.metrics.errorCount}"

  -- Display recent logs
  displayRecentLogs server.logger 5

  IO.eprintln "✅ Graceful shutdown completed"

-- Connection Pool Management Functions (Server Level)

-- Borrow a connection from the server's connection pool
def borrowConnectionFromServer (server : ProductionServerState) : IO (ProductionServerState × Option HTTP2ConnectionWithWebSocket) := do
  let poolResult ← borrowConnection server.connectionPool
  match poolResult with
  | (updatedPool, some conn) =>
    let updatedServer := { server with connectionPool := updatedPool }
    return (updatedServer, some conn)
  | (updatedPool, none) =>
    let updatedServer := { server with connectionPool := updatedPool }
    return (updatedServer, none)

-- Return a connection to the server's connection pool
def returnConnectionToServer (server : ProductionServerState) (conn : HTTP2ConnectionWithWebSocket) : IO ProductionServerState := do
  let updatedPool ← returnConnection server.connectionPool conn
  return { server with connectionPool := updatedPool }

-- Cleanup expired connections in the server's connection pool
def cleanupServerConnectionPool (server : ProductionServerState) : IO ProductionServerState := do
  let updatedPool ← cleanupExpiredConnections server.connectionPool
  return { server with connectionPool := updatedPool }

-- Get connection pool statistics from the server
def getServerPoolStats (server : ProductionServerState) : ConnectionPoolStats :=
  getPoolStats server.connectionPool

-- Rate Limiting Management Functions (Server Level)

-- Check rate limit for a client request
def checkRateLimitForServer (server : ProductionServerState) (clientKey : String) : IO (ProductionServerState × Bool) := do
  let (updatedLimiter, allowed) ← checkRateLimit server.rateLimiter clientKey
  let updatedServer := { server with rateLimiter := updatedLimiter }

  if !allowed then
    -- Log rate limit violation
    let updatedServer ← logServerEvent updatedServer LogLevel.WARN "ratelimit" s!"Rate limit exceeded for client: {clientKey}"
    return (updatedServer, false)
  else
    return (updatedServer, true)

-- Cleanup expired rate limit entries in the server
def cleanupServerRateLimiter (server : ProductionServerState) : IO ProductionServerState := do
  let updatedLimiter ← cleanupRateLimiter server.rateLimiter
  return { server with rateLimiter := updatedLimiter }

-- Get rate limiter statistics from the server
def getServerRateLimiterStats (server : ProductionServerState) : String :=
  getRateLimiterStats server.rateLimiter

end LeanServer
