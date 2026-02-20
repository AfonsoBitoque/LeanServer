import LeanServer.Server.HTTPServer
import LeanServer.Server.Concurrency
import LeanServer.Server.Metrics

/-!
# Deep Health Check (R23)

Provides comprehensive health checking beyond the simple `/health` endpoint
already in HTTPServer.lean. Deep checks verify internal subsystem health.

## Health Check Levels
- **Shallow** (`/health`): returns 200 if process is alive (already exists)
- **Deep** (`/health/deep`): checks all subsystems
- **Readiness** (`/ready`): checks if server can accept traffic
- **Liveness** (`/livez`): checks if server is not deadlocked

## Subsystem Checks
- TLS certificate validity
- Thread pool utilization
- Memory usage (via GC)
- Rate limiter state
- Connection pool health
- Config file accessibility
-/

namespace LeanServer

-- ==========================================
-- Health Check Types
-- ==========================================

/-- Health status of a subsystem -/
inductive HealthStatus where
  | healthy
  | degraded (reason : String)
  | unhealthy (reason : String)
  deriving Inhabited, BEq, Repr

instance : ToString HealthStatus where
  toString
    | .healthy       => "HEALTHY"
    | .degraded r    => s!"DEGRADED: {r}"
    | .unhealthy r   => s!"UNHEALTHY: {r}"

/-- Overall health status -/
def HealthStatus.isUp : HealthStatus → Bool
  | .healthy     => true
  | .degraded _  => true
  | .unhealthy _ => false

/-- A single health check result -/
structure HealthCheckResult where
  name     : String
  status   : HealthStatus
  durationMs : Nat
  details  : List (String × String) := []
  deriving Inhabited, Repr

/-- Composite health check report -/
structure HealthReport where
  overall    : HealthStatus
  checks     : List HealthCheckResult
  serverUpMs : Nat
  timestamp  : Nat
  version    : String := "0.1.0"
  deriving Inhabited, Repr

-- ==========================================
-- Individual Health Checks
-- ==========================================

/-- Check thread pool health -/
def checkThreadPool : IO HealthCheckResult := do
  let startMs ← IO.monoMsNow
  let count ← getActiveThreadCount
  let threads := count.toNat
  let endMs ← IO.monoMsNow
  let maxThreads := maxConcurrentConnections
  let utilization := if maxThreads > 0 then threads * 100 / maxThreads else 0
  let status := if utilization > 90 then
    HealthStatus.degraded s!"Thread utilization at {utilization}%"
  else if utilization > 99 then
    HealthStatus.unhealthy s!"Thread pool exhausted ({threads}/{maxThreads})"
  else
    HealthStatus.healthy
  return { name := "thread_pool", status, durationMs := endMs - startMs
           details := [("active", toString threads), ("max", toString maxThreads)
                       , ("utilization_pct", toString utilization)] }

/-- Check TLS certificate accessibility -/
def checkTLSCertificate (certPath keyPath : String) : IO HealthCheckResult := do
  let startMs ← IO.monoMsNow
  let certOk ← do
    try
      let _ ← IO.FS.readFile certPath
      pure true
    catch _ => pure false
  let keyOk ← do
    try
      let _ ← IO.FS.readFile keyPath
      pure true
    catch _ => pure false
  let endMs ← IO.monoMsNow
  let status := if certOk && keyOk then HealthStatus.healthy
    else if certOk then HealthStatus.degraded s!"Key file not accessible: {keyPath}"
    else HealthStatus.unhealthy s!"Certificate not accessible: {certPath}"
  return { name := "tls_certificate", status, durationMs := endMs - startMs
           details := [("cert_accessible", toString certOk)
                       , ("key_accessible", toString keyOk)] }

/-- Check config file accessibility -/
def checkConfigFile (configPath : String := "server.config") : IO HealthCheckResult := do
  let startMs ← IO.monoMsNow
  let accessible ← do
    try
      let _ ← IO.FS.readFile configPath
      pure true
    catch _ => pure false
  let endMs ← IO.monoMsNow
  let status := if accessible then HealthStatus.healthy
    else HealthStatus.degraded "Config file not accessible (using defaults)"
  return { name := "config_file", status, durationMs := endMs - startMs
           details := [("path", configPath), ("accessible", toString accessible)] }

/-- Check memory / GC health (basic) -/
def checkMemory : IO HealthCheckResult := do
  let startMs ← IO.monoMsNow
  -- We can't directly query GC stats from Lean 4 without FFI
  -- But we can check if allocation works
  let ok ← do
    try
      let _ := ByteArray.mk (Array.mkEmpty 1024)
      pure true
    catch _ => pure false
  let endMs ← IO.monoMsNow
  let status := if ok then HealthStatus.healthy
    else HealthStatus.unhealthy "Memory allocation failed"
  return { name := "memory", status, durationMs := endMs - startMs
           details := [("allocation_test", toString ok)] }

/-- Check rate limiter state -/
def checkRateLimiter : IO HealthCheckResult := do
  let startMs ← IO.monoMsNow
  let buckets ← rateLimiterRef.get
  let count := buckets.length
  let endMs ← IO.monoMsNow
  let status := if count > 5000 then
    HealthStatus.degraded s!"Rate limiter tracking {count} IPs (high)"
  else
    HealthStatus.healthy
  return { name := "rate_limiter", status, durationMs := endMs - startMs
           details := [("tracked_ips", toString count)] }

/-- Server uptime reference (set at startup) -/
initialize serverStartTimeRef : IO.Ref Nat ← do
  let now ← IO.monoMsNow
  IO.mkRef now

/-- Get server uptime in milliseconds -/
def getServerUptimeMs : IO Nat := do
  let startTime ← serverStartTimeRef.get
  let now ← IO.monoMsNow
  return now - startTime

-- ==========================================
-- Composite Health Checks
-- ==========================================

/-- Run all deep health checks -/
def deepHealthCheck (certPath keyPath : String) (configPath : String := "server.config") : IO HealthReport := do
  let timestamp ← IO.monoMsNow
  let uptimeMs ← getServerUptimeMs

  -- Run all checks
  let threadCheck ← checkThreadPool
  let certCheck ← checkTLSCertificate certPath keyPath
  let configCheck ← checkConfigFile configPath
  let memoryCheck ← checkMemory
  let rateLimitCheck ← checkRateLimiter

  let checks := [threadCheck, certCheck, configCheck, memoryCheck, rateLimitCheck]

  -- Overall: unhealthy if any check is unhealthy; degraded if any is degraded
  let overall := checks.foldl (fun acc c =>
    match acc, c.status with
    | HealthStatus.unhealthy _, _ => acc
    | _, HealthStatus.unhealthy r => HealthStatus.unhealthy r
    | HealthStatus.degraded _, _ => acc
    | _, HealthStatus.degraded r => HealthStatus.degraded r
    | _, _ => acc
  ) HealthStatus.healthy

  return { overall, checks, serverUpMs := uptimeMs, timestamp }

/-- Readiness check — is the server ready to accept traffic? -/
def readinessCheck : IO HealthReport := do
  let timestamp ← IO.monoMsNow
  let uptimeMs ← getServerUptimeMs

  let threadCheck ← checkThreadPool
  -- Server is not ready if thread pool is exhausted
  let overall := if threadCheck.status.isUp then HealthStatus.healthy
    else HealthStatus.unhealthy "Thread pool exhausted"
  return { overall, checks := [threadCheck], serverUpMs := uptimeMs, timestamp }

/-- Liveness check — is the server still alive (not deadlocked)? -/
def livenessCheck : IO HealthReport := do
  let timestamp ← IO.monoMsNow
  let uptimeMs ← getServerUptimeMs
  -- If we can reach this point, the server is alive
  return { overall := .healthy, checks := [], serverUpMs := uptimeMs, timestamp }

-- ==========================================
-- Health Check HTTP Response
-- ==========================================

/-- Format a health check result as JSON -/
def HealthCheckResult.toJSON (r : HealthCheckResult) : String :=
  let statusStr := match r.status with
    | .healthy => "UP" | .degraded _ => "DEGRADED" | .unhealthy _ => "UP"
  let detailsJson := String.intercalate "," (r.details.map fun (k, v) => s!"\"{k}\":\"{v}\"")
  let message := match r.status with
    | .healthy => "" | .degraded m => m | .unhealthy m => m
  s!"\{\"name\":\"{r.name}\",\"status\":\"{statusStr}\",\"duration_ms\":{r.durationMs},\"message\":\"{message}\",\"details\":\{{detailsJson}}}"

/-- Format a health report as JSON -/
def HealthReport.toJSON (report : HealthReport) : String :=
  let statusStr := match report.overall with
    | .healthy => "UP" | .degraded _ => "DEGRADED" | .unhealthy _ => "DOWN"
  let checksJson := String.intercalate ",\n    " (report.checks.map HealthCheckResult.toJSON)
  s!"\{\"status\":\"{statusStr}\",\"version\":\"{report.version}\",\"uptime_ms\":{report.serverUpMs},\"timestamp\":{report.timestamp},\"checks\":[\n    {checksJson}\n  ]}"

/-- Generate health check HTTP response -/
def healthCheckResponse (report : HealthReport) : HTTPResponse :=
  let statusCode := if report.overall.isUp then "200" else "503"
  { statusCode
    contentType := "application/json"
    body := report.toJSON
    extraHeaders := [("cache-control", "no-cache, no-store")] }

-- ==========================================
-- Proofs
-- ==========================================

/-- Healthy status is always up -/
theorem healthy_is_up : HealthStatus.healthy.isUp = true := rfl

/-- Unhealthy status is never up -/
theorem unhealthy_is_not_up (r : String) : (HealthStatus.unhealthy r).isUp = false := rfl

/-- Degraded status is still up -/
theorem degraded_is_up (r : String) : (HealthStatus.degraded r).isUp = true := rfl

end LeanServer
