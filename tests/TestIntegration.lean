import LeanServer.Server.HTTPServer
import LeanServer.Server.CORSMiddleware
import LeanServer.Server.ContentNegotiation
import LeanServer.Server.ResponseCompression
import LeanServer.Server.RequestId
import LeanServer.Server.DistributedTracing
import LeanServer.Server.HealthCheck
import LeanServer.Server.Metrics
import LeanServer.Server.GracefulShutdown
import LeanServer.Server.ConfigReload
import Init.System.IO

/-!
# Integration Test (ROADMAP F2.7)

Validates that all F2 module integrations work correctly:
- F2.1: Middleware pipeline (register & apply)
- F2.2: Health endpoints (route registry)
- F2.3: Metrics endpoint (route registry)
- F2.4: Graceful shutdown handler (registry)
- F2.5: Config hot-reload handler (registry)
- F2.6: Distributed tracing hook (registry)
-/

open LeanServer

def passed (name : String) : IO Unit :=
  IO.println s!"  ✅ {name}"

/-- Check if `needle` appears as a substring in `haystack` -/
def contains (haystack needle : String) : Bool :=
  let hn := haystack.length
  let nn := needle.length
  if nn > hn || nn == 0 then nn == 0
  else Id.run do
    let chars := haystack.toList
    let nchars := needle.toList
    for i in List.range (hn - nn + 1) do
      let slice := (chars.drop i).take nn
      if slice == nchars then return true
    return false

def failed (name : String) (reason : String) : IO Unit :=
  IO.eprintln s!"  ❌ {name}: {reason}"

def assert (name : String) (cond : Bool) (failMsg : String := "assertion failed") : IO Bool := do
  if cond then
    passed name
    return true
  else
    failed name failMsg
    return false

def main : IO Unit := do
  IO.println "🧪 Running Integration Tests (ROADMAP F2.7)"
  IO.println ""

  let mut total := 0
  let mut pass := 0

  -- ==========================================
  -- F2.1: Middleware Pipeline
  -- ==========================================
  IO.println "── F2.1: Middleware Pipeline ──"

  -- Test: register and retrieve middleware
  total := total + 1
  registerMiddlewares [
    RequestId.requestIdMiddleware {},
    advancedCORSMiddleware {},
    contentNegotiationMiddleware,
    compressionMiddleware {}
  ]
  let mws ← getMiddlewares
  let ok ← assert "Register 4 middleware" (mws.length ≥ 4)
    s!"expected ≥4 middleware, got {mws.length}"
  if ok then pass := pass + 1

  -- Test: middleware names are correct
  total := total + 1
  let names := mws.map (·.name)
  let hasRequestId := names.any (· == "request-id")
  let hasCors := names.any (· == "cors")
  let ok ← assert "Middleware names present" (hasRequestId && hasCors)
    s!"names: {names}"
  if ok then pass := pass + 1

  -- Test: apply middleware to response
  total := total + 1
  let testResp : LeanServer.HTTPResponse := { statusCode := "200", contentType := "text/plain", body := "hello" }
  let applied := applyMiddleware mws "GET" "/" "HTTP/1.1" "" testResp
  let hasHeaders := applied.extraHeaders.length > 0
  let ok ← assert "Middleware transforms response" hasHeaders
    "no extra headers after middleware"
  if ok then pass := pass + 1

  IO.println ""

  -- ==========================================
  -- F2.2: Health Endpoints
  -- ==========================================
  IO.println "── F2.2: Health Endpoints ──"

  -- Test: register health route
  total := total + 1
  registerRoute "GET" "/health/deep" fun _ => do
    let report ← deepHealthCheck "cert.pem" "key.pem"
    pure (healthCheckResponse report)
  let found ← findRegisteredRoute "GET" "/health/deep"
  let ok ← assert "Register /health/deep route" found.isSome
  if ok then pass := pass + 1

  -- Test: register readiness route
  total := total + 1
  registerRoute "GET" "/ready" fun _ => do
    let report ← readinessCheck
    pure (healthCheckResponse report)
  let found ← findRegisteredRoute "GET" "/ready"
  let ok ← assert "Register /ready route" found.isSome
  if ok then pass := pass + 1

  -- Test: register liveness route
  total := total + 1
  registerRoute "GET" "/livez" fun _ => do
    let report ← livenessCheck
    pure (healthCheckResponse report)
  let found ← findRegisteredRoute "GET" "/livez"
  let ok ← assert "Register /livez route" found.isSome
  if ok then pass := pass + 1

  -- Test: call health handler
  total := total + 1
  match found with
  | some handler =>
    let resp ← handler ""
    let isJson := resp.contentType.startsWith "application/json"
    let ok ← assert "Health response is JSON" isJson
      s!"contentType={resp.contentType}"
    if ok then pass := pass + 1
  | none =>
    failed "Health response is JSON" "no handler found"

  IO.println ""

  -- ==========================================
  -- F2.3: Metrics Endpoint
  -- ==========================================
  IO.println "── F2.3: Metrics Endpoint ──"

  -- Test: register metrics route
  total := total + 1
  registerRoute "GET" "/metrics" fun _ => do
    let body ← generatePrometheusMetrics
    return { statusCode := "200", contentType := "text/plain; version=0.0.4; charset=utf-8", body := body }
  let found ← findRegisteredRoute "GET" "/metrics"
  let ok ← assert "Register /metrics route" found.isSome
  if ok then pass := pass + 1

  -- Test: call metrics handler and verify Prometheus format
  total := total + 1
  match found with
  | some handler =>
    let resp ← handler ""
    let hasHelp := contains resp.body "# HELP" || contains resp.body "leanserver"
    let ok ← assert "Metrics response is Prometheus format" hasHelp
      s!"body length={resp.body.length}"
    if ok then pass := pass + 1
  | none =>
    failed "Metrics response is Prometheus format" "no handler found"

  IO.println ""

  -- ==========================================
  -- F2.4: Graceful Shutdown
  -- ==========================================
  IO.println "── F2.4: Graceful Shutdown ──"

  -- Test: register shutdown handler
  total := total + 1
  let shutdownCalled ← IO.mkRef false
  registerShutdownHandler do
    shutdownCalled.set true
  let handler ← getShutdownHandler
  let ok ← assert "Register shutdown handler" handler.isSome
  if ok then pass := pass + 1

  -- Test: invoke shutdown handler
  total := total + 1
  match handler with
  | some h =>
    h
    let called ← shutdownCalled.get
    let ok ← assert "Shutdown handler invoked" called
    if ok then pass := pass + 1
  | none =>
    failed "Shutdown handler invoked" "no handler"

  -- Test: ShutdownCoordinator creates correctly
  total := total + 1
  let coord ← ShutdownCoordinator.create { drainTimeoutMs := 5000 }
  let isDraining ← coord.isDraining
  let ok ← assert "ShutdownCoordinator starts in running state" (!isDraining)
  if ok then pass := pass + 1

  IO.println ""

  -- ==========================================
  -- F2.5: Config Hot-Reload
  -- ==========================================
  IO.println "── F2.5: Config Hot-Reload ──"

  -- Test: register reload handler
  total := total + 1
  let reloadCalled ← IO.mkRef false
  registerReloadHandler do
    reloadCalled.set true
  let handler ← getReloadHandler
  let ok ← assert "Register reload handler" handler.isSome
  if ok then pass := pass + 1

  -- Test: invoke reload handler
  total := total + 1
  match handler with
  | some h =>
    h
    let called ← reloadCalled.get
    let ok ← assert "Reload handler invoked" called
    if ok then pass := pass + 1
  | none =>
    failed "Reload handler invoked" "no handler"

  -- Test: force config reload (file may not exist = graceful no-op)
  total := total + 1
  let diff ← forceConfigReload "nonexistent_config_12345.conf"
  let ok ← assert "Force reload of missing file returns none" diff.isNone
  if ok then pass := pass + 1

  IO.println ""

  -- ==========================================
  -- F2.6: Distributed Tracing
  -- ==========================================
  IO.println "── F2.6: Distributed Tracing ──"

  -- Test: register tracing hook
  total := total + 1
  registerTracingHook fun method path traceparent => do
    let span ← startSpanFromTraceparent
      (if traceparent.isEmpty then "00-0000000000000000-0000000000000000-00" else traceparent)
      s!"{method} {path}" .server
    let finished ← finishSpan span .ok
    return injectTraceparent finished
  let hook ← getTracingHook
  let ok ← assert "Register tracing hook" hook.isSome
  if ok then pass := pass + 1

  -- Test: invoke tracing hook and check headers
  total := total + 1
  match hook with
  | some h =>
    let headers ← h "GET" "/" ""
    let hasTraceparent := headers.any (fun (k, _) => k == "traceparent")
    let ok ← assert "Tracing hook produces traceparent header" hasTraceparent
      s!"headers: {headers.map (·.1)}"
    if ok then pass := pass + 1
  | none =>
    failed "Tracing hook produces traceparent header" "no hook"

  -- Test: traceparent header format (00-{32hex}-{16hex}-{2hex})
  total := total + 1
  match hook with
  | some h =>
    let headers ← h "POST" "/api/data" ""
    match headers.find? (fun (k, _) => k == "traceparent") with
    | some (_, val) =>
      let parts := val.splitOn "-"
      let ok ← assert "traceparent has 4 parts" (parts.length == 4)
        s!"parts={parts.length}: {val}"
      if ok then pass := pass + 1
    | none =>
      failed "traceparent has 4 parts" "no traceparent header"
  | none =>
    failed "traceparent has 4 parts" "no hook"

  IO.println ""

  -- ==========================================
  -- Route lookup: non-existent route returns none
  -- ==========================================
  IO.println "── Negative Tests ──"

  total := total + 1
  let notFound ← findRegisteredRoute "DELETE" "/nonexistent"
  let ok ← assert "Non-existent route returns none" notFound.isNone
  if ok then pass := pass + 1

  total := total + 1
  let wrongMethod ← findRegisteredRoute "POST" "/health/deep"
  let ok ← assert "Wrong method returns none" wrongMethod.isNone
  if ok then pass := pass + 1

  IO.println ""

  -- ==========================================
  -- Summary
  -- ==========================================
  IO.println "══════════════════════════════════════"
  if pass == total then
    IO.println s!"✅ All {pass}/{total} integration tests passed!"
  else
    IO.println s!"❌ {pass}/{total} integration tests passed ({total - pass} failed)"
    IO.eprintln s!"FAIL: {total - pass} test(s) failed"
