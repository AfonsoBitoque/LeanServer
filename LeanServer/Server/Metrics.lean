import LeanServer.Server.HTTPServer
import LeanServer.Server.Concurrency

/-!
# Prometheus Metrics Exporter (R22)

Exposes server metrics in Prometheus exposition format (text/plain; version=0.0.4).

## Metrics Exported
- `leanserver_requests_total` — Counter: total HTTP requests by method/status
- `leanserver_connections_active` — Gauge: current active connections
- `leanserver_connections_total` — Counter: total connections accepted
- `leanserver_bytes_sent_total` — Counter: total bytes sent
- `leanserver_bytes_received_total` — Counter: total bytes received
- `leanserver_errors_total` — Counter: total errors by category
- `leanserver_threads_active` — Gauge: active worker threads
- `leanserver_threads_max` — Gauge: max concurrent threads allowed
- `leanserver_tls_handshakes_total` — Counter: TLS handshakes completed
- `leanserver_quic_connections_active` — Gauge: active QUIC connections
- `leanserver_uptime_seconds` — Gauge: server uptime
- `leanserver_build_info` — Info: version and build metadata

## Endpoint
Served at the configurable `metricsPath` (default: `/metrics`).
Content-Type: `text/plain; version=0.0.4; charset=utf-8`
-/

namespace LeanServer

-- ==========================================
-- Metric Types (Prometheus data model)
-- ==========================================

/-- Prometheus metric type -/
inductive MetricType where
  | counter   : MetricType
  | gauge     : MetricType
  | histogram : MetricType
  | summary_  : MetricType
  deriving Repr, BEq

instance : ToString MetricType where
  toString
    | .counter   => "counter"
    | .gauge     => "gauge"
    | .histogram => "histogram"
    | .summary_  => "summary"

/-- A label pair for a metric -/
structure MetricLabel where
  key   : String
  value : String
  deriving Repr, BEq, Inhabited

/-- A single metric sample -/
structure MetricSample where
  name   : String
  labels : List MetricLabel
  value  : Float
  deriving Repr

/-- A metric family (HELP + TYPE + samples) -/
structure MetricFamily where
  name    : String
  help    : String
  type_   : MetricType
  samples : List MetricSample
  deriving Repr

-- ==========================================
-- Metric Registry
-- ==========================================

/-- Mutable counters tracked by the server -/
structure MetricsState where
  requestsByMethod   : List (String × Nat)     -- (method, count)
  requestsByStatus   : List (Nat × Nat)         -- (statusCode, count)
  connectionsTotal   : Nat
  connectionsActive  : Nat
  bytesSent          : Nat
  bytesReceived      : Nat
  errorsByCategory   : List (String × Nat)      -- (category, count)
  tlsHandshakes      : Nat
  quicConnections    : Nat
  startTimeMs        : Nat
  deriving Repr, Inhabited

/-- Global metrics state -/
initialize metricsStateRef : IO.Ref MetricsState ← IO.mkRef {
  requestsByMethod := []
  requestsByStatus := []
  connectionsTotal := 0
  connectionsActive := 0
  bytesSent := 0
  bytesReceived := 0
  errorsByCategory := []
  tlsHandshakes := 0
  quicConnections := 0
  startTimeMs := 0
}

/-- Initialize metrics with server start time -/
def initMetrics : IO Unit := do
  let now ← IO.monoMsNow
  metricsStateRef.modify fun s => { s with startTimeMs := now }

/-- Record an HTTP request -/
def recordRequest (method : String) (statusCode : Nat) : IO Unit := do
  metricsStateRef.modify fun s =>
    let updatedMethods := match s.requestsByMethod.find? (fun (m, _) => m == method) with
      | some (m, _) => s.requestsByMethod.map fun (k, v) => if k == m then (k, v + 1) else (k, v)
      | none => s.requestsByMethod ++ [(method, 1)]
    let updatedStatus := match s.requestsByStatus.find? (fun (c, _) => c == statusCode) with
      | some (c, _) => s.requestsByStatus.map fun (k, v) => if k == c then (k, v + 1) else (k, v)
      | none => s.requestsByStatus ++ [(statusCode, 1)]
    { s with requestsByMethod := updatedMethods, requestsByStatus := updatedStatus }

/-- Record bytes transferred -/
def recordBytes (sent received : Nat) : IO Unit :=
  metricsStateRef.modify fun s => { s with
    bytesSent := s.bytesSent + sent
    bytesReceived := s.bytesReceived + received
  }

/-- Record an error -/
def recordError (category : String) : IO Unit :=
  metricsStateRef.modify fun s =>
    let updated := match s.errorsByCategory.find? (fun (c, _) => c == category) with
      | some (c, _cnt) => s.errorsByCategory.map fun (k, v) => if k == c then (k, v + 1) else (k, v)
      | none => s.errorsByCategory ++ [(category, 1)]
    { s with errorsByCategory := updated }

/-- Record a new connection -/
def recordConnection (isOpen : Bool) : IO Unit :=
  metricsStateRef.modify fun s => { s with
    connectionsTotal := if isOpen then s.connectionsTotal + 1 else s.connectionsTotal
    connectionsActive := if isOpen then s.connectionsActive + 1
                         else if s.connectionsActive > 0 then s.connectionsActive - 1
                         else 0
  }

/-- Record a TLS handshake -/
def recordTLSHandshake : IO Unit :=
  metricsStateRef.modify fun s => { s with tlsHandshakes := s.tlsHandshakes + 1 }

-- ==========================================
-- Prometheus Exposition Format
-- ==========================================

/-- Format labels as Prometheus label string -/
private def formatLabels (labels : List MetricLabel) : String :=
  if labels.isEmpty then ""
  else
    let pairs := labels.map fun l => s!"{l.key}=\"{l.value}\""
    "{" ++ ", ".intercalate pairs ++ "}"

/-- Format a single metric family in Prometheus exposition format -/
private def formatMetricFamily (fam : MetricFamily) : String :=
  let header := s!"# HELP {fam.name} {fam.help}\n# TYPE {fam.name} {fam.type_}\n"
  let samples := fam.samples.map fun s =>
    s!"{s.name}{formatLabels s.labels} {s.value}"
  header ++ "\n".intercalate samples ++ "\n"

/-- Helper to create a metric family -/
private def mkFamily (n h : String) (t : MetricType) (ss : List MetricSample) : MetricFamily :=
  { name := n, help := h, type_ := t, samples := ss }

/-- Helper to create a simple sample with no labels -/
private def mkSample (n : String) (v : Float) : MetricSample :=
  { name := n, labels := [], value := v }

/-- Helper to create a labeled sample -/
private def mkLabeledSample (n : String) (lbls : List MetricLabel) (v : Float) : MetricSample :=
  { name := n, labels := lbls, value := v }

/-- Convert Nat to Float for metric values -/
private def natToFloat (n : Nat) : Float := n.toFloat

/-- Generate the full Prometheus metrics response -/
def generatePrometheusMetrics : IO String := do
  let state ← metricsStateRef.get
  let now ← IO.monoMsNow
  let uptimeSec := (now - state.startTimeMs) / 1000
  let threadCount ← getActiveThreadCount
  let threadCountNat := threadCount.toNat

  let mut families : List MetricFamily := []

  -- Build info
  families := families ++ [mkFamily "leanserver_build_info" "Build information" .gauge
    [mkLabeledSample "leanserver_build_info"
      [{ key := "version", value := "0.1.0" },
       { key := "language", value := "lean4" }] 1.0]]

  -- Uptime
  families := families ++ [mkFamily "leanserver_uptime_seconds" "Server uptime in seconds" .gauge
    [mkSample "leanserver_uptime_seconds" (natToFloat uptimeSec)]]

  -- Requests by method
  let methodSamples := state.requestsByMethod.map fun (method, count) =>
    mkLabeledSample "leanserver_requests_total" [{ key := "method", value := method }] (natToFloat count)
  if !methodSamples.isEmpty then
    families := families ++ [mkFamily "leanserver_requests_total" "Total HTTP requests by method" .counter methodSamples]

  -- Requests by status
  let statusSamples := state.requestsByStatus.map fun (status, count) =>
    mkLabeledSample "leanserver_responses_total" [{ key := "status", value := toString status }] (natToFloat count)
  if !statusSamples.isEmpty then
    families := families ++ [mkFamily "leanserver_responses_total" "Total HTTP responses by status code" .counter statusSamples]

  -- Active connections
  families := families ++ [mkFamily "leanserver_connections_active" "Current active connections" .gauge
    [mkSample "leanserver_connections_active" (natToFloat state.connectionsActive)]]

  -- Total connections
  families := families ++ [mkFamily "leanserver_connections_total" "Total connections accepted" .counter
    [mkSample "leanserver_connections_total" (natToFloat state.connectionsTotal)]]

  -- Bytes sent/received
  families := families ++ [mkFamily "leanserver_bytes_sent_total" "Total bytes sent" .counter
    [mkSample "leanserver_bytes_sent_total" (natToFloat state.bytesSent)]]
  families := families ++ [mkFamily "leanserver_bytes_received_total" "Total bytes received" .counter
    [mkSample "leanserver_bytes_received_total" (natToFloat state.bytesReceived)]]

  -- Errors
  let errSamples := state.errorsByCategory.map fun (cat, count) =>
    mkLabeledSample "leanserver_errors_total" [{ key := "category", value := cat }] (natToFloat count)
  if !errSamples.isEmpty then
    families := families ++ [mkFamily "leanserver_errors_total" "Total errors by category" .counter errSamples]

  -- Threads
  families := families ++ [mkFamily "leanserver_threads_active" "Active worker threads" .gauge
    [mkSample "leanserver_threads_active" (natToFloat threadCountNat)]]
  families := families ++ [mkFamily "leanserver_threads_max" "Maximum concurrent threads allowed" .gauge
    [mkSample "leanserver_threads_max" (natToFloat maxConcurrentConnections)]]

  -- TLS handshakes
  families := families ++ [mkFamily "leanserver_tls_handshakes_total" "Total TLS handshakes completed" .counter
    [mkSample "leanserver_tls_handshakes_total" (natToFloat state.tlsHandshakes)]]

  -- Format all families
  let output := families.map formatMetricFamily
  return "\n".intercalate output

/-- Build the HTTP response for the metrics endpoint -/
def metricsHTTPResponse : IO String := do
  let body ← generatePrometheusMetrics
  let headers := "HTTP/1.1 200 OK\r\n" ++
    "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n" ++
    s!"Content-Length: {body.length}\r\n" ++
    "Connection: close\r\n\r\n"
  return headers ++ body

end LeanServer
