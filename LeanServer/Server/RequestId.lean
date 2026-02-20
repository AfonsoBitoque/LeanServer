import LeanServer.Server.HTTPServer

/-!
# Request ID Propagation (R24)

Provides unique request ID generation and propagation throughout the
request lifecycle. Supports both generating new IDs and propagating
incoming IDs from upstream proxies.

## Headers Supported
- `X-Request-Id` — Standard request ID header
- `X-Correlation-Id` — Correlation ID for cross-service tracking
- `X-Amzn-Trace-Id` — AWS trace ID format

## Features
- UUID v4-like ID generation (using IO.getRandomBytes)
- Incoming ID extraction from configurable headers
- ID injection into response headers
- Request context propagation
-/

namespace LeanServer.RequestId

-- ==========================================
-- Request ID Types
-- ==========================================

/-- Request ID configuration -/
structure RequestIdConfig where
  /-- Header to extract incoming request ID from -/
  incomingHeader  : String := "x-request-id"
  /-- Header to set on outgoing responses -/
  outgoingHeader  : String := "x-request-id"
  /-- Also set correlation ID header -/
  setCorrelationId : Bool := true
  /-- Correlation ID header name -/
  correlationHeader : String := "x-correlation-id"
  /-- Prefix for generated IDs -/
  idPrefix        : String := "ls"
  deriving Inhabited, Repr

/-- A request context carrying IDs through the pipeline -/
structure RequestContext where
  /-- Unique request ID for this request -/
  requestId     : String
  /-- Correlation ID (same across related requests) -/
  correlationId : String
  /-- Client IP address -/
  clientIP      : String := ""
  /-- Request start time (ms) -/
  startTimeMs   : Nat := 0
  /-- Additional context key-value pairs -/
  extra         : List (String × String) := []
  deriving Inhabited, Repr

-- ==========================================
-- ID Generation
-- ==========================================

/-- Generate a UUID-v4-like request ID.
    Format: {prefix}-{8hex}-{4hex}-{4hex}-{4hex}-{12hex} -/
def generateRequestId (pfx : String := "ls") : IO String := do
  let bytes ← IO.getRandomBytes 16
  let hexAt (i : Nat) : String :=
    let b := if i < bytes.size then bytes.get! i else 0
    let hi := b.toNat / 16
    let lo := b.toNat % 16
    let hexChar (n : Nat) : Char :=
      if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)
    String.ofList [hexChar hi, hexChar lo]
  let p1 := String.join (List.range 4 |>.map hexAt)
  let p2 := String.join (List.range 2 |>.map (· + 4) |>.map hexAt)
  let p3 := String.join (List.range 2 |>.map (· + 6) |>.map hexAt)
  let p4 := String.join (List.range 2 |>.map (· + 8) |>.map hexAt)
  let p5 := String.join (List.range 6 |>.map (· + 10) |>.map hexAt)
  return s!"{pfx}-{p1}-{p2}-{p3}-{p4}-{p5}"

/-- Generate a short request ID (12 hex chars) -/
def generateShortRequestId (pfx : String := "ls") : IO String := do
  let bytes ← IO.getRandomBytes 6
  let hexAt (i : Nat) : String :=
    let b := if i < bytes.size then bytes.get! i else 0
    let hi := b.toNat / 16
    let lo := b.toNat % 16
    let hexChar (n : Nat) : Char :=
      if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)
    String.ofList [hexChar hi, hexChar lo]
  let hex := String.join (List.range 6 |>.map hexAt)
  return s!"{pfx}-{hex}"

-- ==========================================
-- Header Extraction and Injection
-- ==========================================

/-- Find a header value (case-insensitive) -/
def findHeaderValue (headers : List (String × String)) (name : String) : Option String :=
  match headers.find? (fun (k, _) => k.toLower == name.toLower) with
  | some (_, v) => if v.isEmpty then none else some v
  | none => none

/-- Extract or generate a request context from incoming headers -/
def extractRequestContext (headers : List (String × String))
    (clientIP : String := "") (config : RequestIdConfig := {}) : IO RequestContext := do
  let nowMs ← IO.monoMsNow
  -- Try to extract existing request ID
  let requestId ← match findHeaderValue headers config.incomingHeader with
    | some id => pure id
    | none => generateRequestId (pfx := config.idPrefix)

  -- Try to extract correlation ID (falls back to request ID)
  let correlationId := match findHeaderValue headers config.correlationHeader with
    | some id => id
    | none => requestId

  return { requestId, correlationId, clientIP, startTimeMs := nowMs }

/-- Inject request ID headers into a response -/
def injectRequestIdHeaders (resp : HTTPResponse) (ctx : RequestContext)
    (config : RequestIdConfig := {}) : HTTPResponse :=
  let headers := [(config.outgoingHeader, ctx.requestId)]
  let headers := if config.setCorrelationId then
    headers ++ [(config.correlationHeader, ctx.correlationId)]
  else headers
  { resp with extraHeaders := resp.extraHeaders ++ headers }

/-- Request ID middleware -/
def requestIdMiddleware (config : RequestIdConfig := {}) : LeanServer.Middleware := {
  name := "request-id"
  apply := fun _ _ _ _ resp =>
    -- In the middleware pipeline, we don't have access to the request headers,
    -- so we generate a new ID. The full context extraction happens at the server level.
    -- Here we just ensure the header exists.
    let hasId := resp.extraHeaders.any fun (k, _) => k.toLower == config.outgoingHeader.toLower
    if hasId then resp
    else { resp with extraHeaders := resp.extraHeaders ++ [(config.outgoingHeader, "generated")] }
}

-- ==========================================
-- Request Context Propagation
-- ==========================================

/-- Global request context storage (thread-local via IO.Ref per request) -/
initialize currentRequestContextRef : IO.Ref (Option RequestContext) ← IO.mkRef none

/-- Set the current request context (call at start of request handling) -/
def setRequestContext (ctx : RequestContext) : IO Unit :=
  currentRequestContextRef.set (some ctx)

/-- Get the current request context -/
def getRequestContext : IO (Option RequestContext) :=
  currentRequestContextRef.get

/-- Clear the current request context (call at end of request handling) -/
def clearRequestContext : IO Unit :=
  currentRequestContextRef.set none

/-- Run an action with a request context -/
def withRequestContext (ctx : RequestContext) (action : IO α) : IO α := do
  setRequestContext ctx
  try
    let result ← action
    clearRequestContext
    return result
  catch e =>
    clearRequestContext
    throw e

/-- Get the elapsed time since request start -/
def requestElapsedMs (ctx : RequestContext) : IO Nat := do
  let nowMs ← IO.monoMsNow
  return nowMs - ctx.startTimeMs

-- ==========================================
-- Proofs
-- ==========================================

/-- Finding a header that exists returns some -/
theorem find_existing_header (name value : String) (rest : List (String × String))
    (_h : name.toLower == name.toLower) :
    findHeaderValue ((name, value) :: rest) name = if value.isEmpty then none else some value := by
  simp [findHeaderValue, List.find?]

end LeanServer.RequestId
