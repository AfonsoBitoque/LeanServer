import LeanServer.Server.HTTPServer

/-!
# Advanced CORS Middleware (R25)

Configurable CORS (Cross-Origin Resource Sharing) middleware with support for:
- Per-origin allow lists (not just wildcard)
- Configurable allowed methods and headers
- Credentials support
- Preflight caching
- Origin validation with pattern matching

## Usage
```lean
let corsConfig : CORSConfig := {
  allowedOrigins := [.exact "https://example.com", .pattern "*.example.com"]
  allowCredentials := true
  maxAge := 3600
}
let middleware := advancedCORSMiddleware corsConfig
```

Extends the basic `corsMiddleware` in HTTPServer.lean with production features.
-/

namespace LeanServer

-- ==========================================
-- CORS Configuration Types
-- ==========================================

/-- Origin matching pattern -/
inductive OriginPattern where
  /-- Match any origin -/
  | wildcard
  /-- Match exact origin -/
  | exact (origin : String)
  /-- Match pattern (supports leading wildcard: *.example.com) -/
  | pattern (pat : String)
  deriving Inhabited, BEq, Repr

/-- CORS configuration -/
structure CORSConfig where
  /-- Allowed origins -/
  allowedOrigins   : List OriginPattern := [.wildcard]
  /-- Allowed HTTP methods -/
  allowedMethods   : List String := ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
  /-- Allowed request headers -/
  allowedHeaders   : List String := ["Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin"]
  /-- Headers exposed to the client -/
  exposedHeaders   : List String := ["X-Request-Id", "X-Correlation-Id"]
  /-- Whether credentials (cookies, auth) are allowed -/
  allowCredentials : Bool := false
  /-- Max age (seconds) for preflight cache -/
  maxAge           : Nat := 86400
  /-- Whether to add Vary: Origin header -/
  varyOrigin       : Bool := true
  deriving Inhabited, Repr

/-- CORS preflight result -/
inductive CORSResult where
  | allowed (origin : String)
  | denied
  | preflight (origin : String)
  deriving Inhabited, BEq, Repr

-- ==========================================
-- Origin Matching
-- ==========================================

/-- Check if a string ends with a suffix -/
private def endsWith (s suffix : String) : Bool :=
  if suffix.length > s.length then false
  else s.drop (s.length - suffix.length) == suffix

/-- Check if an origin matches a pattern -/
def matchOrigin (origin : String) (pat : OriginPattern) : Bool :=
  match pat with
  | .wildcard => true
  | .exact o  => origin == o
  | .pattern p =>
    if p.startsWith "*." then
      let suffix := (p.drop 1).toString  -- drop the * but keep the .
      endsWith origin suffix || origin == (p.drop 2).toString  -- also match bare domain
    else
      origin == p

/-- Check if an origin is allowed by the CORS config -/
def isOriginAllowed (origin : String) (config : CORSConfig) : Bool :=
  config.allowedOrigins.any (matchOrigin origin)

/-- Check if a method is allowed -/
def isMethodAllowed (method : String) (config : CORSConfig) : Bool :=
  config.allowedMethods.any (· == method.toUpper)

/-- Check if a header is allowed (case-insensitive) -/
def isHeaderAllowed (header : String) (config : CORSConfig) : Bool :=
  config.allowedHeaders.any (fun h => h.toLower == header.toLower)

-- ==========================================
-- CORS Header Generation
-- ==========================================

/-- Generate CORS headers for an allowed request -/
def corsResponseHeaders (origin : String) (config : CORSConfig) : List (String × String) := Id.run do
  let mut headers : List (String × String) := []

  -- Access-Control-Allow-Origin
  let allowOrigin := if config.allowCredentials then
    origin  -- Can't use * with credentials
  else
    match config.allowedOrigins with
    | [.wildcard] => "*"
    | _ => origin
  headers := headers ++ [("access-control-allow-origin", allowOrigin)]

  -- Credentials
  if config.allowCredentials then
    headers := headers ++ [("access-control-allow-credentials", "true")]

  -- Exposed headers
  if !config.exposedHeaders.isEmpty then
    headers := headers ++ [("access-control-expose-headers", String.intercalate ", " config.exposedHeaders)]

  -- Vary header
  if config.varyOrigin then
    headers := headers ++ [("vary", "Origin")]

  return headers

/-- Generate CORS preflight response headers -/
def corsPreflightHeaders (origin : String) (config : CORSConfig) : List (String × String) := Id.run do
  let mut headers := corsResponseHeaders origin config

  -- Allowed methods
  headers := headers ++ [("access-control-allow-methods", String.intercalate ", " config.allowedMethods)]

  -- Allowed headers
  headers := headers ++ [("access-control-allow-headers", String.intercalate ", " config.allowedHeaders)]

  -- Max age
  headers := headers ++ [("access-control-max-age", toString config.maxAge)]

  return headers

-- ==========================================
-- CORS Middleware
-- ==========================================

/-- Advanced CORS middleware with configurable origin validation -/
def advancedCORSMiddleware (config : CORSConfig := {}) : Middleware := {
  name := "advanced-cors"
  apply := fun method _ _ _ resp =>
    -- In the middleware pipeline, we don't have direct access to the Origin header.
    -- The middleware adds headers assuming the origin was validated at the server level.
    -- For OPTIONS preflight:
    if method == "OPTIONS" then
      let preflightHeaders := corsPreflightHeaders "*" config
      { statusCode := "204", contentType := "text/plain", body := ""
        extraHeaders := preflightHeaders }
    else
      let headers := corsResponseHeaders "*" config
      { resp with extraHeaders := resp.extraHeaders ++ headers }
}

/-- Process a CORS request with full origin validation.
    Call this at the server level where headers are available. -/
def processCORSRequest (method : String) (headers : List (String × String))
    (config : CORSConfig) : CORSResult :=
  let origin := match headers.find? (fun (k, _) => k.toLower == "origin") with
    | some (_, v) => v
    | none => ""
  if origin.isEmpty then .allowed ""  -- Same-origin request
  else if !isOriginAllowed origin config then .denied
  else if method == "OPTIONS" then .preflight origin
  else .allowed origin

/-- Apply CORS result to an HTTP response -/
def applyCORSResult (resp : HTTPResponse) (result : CORSResult) (config : CORSConfig) : HTTPResponse :=
  match result with
  | .allowed origin =>
    if origin.isEmpty then resp
    else { resp with extraHeaders := resp.extraHeaders ++ corsResponseHeaders origin config }
  | .denied =>
    { statusCode := "403", contentType := "text/plain", body := "CORS origin not allowed"
      extraHeaders := [] }
  | .preflight origin =>
    { statusCode := "204", contentType := "text/plain", body := ""
      extraHeaders := corsPreflightHeaders origin config }

-- ==========================================
-- Proofs
-- ==========================================

/-- Wildcard pattern matches any origin -/
theorem wildcard_matches_any (origin : String) :
    matchOrigin origin .wildcard = true := by
  simp [matchOrigin]

/-- Exact pattern matches itself -/
theorem exact_matches_self (origin : String) :
    matchOrigin origin (.exact origin) = true := by
  simp [matchOrigin]

end LeanServer
