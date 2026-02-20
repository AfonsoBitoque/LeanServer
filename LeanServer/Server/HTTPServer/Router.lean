import LeanServer.Server.HTTPServer

/-!
  # HTTP Router — Re-export Module
  HTTP request routing, middleware, and static file serving.

  ## Key Types
  - `HTTPRequest` — Parsed HTTP request
  - `HTTPResponse` — HTTP response
  - `Middleware` — Request/Response middleware

  ## Key Functions
  - `routeRequest` — Route a request to a handler
  - `applyMiddleware` — Apply middleware chain
  - `serveStaticFile` — Serve static files from disk
  - `sendErrorResponse` — Send error response
  - `parseHTTPRequest` — Parse raw HTTP request

  ## Built-in Middleware
  - `corsMiddleware` — CORS headers
  - `securityHeadersMiddleware` — Security headers
  - `serverTimingMiddleware` — Server-Timing header
  - `loggingMiddleware` — Request logging
-/

namespace LeanServer.Router

/-- Route an HTTP request -/
@[inline] def route (method path : String) (proto : String := "https") (body : String := "") : IO LeanServer.HTTPResponse :=
  LeanServer.routeRequest method path proto body

/-- Parse raw HTTP request -/
@[inline] def parse (raw : String) : Option LeanServer.HTTPRequest :=
  LeanServer.parseHTTPRequest raw

/-- Serve static file -/
@[inline] def serveStatic (basePath requestPath : String) : IO LeanServer.HTTPResponse :=
  LeanServer.serveStaticFile basePath requestPath

/-- Apply middleware chain -/
@[inline] def applyMiddleware (middlewares : List LeanServer.Middleware)
    (method path proto body : String) (resp : LeanServer.HTTPResponse) : LeanServer.HTTPResponse :=
  LeanServer.applyMiddleware middlewares method path proto body resp

/-- Default middleware stack -/
@[inline] def defaultMiddlewares : List LeanServer.Middleware :=
  LeanServer.defaultMiddlewares

end LeanServer.Router
