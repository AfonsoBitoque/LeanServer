-- Web Application Framework
-- High-level web framework built on top of LeanServer HTTP infrastructure
-- Provides routing, middleware, and database integration for full-stack applications

import LeanServer.Db.Database
import LeanServer.Db.PostgreSQL
import LeanServer.Db.MySQL
import LeanServer.Protocol.HTTP2
import LeanServer.Server.HTTPServer

namespace LeanServer

-- Web Application Configuration
structure WebAppConfig where
  port : UInt16 := 8080
  databaseConfig : DatabaseConfig
  databaseType : DatabaseType := DatabaseType.PostgreSQL
  maxConnections : Nat := 100

-- HTTP Request Context with Database Access
-- Stores both driver managers; only the active one is populated.
structure RequestContext where
  request : HttpRequest
  pgManager : Option (DatabaseManager PostgreSQLDriver) := none
  myManager : Option (DatabaseManager MySQLDriver) := none
  sessionData : Option (List (String × String)) := none

-- HTTP Response Builder
structure WebAppResponseBuilder where
  statusCode : UInt16 := 200
  headers : Array HeaderField := #[]
  body : ByteArray := ByteArray.empty
  contentType : String := "text/plain"

-- Route Handler Type
abbrev WebAppRouteHandler := RequestContext → IO WebAppResponseBuilder

-- Web Application State
structure WebAppState where
  config : WebAppConfig
  routes : List (String × WebAppRouteHandler) := []
  middleware : Array (RequestContext → IO (Option RequestContext)) := #[]
  pgManager : Option (DatabaseManager PostgreSQLDriver) := none
  myManager : Option (DatabaseManager MySQLDriver) := none

-- Initialize Web Application
def initWebApp (config : WebAppConfig) : IO WebAppState := do
  IO.eprintln s!"🚀 Initializing Web Application on port {config.port}"

  -- Initialize database based on type
  match config.databaseType with
  | DatabaseType.PostgreSQL =>
    let driver : PostgreSQLDriver := {}
    let mgr ← initDatabaseManager driver config.databaseConfig DatabaseType.PostgreSQL
    IO.eprintln "✅ PostgreSQL database connection established"
    IO.eprintln s!"✅ Web application ready with {config.maxConnections} max connections"
    return { config := config, pgManager := some mgr }
  | DatabaseType.MySQL =>
    let driver : MySQLDriver := {}
    let mgr ← initDatabaseManager driver config.databaseConfig DatabaseType.MySQL
    IO.eprintln "✅ MySQL database connection established"
    IO.eprintln s!"✅ Web application ready with {config.maxConnections} max connections"
    return { config := config, myManager := some mgr }
  | DatabaseType.SQLite =>
    -- SQLite not yet supported; fall back to PostgreSQL
    let driver : PostgreSQLDriver := {}
    let mgr ← initDatabaseManager driver config.databaseConfig DatabaseType.PostgreSQL
    IO.eprintln "⚠️ SQLite not yet supported, using PostgreSQL"
    return { config := config, pgManager := some mgr }

-- Add Route
def addWebAppRoute (app : WebAppState) (method : String) (path : String) (handler : WebAppRouteHandler) : WebAppState :=
  let routeKey := s!"{method}:{path}"
  { app with routes := (routeKey, handler) :: app.routes }

-- Add Middleware
def addWebAppMiddleware (app : WebAppState) (middleware : RequestContext → IO (Option RequestContext)) : WebAppState :=
  { app with middleware := app.middleware.push middleware }

-- Create Response Builder
def createWebAppResponse
  (statusCode : UInt16 := 200)
  (body : String := "")
  (contentType : String := "text/plain") : WebAppResponseBuilder :=
{
  statusCode := statusCode
  body := body.toUTF8
  contentType := contentType
  headers := #[{ name := "Content-Type", value := contentType : HeaderField }]
}

-- JSON Response Helper
def webAppJsonResponse (data : String) : WebAppResponseBuilder :=
  createWebAppResponse 200 data "application/json"

-- HTML Response Helper
def webAppHtmlResponse (html : String) : WebAppResponseBuilder :=
  createWebAppResponse 200 html "text/html"

-- Error Response Helper
def webAppErrorResponse (statusCode : UInt16) (message : String) : WebAppResponseBuilder :=
  createWebAppResponse statusCode message "text/plain"

-- Database Middleware - Database manager is already in context
def webAppDatabaseMiddleware : RequestContext → IO (Option RequestContext) := fun ctx => do
  return some ctx

-- Session Middleware - Basic session management
def webAppSessionMiddleware : RequestContext → IO (Option RequestContext) := fun ctx => do
  -- Simple session extraction from headers (in real app, use cookies/tokens)
  let sessionHeader := ctx.request.headers.find? (fun h => h.name == "X-Session-ID")
  let sessionData := match sessionHeader with
  | some header => some [("sessionId", header.value)]
  | none => none

  return some { ctx with sessionData := sessionData }

-- Process Request with Middleware Chain
def processWebAppMiddleware
  (ctx : RequestContext)
  (middleware : Array (RequestContext → IO (Option RequestContext)))
  (index : Nat := 0) : IO (Option RequestContext) := do
  if index >= middleware.size then
    return some ctx
  else
    let middlewareFunc := middleware[index]!
    let result ← middlewareFunc ctx
    match result with
    | some newCtx => processWebAppMiddleware newCtx middleware (index + 1)
    | none => return none

-- Handle HTTP Request
def handleWebAppRequest (app : WebAppState) (httpRequest : HttpRequest) : IO WebAppResponseBuilder := do
  let routeKey := s!"{httpRequest.method}:{httpRequest.path}"

  -- Create request context
  let ctx : RequestContext := {
    request := httpRequest
    pgManager := app.pgManager
    myManager := app.myManager
  }

  -- Process middleware chain
  let processedCtx ← processWebAppMiddleware ctx app.middleware

  match processedCtx with
  | some finalCtx =>
    -- Find and execute route handler
    match app.routes.find? (fun (key, _) => key == routeKey) with
    | some (_, handler) =>
      let response ← handler finalCtx
      return response
    | none =>
      return webAppErrorResponse 404 s!"Route not found: {httpRequest.method} {httpRequest.path}"
  | none =>
    return webAppErrorResponse 403 "Request blocked by middleware"

-- Convert Response Builder to HTTP Response
def webAppResponseToHttpResponse (builder : WebAppResponseBuilder) : HttpResponse :=
{
  statusCode := builder.statusCode
  headers := builder.headers
  body := builder.body
  streamId := 1
}

-- Database Query Helpers for Route Handlers

-- Execute query using PostgreSQL manager from context
def executePgQuery (ctx : RequestContext) (query : String) : IO (Except DatabaseError (RequestContext × QueryResult)) := do
  match ctx.pgManager with
  | some mgr =>
    match ← executeQueryWithPool mgr query with
    | Except.ok (updatedMgr, result) =>
      return Except.ok ({ ctx with pgManager := some updatedMgr }, result)
    | Except.error err =>
      return Except.error err
  | none =>
    return Except.error (DatabaseError.ConnectionFailed "PostgreSQL manager not configured")

-- Execute query using MySQL manager from context
def executeMySqlQuery (ctx : RequestContext) (query : String) : IO (Except DatabaseError (RequestContext × QueryResult)) := do
  match ctx.myManager with
  | some mgr =>
    match ← executeQueryWithPool mgr query with
    | Except.ok (updatedMgr, result) =>
      return Except.ok ({ ctx with myManager := some updatedMgr }, result)
    | Except.error err =>
      return Except.error err
  | none =>
    return Except.error (DatabaseError.ConnectionFailed "MySQL manager not configured")

-- Helper to convert QueryResult rows to simple JSON string
def queryResultToJson (result : QueryResult) : String :=
  let jsonRows := result.rows.map (fun row =>
    let n := min result.columns.size row.size
    let indices := List.range n
    let pairs := indices.map (fun i => s!"\"{result.columns[i]!}\": \"{row[i]!}\"")
    "{" ++ String.intercalate ", " pairs ++ "}"
  )
  "[" ++ String.intercalate ", " jsonRows.toList ++ "]"

-- Start Web Application Server
def startWebApp (app : WebAppState) : IO Unit := do
  IO.eprintln s!"🌐 Starting Web Application Server on port {app.config.port}"
  IO.eprintln s!"📊 Routes configured: {app.routes.length}"
  IO.eprintln s!"🔧 Middleware configured: {app.middleware.size}"
  IO.eprintln "Press Ctrl+C to stop..."

  -- Initialize HTTP server
  let _httpServer ← initHTTPServer app.config.port

  -- Main server loop would go here - for now, just show that we're ready
  IO.eprintln "✅ Web application server initialized and ready to accept connections"
  IO.eprintln "💡 Ready to handle requests with database integration!"

-- ==========================================
-- Monadic Route DSL (#18)
-- ==========================================
-- Allows defining routes with `do`-notation:
--
--   def myApp := webApp defaultWebAppConfig do
--     get "/" fun _ => htmlResponse "<h1>Hello</h1>"
--     get "/health" fun _ => jsonResponse "{\"ok\":true}"
--     post "/users" fun ctx => do
--       let body := ctx.request.body
--       jsonResponse "{\"created\":true}" |>.withStatus 201
--     use loggingMiddleware

/-- Route builder monad — accumulates routes and middleware into a WebAppState -/
abbrev RouteBuilder := StateM WebAppState PUnit

/-- Register a GET route -/
def get (path : String) (handler : WebAppRouteHandler) : RouteBuilder := do
  let app ← MonadState.get
  MonadState.set (addWebAppRoute app "GET" path handler)

/-- Register a POST route -/
def post (path : String) (handler : WebAppRouteHandler) : RouteBuilder := do
  let app ← MonadState.get
  MonadState.set (addWebAppRoute app "POST" path handler)

/-- Register a PUT route -/
def put (path : String) (handler : WebAppRouteHandler) : RouteBuilder := do
  let app ← MonadState.get
  MonadState.set (addWebAppRoute app "PUT" path handler)

/-- Register a DELETE route -/
def delete (path : String) (handler : WebAppRouteHandler) : RouteBuilder := do
  let app ← MonadState.get
  MonadState.set (addWebAppRoute app "DELETE" path handler)

/-- Register a PATCH route -/
def patch (path : String) (handler : WebAppRouteHandler) : RouteBuilder := do
  let app ← MonadState.get
  MonadState.set (addWebAppRoute app "PATCH" path handler)

/-- Register middleware -/
def use (mw : RequestContext → IO (Option RequestContext)) : RouteBuilder := do
  let app ← MonadState.get
  MonadState.set (addWebAppMiddleware app mw)

/-- Add a response status code override to WebAppResponseBuilder -/
def WebAppResponseBuilder.withStatus (resp : WebAppResponseBuilder) (code : UInt16) : WebAppResponseBuilder :=
  { resp with statusCode := code }

/-- Convenience alias for webAppJsonResponse (scoped to WebApp to avoid collision with Simple) -/
def WebApp.jsonResponse (data : String) : IO WebAppResponseBuilder :=
  pure (webAppJsonResponse data)

/-- Convenience alias for webAppHtmlResponse (scoped to WebApp to avoid collision with Simple) -/
def WebApp.htmlResponse (html : String) : IO WebAppResponseBuilder :=
  pure (webAppHtmlResponse html)

/-- Convenience alias for webAppErrorResponse (scoped to WebApp to avoid collision with Simple) -/
def WebApp.errorResponse (code : UInt16) (msg : String) : IO WebAppResponseBuilder :=
  pure (webAppErrorResponse code msg)

/-- Default config for simple web apps (no database) -/
def defaultWebAppConfig : WebAppConfig := {
  port := 8080
  databaseConfig := { host := "localhost", port := 5432, database := "app", username := "user", password := "" }
}

/-- Build a WebAppState from a monadic route builder -/
def webApp (config : WebAppConfig) (builder : RouteBuilder) : WebAppState :=
  let initial : WebAppState := { config := config }
  (builder.run initial).snd

end LeanServer
