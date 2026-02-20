-- LeanServer Web Framework
-- Enhanced web framework with declarative routing, path parameters,
-- HTML templates, composable middleware, and a lightweight ORM.
--
-- Building on top of WebApplication.lean's monadic DSL, this module adds:
--   1. Path parameters (/users/:id, /posts/:postId/comments/:commentId)
--   2. Route groups with shared prefixes and middleware
--   3. Simple HTML template engine with variable interpolation
--   4. Middleware composition operators (>>>), (|||), conditionals
--   5. Lightweight ORM: Model typeclass, query builder, CRUD helpers

import LeanServer.Db.Database
import LeanServer.Db.PostgreSQL
import LeanServer.Db.MySQL
import LeanServer.Protocol.HTTP2
import LeanServer.Server.HTTPServer

namespace LeanServer.Web

-- ══════════════════════════════════════════
-- §1  PATH PARAMETERS & PATTERN MATCHING
-- ══════════════════════════════════════════

/-- A single segment of a route pattern -/
inductive RouteSegment where
  | literal  : String → RouteSegment  -- exact match, e.g. "users"
  | param    : String → RouteSegment  -- captures a value, e.g. ":id"
  | wildcard : RouteSegment           -- matches everything remaining ("*")
  deriving Inhabited

/-- A parsed route pattern -/
structure RoutePattern where
  method   : String
  segments : Array RouteSegment
  deriving Inhabited

/-- Captured path parameters -/
abbrev PathParams := List (String × String)

/-- Parse a route pattern string into segments.
    - "/users/:id"       → [literal "users", param "id"]
    - "/files/*"         → [literal "files", wildcard]
    - "/api/v1/:resource/:id" → [literal "api", literal "v1", param "resource", param "id"]
-/
def parseRoutePattern (method : String) (pattern : String) : RoutePattern :=
  let parts := pattern.splitOn "/"
  let parts := parts.filter (· ≠ "")
  let segments := parts.map fun part =>
    if part == "*" then RouteSegment.wildcard
    else if part.startsWith ":" then RouteSegment.param (part.drop 1).toString
    else RouteSegment.literal part
  { method := method, segments := segments.toArray }

/-- Match a request path against a route pattern, extracting parameters -/
def matchRoute (pattern : RoutePattern) (method : String) (path : String) : Option PathParams :=
  if pattern.method ≠ method then none
  else
    let parts := (path.splitOn "/").filter (· ≠ "")
    let rec go (segIdx : Nat) (partIdx : Nat) (params : PathParams) : Option PathParams :=
      if segIdx >= pattern.segments.size then
        if partIdx >= parts.length then some params
        else none
      else if segIdx < pattern.segments.size then
        match pattern.segments[segIdx]! with
        | RouteSegment.literal s =>
          if partIdx < parts.length then
            let part := parts.toArray[partIdx]!
            if part == s then go (segIdx + 1) (partIdx + 1) params
            else none
          else none
        | RouteSegment.param name =>
          if partIdx < parts.length then
            let value := parts.toArray[partIdx]!
            go (segIdx + 1) (partIdx + 1) ((name, value) :: params)
          else none
        | RouteSegment.wildcard =>
          -- wildcard consumes everything remaining
          some params
      else none
    go 0 0 []

-- ══════════════════════════════════════════
-- §2  ENHANCED REQUEST CONTEXT
-- ══════════════════════════════════════════

/-- Request context with path parameters, query params, and metadata -/
structure Context where
  request    : HttpRequest
  pathParams : PathParams := []
  queryParams : List (String × String) := []
  locals     : List (String × String) := []   -- middleware can attach data
  pgManager  : Option (DatabaseManager PostgreSQLDriver) := none
  myManager  : Option (DatabaseManager MySQLDriver) := none
  deriving Inhabited

/-- Look up a path parameter by name -/
def Context.param (ctx : Context) (name : String) : Option String :=
  ctx.pathParams.find? (fun (k, _) => k == name) |>.map Prod.snd

/-- Look up a path parameter, with default -/
def Context.paramOr (ctx : Context) (name : String) (default : String) : String :=
  ctx.param name |>.getD default

/-- Look up a query parameter -/
def Context.query (ctx : Context) (name : String) : Option String :=
  ctx.queryParams.find? (fun (k, _) => k == name) |>.map Prod.snd

/-- Look up a local (middleware-attached) value -/
def Context.local (ctx : Context) (name : String) : Option String :=
  ctx.locals.find? (fun (k, _) => k == name) |>.map Prod.snd

/-- Set a local value (used by middleware) -/
def Context.setLocal (ctx : Context) (name : String) (value : String) : Context :=
  { ctx with locals := (name, value) :: ctx.locals }

/-- Parse query string: "key1=val1&key2=val2" → [(key1,val1), (key2,val2)] -/
def parseQueryString (qs : String) : List (String × String) :=
  let pairs := qs.splitOn "&"
  pairs.filterMap fun pair =>
    match pair.splitOn "=" with
    | [k, v] => some (k, v)
    | _ => none

/-- Extract query params from a request path like "/path?key=val" -/
def extractQueryParams (path : String) : (String × List (String × String)) :=
  match path.splitOn "?" with
  | [p, qs] => (p, parseQueryString qs)
  | _       => (path, [])

-- ══════════════════════════════════════════
-- §3  RESPONSE BUILDER
-- ══════════════════════════════════════════

/-- Response with builder pattern -/
structure Response where
  statusCode  : UInt16 := 200
  headers     : Array HeaderField := #[]
  body        : ByteArray := ByteArray.empty
  contentType : String := "text/plain"
  deriving Inhabited

def Response.ok (body : String) (contentType : String := "text/plain") : Response :=
  { statusCode := 200, body := body.toUTF8, contentType := contentType,
    headers := #[⟨"Content-Type", contentType⟩] }

def Response.html (body : String) : Response :=
  Response.ok body "text/html; charset=utf-8"

def Response.json (body : String) : Response :=
  Response.ok body "application/json"

def Response.redirect (url : String) (code : UInt16 := 302) : Response :=
  { statusCode := code, headers := #[⟨"Location", url⟩], contentType := "text/plain" }

def Response.notFound (msg : String := "Not Found") : Response :=
  { statusCode := 404, body := msg.toUTF8, contentType := "text/plain",
    headers := #[⟨"Content-Type", "text/plain"⟩] }

def Response.error (code : UInt16) (msg : String) : Response :=
  { statusCode := code, body := msg.toUTF8, contentType := "text/plain",
    headers := #[⟨"Content-Type", "text/plain"⟩] }

def Response.withHeader (r : Response) (name : String) (value : String) : Response :=
  { r with headers := r.headers.push ⟨name, value⟩ }

def Response.withStatus (r : Response) (code : UInt16) : Response :=
  { r with statusCode := code }

-- ══════════════════════════════════════════
-- §4  COMPOSABLE MIDDLEWARE
-- ══════════════════════════════════════════

/-- Middleware: transforms a Context, possibly short-circuiting with a Response -/
abbrev Middleware := Context → IO (Except Response Context)

/-- Handler: produces a Response from a Context -/
abbrev Handler := Context → IO Response

/-- Compose two middleware: first runs `a`, then `b` on success -/
def Middleware.compose (a b : Middleware) : Middleware := fun ctx => do
  match ← a ctx with
  | .ok ctx' => b ctx'
  | .error r => return .error r

/-- Infix for middleware composition -/
instance : AndThen Middleware where
  andThen a b := Middleware.compose a (b ())

/-- Run middleware only if a condition holds -/
def Middleware.when (pred : Context → Bool) (mw : Middleware) : Middleware := fun ctx =>
  if pred ctx then mw ctx else return .ok ctx

/-- Combine middleware that must ALL pass (AND semantics) -/
def Middleware.all (mws : List Middleware) : Middleware := fun ctx => do
  let mut current := ctx
  for mw in mws do
    match ← mw current with
    | .ok ctx' => current := ctx'
    | .error r => return .error r
  return .ok current

/-- Identity middleware — always passes through -/
def Middleware.identity : Middleware := fun ctx => return .ok ctx

-- ── Built-in middleware ──────────────────

/-- Logging middleware: logs method and path -/
def loggingMiddleware : Middleware := fun ctx => do
  IO.eprintln s!"[{ctx.request.method}] {ctx.request.path}"
  return .ok ctx

/-- CORS middleware with configurable origin -/
def corsMiddleware (allowOrigin : String := "*") : Middleware := fun ctx => do
  let ctx' := ctx.setLocal "cors-origin" allowOrigin
  return .ok ctx'

/-- Basic auth middleware: checks Authorization header -/
def basicAuthMiddleware (checkCredentials : String → String → IO Bool) : Middleware := fun ctx => do
  let authHeader := ctx.request.headers.find? (fun h => h.name == "Authorization")
  match authHeader with
  | some h =>
    let parts := h.value.splitOn " "
    if parts.length >= 2 then
      -- In real implementation, base64 decode "user:pass"
      let valid ← checkCredentials (parts.toArray[0]!) (parts.toArray[1]!)
      if valid then return .ok (ctx.setLocal "authenticated" "true")
      else return .error (Response.error 401 "Unauthorized")
    else return .error (Response.error 401 "Unauthorized")
  | none => return .error (Response.error 401 "Missing Authorization header")

/-- Rate limiting state: tracks request counts per window -/
structure RateLimitState where
  count     : Nat    -- requests in current window
  windowStart : Nat  -- start of current window (milliseconds)

/-- Rate limiting middleware with sliding window counter.
    Tracks requests via a shared IO.Ref and rejects with 429 when exceeded. -/
def rateLimitMiddleware (maxRequests : Nat := 100) (windowMs : Nat := 60000)
    (stateRef : IO.Ref RateLimitState) : Middleware := fun ctx => do
  let now ← IO.monoMsNow
  let state ← stateRef.get
  -- Reset counter if window has elapsed
  let state := if now - state.windowStart > windowMs then
    { count := 0, windowStart := now }
  else state
  if state.count >= maxRequests then
    let remaining := windowMs - (now - state.windowStart)
    return .error (Response.error 429 "Too Many Requests"
      |>.withHeader "Retry-After" s!"{remaining / 1000}"
      |>.withHeader "X-RateLimit-Limit" s!"{maxRequests}"
      |>.withHeader "X-RateLimit-Remaining" "0")
  else
    stateRef.set { state with count := state.count + 1 }
    return .ok (ctx.setLocal "rate-limit-remaining" s!"{maxRequests - state.count - 1}")

/-- Request ID middleware: attaches a unique request identifier -/
def requestIdMiddleware : Middleware := fun ctx => do
  -- Simple timestamp-based ID (production: UUID)
  let now ← IO.monoMsNow
  return .ok (ctx.setLocal "request-id" s!"req-{now}")

-- ══════════════════════════════════════════
-- §5  HTML TEMPLATE ENGINE
-- ══════════════════════════════════════════

/-- Template variable bindings -/
abbrev TemplateVars := List (String × String)

/-- Simple template engine with `{{variable}}` interpolation.
    Supports:
    - `{{varName}}`           — variable substitution
    - `{{#if varName}}...{{/if}}` — conditional blocks
    - `{{#each items}}...{{/each}}` — iteration (items = semicolon-separated values)
    - `{{> partialName}}`     — partial inclusion (from a partial map)

    Uses fuel parameter for guaranteed termination. Fuel = template.length
    is sufficient since each recursive call operates on a strictly shorter string. -/
def renderTemplate (template : String) (vars : TemplateVars)
    (tplPartials : List (String × String) := []) : String :=
  renderTemplateAux template vars tplPartials (template.length + 1)
where
  renderTemplateAux (template : String) (vars : TemplateVars)
      (tplPartials : List (String × String)) (fuel : Nat) : String :=
    match fuel with
    | 0 => template  -- Fuel exhausted: return remaining template as-is
    | fuel' + 1 => Id.run do
  let mut result := ""
  let mut i := 0
  let chars := template.toList.toArray
  let len := chars.size
  while i < len do
    if i + 1 < len && chars[i]! == '{' && chars[i + 1]! == '{' then
      -- Find closing }}
      let mut j := i + 2
      while j + 1 < len && ¬(chars[j]! == '}' && chars[j + 1]! == '}') do
        j := j + 1
      if j + 1 < len then
        let tag := (chars.extract (i + 2) j).toList
        let tagStr : String := ((String.ofList tag).trimAscii).toString
        if tagStr.startsWith "#if " then
          -- Conditional: {{#if varName}}...{{/if}}
          let varName : String := ((tagStr.drop 4).toString.trimAscii).toString
          let endTag := "{{/if}}"
          let remaining := String.ofList (chars.extract (j + 2) len).toList
          match remaining.splitOn endTag with
          | body :: rest =>
            let hasValue := vars.find? (fun (k, _) => k == varName) |>.isSome
            if hasValue then
              result := result ++ renderTemplateAux body vars tplPartials fuel'
            result := result ++ renderTemplateAux (String.intercalate endTag rest) vars tplPartials fuel'
            return result
          | [] =>
            result := result ++ "{{TEMPLATE_ERROR: unclosed #if}}"
            i := j + 2
        else if tagStr.startsWith "#each " then
          -- Iteration: {{#each items}}...{{/each}}
          let varName : String := ((tagStr.drop 6).toString.trimAscii).toString
          let endTag := "{{/each}}"
          let remaining := String.ofList (chars.extract (j + 2) len).toList
          match remaining.splitOn endTag with
          | body :: rest =>
            let values := match vars.find? (fun (k, _) => k == varName) with
              | some (_, v) => v.splitOn ";"
              | none => []
            for val in values do
              let itemVars := ("item", val) :: vars
              result := result ++ renderTemplateAux body itemVars tplPartials fuel'
            result := result ++ renderTemplateAux (String.intercalate endTag rest) vars tplPartials fuel'
            return result
          | [] =>
            result := result ++ "{{TEMPLATE_ERROR: unclosed #each}}"
            i := j + 2
        else if tagStr.startsWith "> " then
          -- Partial: {{> partialName}}
          let partialName : String := ((tagStr.drop 2).toString.trimAscii).toString
          match tplPartials.find? (fun (k, _) => k == partialName) with
          | some (_, partialContent) =>
            result := result ++ renderTemplateAux partialContent vars tplPartials fuel'
          | none =>
            result := result ++ "{{PARTIAL_NOT_FOUND: " ++ partialName ++ "}}"
          i := j + 2
        else
          -- Simple variable substitution
          match vars.find? (fun (k, _) => k == tagStr) with
          | some (_, v) => result := result ++ v
          | none        => result := result ++ "{{UNDEFINED: " ++ tagStr ++ "}}"
          i := j + 2
      else
        result := result.push chars[i]!
        i := i + 1
    else
      result := result.push chars[i]!
      i := i + 1
  return result

/-- Render a template and return an HTML response -/
def renderHtml (template : String) (vars : TemplateVars)
    (partials : List (String × String) := []) : Response :=
  Response.html (renderTemplate template vars partials)

/-- Common HTML page wrapper template -/
def layoutTemplate : String :=
  "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{{title}}</title>" ++
  "<style>body{font-family:system-ui,sans-serif;max-width:800px;margin:2em auto;padding:0 1em}" ++
  "h1{color:#2d3748}a{color:#3182ce}.card{border:1px solid #e2e8f0;border-radius:8px;padding:1em;margin:1em 0}" ++
  "</style>{{> head}}</head><body>{{> nav}}<main>{{content}}</main>" ++
  "<footer><p>&copy; LeanServer</p></footer></body></html>"

/-- Render content inside the layout -/
def renderPage (title : String) (content : String) (vars : TemplateVars := [])
    (partials : List (String × String) := []) : Response :=
  let allVars := [("title", title), ("content", content)] ++ vars
  let defaultPartials := [("head", ""), ("nav", "")] ++ partials
  renderHtml layoutTemplate allVars defaultPartials

-- ══════════════════════════════════════════
-- §6  LIGHTWEIGHT ORM
-- ══════════════════════════════════════════

/-- A database column definition -/
structure Column where
  name     : String
  colType  : String   -- SQL type: "TEXT", "INTEGER", "BOOLEAN", etc.
  nullable : Bool := true
  primaryKey : Bool := false
  deriving Inhabited

/-- Typeclass for types that can be stored in the database -/
class Model (α : Type) where
  tableName : String
  columns   : Array Column
  toRow     : α → Array String
  fromRow   : Array String → Option α

/-- SQL query builder -/
structure QueryBuilder where
  table      : String
  selectCols : List String := ["*"]
  conditions : List String := []
  orderBy    : Option String := none
  limitVal   : Option Nat := none
  offsetVal  : Option Nat := none
  deriving Inhabited

def QueryBuilder.from (table : String) : QueryBuilder :=
  { table := table }

def QueryBuilder.select (qb : QueryBuilder) (cols : List String) : QueryBuilder :=
  { qb with selectCols := cols }

def QueryBuilder.where_ (qb : QueryBuilder) (cond : String) : QueryBuilder :=
  { qb with conditions := qb.conditions ++ [cond] }

def QueryBuilder.orderByAsc (qb : QueryBuilder) (col : String) : QueryBuilder :=
  { qb with orderBy := some s!"{col} ASC" }

def QueryBuilder.orderByDesc (qb : QueryBuilder) (col : String) : QueryBuilder :=
  { qb with orderBy := some s!"{col} DESC" }

def QueryBuilder.limit (qb : QueryBuilder) (n : Nat) : QueryBuilder :=
  { qb with limitVal := some n }

def QueryBuilder.offset (qb : QueryBuilder) (n : Nat) : QueryBuilder :=
  { qb with offsetVal := some n }

/-- Build the final SQL SELECT string -/
def QueryBuilder.toSQL (qb : QueryBuilder) : String := Id.run do
  let cols := String.intercalate ", " qb.selectCols
  let mut sql := s!"SELECT {cols} FROM {qb.table}"
  if qb.conditions.length > 0 then
    let conds := String.intercalate " AND " qb.conditions
    sql := sql ++ s!" WHERE {conds}"
  match qb.orderBy with
  | some ob => sql := sql ++ s!" ORDER BY {ob}"
  | none    => pure ()
  match qb.limitVal with
  | some n  => sql := sql ++ s!" LIMIT {n}"
  | none    => pure ()
  match qb.offsetVal with
  | some n  => sql := sql ++ s!" OFFSET {n}"
  | none    => pure ()
  return sql

/-- Generate INSERT SQL for a model instance -/
def insertSQL [Model α] (obj : α) : String :=
  let cols := (Model.columns (α := α)).map (·.name)
  let vals := (Model.toRow obj).map (fun v => s!"'{v}'")
  let colStr := String.intercalate ", " cols.toList
  let valStr := String.intercalate ", " vals.toList
  s!"INSERT INTO {Model.tableName (α := α)} ({colStr}) VALUES ({valStr})"

/-- Generate UPDATE SQL for a model instance by primary key -/
def updateSQL [Model α] (obj : α) : String := Id.run do
  let cols := Model.columns (α := α)
  let vals := Model.toRow obj
  let mut setClauses : List String := []
  let mut whereClause := ""
  for i in List.range cols.size do
    if i < cols.size && i < vals.size then
      let col := cols[i]!
      let val := vals[i]!
      if col.primaryKey then
        whereClause := s!"{col.name} = '{val}'"
      else
        setClauses := setClauses ++ [s!"{col.name} = '{val}'"]
  let setStr := String.intercalate ", " setClauses
  return s!"UPDATE {Model.tableName (α := α)} SET {setStr} WHERE {whereClause}"

/-- Generate DELETE SQL by primary key value -/
def deleteSQL [Model α] (_dummy : α) (pkValue : String) : String :=
  let cols := Model.columns (α := α)
  match cols.toList.find? (·.primaryKey) with
  | some pk => s!"DELETE FROM {Model.tableName (α := α)} WHERE {pk.name} = '{pkValue}'"
  | none    => s!"DELETE FROM {Model.tableName (α := α)} WHERE id = '{pkValue}'"

/-- Generate CREATE TABLE SQL from a Model definition -/
def createTableSQL (α : Type) [Model α] : String :=
  let cols := Model.columns (α := α)
  let colDefs := cols.map fun c =>
    let nullStr := if c.nullable then "" else " NOT NULL"
    let pkStr := if c.primaryKey then " PRIMARY KEY" else ""
    s!"{c.name} {c.colType}{nullStr}{pkStr}"
  let colStr := String.intercalate ", " colDefs.toList
  s!"CREATE TABLE IF NOT EXISTS {Model.tableName (α := α)} ({colStr})"

-- ══════════════════════════════════════════
-- §7  ROUTER
-- ══════════════════════════════════════════

/-- A registered route entry -/
structure RouteEntry where
  pattern    : RoutePattern
  handler    : Handler
  middleware : List Middleware := []
  deriving Inhabited

/-- Router state -/
structure Router where
  routes          : Array RouteEntry := #[]
  globalMiddleware : List Middleware := []
  pathPrefix      : String := ""
  errHandler      : Option (UInt16 → String → Handler) := none
  deriving Inhabited

/-- Create a new router -/
def Router.new : Router := {}

/-- Add a route with a specific method -/
def Router.addRoute (r : Router) (method : String) (path : String)
    (handler : Handler) (mw : List Middleware := []) : Router :=
  let fullPath := if r.pathPrefix == "" then path else r.pathPrefix ++ path
  let entry : RouteEntry := {
    pattern := parseRoutePattern method fullPath
    handler := handler
    middleware := mw
  }
  { r with routes := r.routes.push entry }

/-- Convenience: GET route -/
def Router.get (r : Router) (path : String) (handler : Handler)
    (mw : List Middleware := []) : Router :=
  r.addRoute "GET" path handler mw

/-- Convenience: POST route -/
def Router.post (r : Router) (path : String) (handler : Handler)
    (mw : List Middleware := []) : Router :=
  r.addRoute "POST" path handler mw

/-- Convenience: PUT route -/
def Router.put (r : Router) (path : String) (handler : Handler)
    (mw : List Middleware := []) : Router :=
  r.addRoute "PUT" path handler mw

/-- Convenience: DELETE route -/
def Router.delete (r : Router) (path : String) (handler : Handler)
    (mw : List Middleware := []) : Router :=
  r.addRoute "DELETE" path handler mw

/-- Convenience: PATCH route -/
def Router.patch (r : Router) (path : String) (handler : Handler)
    (mw : List Middleware := []) : Router :=
  r.addRoute "PATCH" path handler mw

/-- Add global middleware -/
def Router.use (r : Router) (mw : Middleware) : Router :=
  { r with globalMiddleware := r.globalMiddleware ++ [mw] }

/-- Create a sub-router with a path prefix and optional shared middleware -/
def Router.group (r : Router) (pfx : String) (mw : List Middleware := [])
    (builder : Router → Router) : Router :=
  let subRouter : Router := { pathPrefix := r.pathPrefix ++ pfx, globalMiddleware := mw }
  let built := builder subRouter
  -- Merge sub-routes into parent, combining middleware
  let mergedRoutes := built.routes.map fun entry =>
    { entry with middleware := mw ++ entry.middleware }
  { r with routes := r.routes ++ mergedRoutes }

/-- Set a custom error handler -/
def Router.withErrorHandler (r : Router) (handler : UInt16 → String → Handler) : Router :=
  { r with errHandler := some handler }

/-- Dispatch a request to the matching route -/
def Router.dispatch (r : Router) (request : HttpRequest)
    (pgMgr : Option (DatabaseManager PostgreSQLDriver) := none)
    (myMgr : Option (DatabaseManager MySQLDriver) := none) : IO Response := do
  -- Separate path from query string
  let (cleanPath, queryParams) := extractQueryParams request.path
  -- Build base context
  let ctx : Context := {
    request := request
    queryParams := queryParams
    pgManager := pgMgr
    myManager := myMgr
  }
  -- Apply global middleware
  let globalMw := Middleware.all r.globalMiddleware
  let ctxResult ← globalMw ctx
  match ctxResult with
  | .error resp => return resp
  | .ok ctx' =>
    -- Find matching route
    for entry in r.routes do
      match matchRoute entry.pattern request.method cleanPath with
      | some params =>
        let routeCtx := { ctx' with pathParams := params }
        -- Apply route-specific middleware
        let routeMw := Middleware.all entry.middleware
        match ← routeMw routeCtx with
        | .ok finalCtx => return ← entry.handler finalCtx
        | .error resp  => return resp
      | none => pure ()
    -- No route matched
    match r.errHandler with
    | some eh => return ← eh 404 s!"Not Found: {request.method} {cleanPath}" ctx'
    | none    => return Response.notFound s!"No route matches {request.method} {cleanPath}"

-- ══════════════════════════════════════════
-- §8  ROUTE BUILDER DSL (Monadic)
-- ══════════════════════════════════════════

/-- Route builder monad — accumulates routes into a Router -/
abbrev RouteM := StateM Router PUnit

/-- Register a GET route in the builder -/
def routeGet (path : String) (handler : Handler) : RouteM := do
  modify fun r => r.get path handler

/-- Register a POST route in the builder -/
def routePost (path : String) (handler : Handler) : RouteM := do
  modify fun r => r.post path handler

/-- Register a PUT route in the builder -/
def routePut (path : String) (handler : Handler) : RouteM := do
  modify fun r => r.put path handler

/-- Register a DELETE route in the builder -/
def routeDelete (path : String) (handler : Handler) : RouteM := do
  modify fun r => r.delete path handler

/-- Use middleware in the builder -/
def routeUse (mw : Middleware) : RouteM := do
  modify fun r => r.use mw

/-- Define a route group in the builder -/
def routeGroup (pfx : String) (mw : List Middleware := [])
    (builder : RouteM) : RouteM := do
  modify fun r => r.group pfx mw (fun sub =>
    let (_, sub') := builder.run sub
    sub')

/-- Build a Router from the monadic builder -/
def buildRouter (builder : RouteM) : Router :=
  let (_, router) := builder.run Router.new
  router

-- ══════════════════════════════════════════
-- §9  EXAMPLE: Putting it all together
-- ══════════════════════════════════════════
-- Usage example (not executed, for documentation):
--
-- def myRouter : Router := buildRouter do
--   routeUse loggingMiddleware
--   routeUse requestIdMiddleware
--
--   routeGet "/" fun _ctx =>
--     return renderPage "Home" "<h1>Welcome to LeanServer</h1>"
--
--   routeGet "/health" fun _ctx =>
--     return Response.json "{\"status\":\"ok\"}"
--
--   -- Path parameters
--   routeGet "/users/:id" fun ctx => do
--     let userId := ctx.paramOr "id" "unknown"
--     return Response.json s!"\{\"user\":\"{userId}\"}"
--
--   -- Route group with shared prefix and middleware
--   routeGroup "/api/v1" [corsMiddleware] do
--     routeGet "/items" fun _ctx =>
--       return Response.json "[]"
--     routePost "/items" fun ctx => do
--       let _body := ctx.request.body
--       return (Response.json "{\"created\":true}").withStatus 201
--     routeDelete "/items/:id" fun ctx => do
--       let itemId := ctx.paramOr "id" "0"
--       return Response.json s!"\{\"deleted\":\"{itemId}\"}"
--
-- ORM example:
--
-- structure User where
--   id    : String
--   name  : String
--   email : String
--
-- instance : Model User where
--   tableName := "users"
--   columns := #[
--     { name := "id",    colType := "SERIAL",   primaryKey := true, nullable := false },
--     { name := "name",  colType := "TEXT",     nullable := false },
--     { name := "email", colType := "TEXT",     nullable := false }
--   ]
--   toRow u := #[u.id, u.name, u.email]
--   fromRow r := if r.size >= 3 then some { id := r[0]!, name := r[1]!, email := r[2]! } else none

end LeanServer.Web
