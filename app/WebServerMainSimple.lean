-- Minimal Web Server with Sockets
import Init.System.IO

-- FFI declarations
-- Winsock init/cleanup: no-ops on Linux (pure Lean)
def wsInit : IO Unit := pure ()
def wsCleanup : IO UInt32 := pure 0

@[extern "lean_socket_create"]
opaque socketCreate (proto : UInt32) : IO UInt64

@[extern "lean_closesocket"]
opaque socketClose (sock : UInt64) : IO Unit

@[extern "lean_bind"]
opaque socketBind (sock : UInt64) (port : UInt32) : IO Unit

@[extern "lean_listen"]
opaque socketListen (sock : UInt64) (backlog : UInt32) : IO Unit

@[extern "lean_accept"]
opaque socketAccept (sock : UInt64) : IO UInt64

@[extern "lean_recv"]
opaque socketRecv (sock : UInt64) (buf : @& ByteArray) (len : UInt32) (flags : UInt32) : IO UInt32

@[extern "lean_send"]
opaque socketSend (sock : UInt64) (buf : @& ByteArray) (len : UInt32) (flags : UInt32) : IO UInt32

-- Refinement Types for HTTP Safety
/-- HTTP Methods that are valid - guaranteed at compile time -/
inductive HttpMethod where
  | GET
  | POST
  | PUT
  | DELETE
  | HEAD
  | OPTIONS
  | PATCH
  deriving Repr, BEq

instance : ToString HttpMethod where
  toString m := match m with
    | HttpMethod.GET => "GET"
    | HttpMethod.POST => "POST"
    | HttpMethod.PUT => "PUT"
    | HttpMethod.DELETE => "DELETE"
    | HttpMethod.HEAD => "HEAD"
    | HttpMethod.OPTIONS => "OPTIONS"
    | HttpMethod.PATCH => "PATCH"

/-- Valid HTTP path - guaranteed to start with '/' and not contain invalid characters -/
structure ValidHttpPath where
  val : String
  startsWithSlash : val.startsWith "/"
  noInvalidChars : ∀ c ∈ val.toList, c ≠ '\x00' ∧ c ≠ '\r' ∧ c ≠ '\n'
  deriving Repr

/-- Valid HTTP header name - guaranteed to be non-empty and contain only valid characters -/
structure ValidHeaderName where
  val : String
  nonEmpty : val.length > 0
  validChars : ∀ c ∈ val.toList, (c.isAlphanum ∨ c ∈ "-_".toList)
  deriving Repr

/-- Valid HTTP header value - guaranteed to not contain control characters -/
structure ValidHeaderValue where
  val : String
  noControlChars : ∀ c ∈ val.toList, c.val ≥ 32 ∨ c = '\t'  -- ASCII 32 is space, tab is allowed
  deriving Repr

-- Type-safe HTTP structures using refinement types
structure SafeWebHttpRequest where
  method : HttpMethod
  path : ValidHttpPath
  headers : List (ValidHeaderName × ValidHeaderValue) := []
  body : String := ""

structure SafeWebHttpResponse where
  statusCode : { n : Nat // 100 ≤ n ∧ n < 600 }  -- Valid HTTP status codes
  headers : List (ValidHeaderName × ValidHeaderValue) := []
  body : String := ""

-- Legacy structures for backward compatibility (will be phased out)
structure WebHttpRequest where
  method : String
  path : String
  headers : List (String × String) := []
  body : String := ""

structure WebHttpResponse where
  statusCode : Nat
  headers : List (String × String) := []
  body : String := ""

-- Safe constructors for refinement types
def mkValidHttpPath (s : String) : Option ValidHttpPath :=
  if h1 : s.startsWith "/" ∧ ∀ c ∈ s.toList, c ≠ '\x00' ∧ c ≠ '\r' ∧ c ≠ '\n' then
    some {
      val := s
      startsWithSlash := h1.left
      noInvalidChars := h1.right
    }
  else none

def mkValidHeaderName (s : String) : Option ValidHeaderName :=
  if h1 : s.length > 0 ∧ ∀ c ∈ s.toList, (c.isAlphanum ∨ c ∈ "-_".toList) then
    some {
      val := s
      nonEmpty := h1.left
      validChars := h1.right
    }
  else none

def mkValidHeaderValue (s : String) : Option ValidHeaderValue :=
  if h1 : ∀ c ∈ s.toList, c.val ≥ 32 ∨ c = '\t' then
    some {
      val := s
      noControlChars := h1
    }
  else none

def parseHttpMethod (s : String) : Option HttpMethod :=
  if s = "GET" then some HttpMethod.GET
  else if s = "POST" then some HttpMethod.POST
  else if s = "PUT" then some HttpMethod.PUT
  else if s = "DELETE" then some HttpMethod.DELETE
  else if s = "HEAD" then some HttpMethod.HEAD
  else if s = "OPTIONS" then some HttpMethod.OPTIONS
  else if s = "PATCH" then some HttpMethod.PATCH
  else none

-- Safe HTTP request parsing with compile-time guarantees
def parseSafeHttpRequest (data : String) : Option SafeWebHttpRequest :=
  let lines := data.splitOn "\r\n"
  if lines.isEmpty then none else

  -- Parse request line safely
  let requestLine := lines[0]!
  let parts := requestLine.splitOn " "
  if parts.length < 2 then none else

  let methodStr := parts[0]!
  let pathStr := parts[1]!

  -- Validate method and path at parse time
  match parseHttpMethod methodStr, mkValidHttpPath pathStr with
  | some method, some path =>
    some {
      method := method
      path := path
      headers := []  -- Headers parsing can be added later
      body := ""
    }
  | _, _ => none

-- Safe response constructor
def mkSafeResponse (status : { n : Nat // 100 ≤ n ∧ n < 600 }) (body : String) : SafeWebHttpResponse :=
  { statusCode := status, body := body }

-- Type-safe handlers using refinement types
def safeHealthCheckHandler (_request : SafeWebHttpRequest) : SafeWebHttpResponse :=
  let status : { n : Nat // 100 ≤ n ∧ n < 600 } := ⟨200, by decide⟩
  mkSafeResponse status "{\"status\": \"healthy\", \"timestamp\": \"2026-01-27\", \"server\": \"LeanServer\", \"safe\": true}"

def safeRootHandler (_request : SafeWebHttpRequest) : SafeWebHttpResponse :=
  let status : { n : Nat // 100 ≤ n ∧ n < 600 } := ⟨200, by decide⟩
  mkSafeResponse status "<h1>🔒 Safe LeanServer!</h1><p>This response is guaranteed safe by Lean types.</p><p>Try: <a href='/health'>/health</a> | <a href='/api/users'>/api/users</a></p>"

def safeUsersHandler (_request : SafeWebHttpRequest) : SafeWebHttpResponse :=
  let status : { n : Nat // 100 ≤ n ∧ n < 600 } := ⟨200, by decide⟩
  mkSafeResponse status "[{\"id\": 1, \"name\": \"Alice\"}, {\"id\": 2, \"name\": \"Bob\"}, {\"id\": 3, \"name\": \"Charlie\"}]"

-- Convert safe response to legacy format for compatibility
def safeResponseToLegacy (safe : SafeWebHttpResponse) : WebHttpResponse :=
  {
    statusCode := safe.statusCode.val
    headers := safe.headers.map (fun (name, value) => (name.val, value.val))
    body := safe.body
  }

-- Safe web request handler with compile-time guarantees
def handleSafeWebRequest (request : SafeWebHttpRequest) : SafeWebHttpResponse :=
  -- Simple routing based on path only for now (methods are guaranteed safe)
  if request.path.val = "/" then
    safeRootHandler request
  else if request.path.val = "/health" then
    safeHealthCheckHandler request
  else if request.path.val = "/api/users" then
    safeUsersHandler request
  else
    let status : { n : Nat // 100 ≤ n ∧ n < 600 } := ⟨404, by decide⟩
    mkSafeResponse status "{\"error\": \"Safe route not found\"}"

-- Simple handlers
def healthCheckHandler (_request : WebHttpRequest) : WebHttpResponse :=
  {
    statusCode := 200
    headers := [("Content-Type", "application/json")]
    body := "{\"status\": \"healthy\", \"timestamp\": \"2026-01-27\", \"server\": \"LeanServer\"}"
  }

def usersHandler (_request : WebHttpRequest) : WebHttpResponse :=
  {
    statusCode := 200
    headers := [("Content-Type", "application/json")]
    body := "[{\"id\": 1, \"name\": \"Alice\"}, {\"id\": 2, \"name\": \"Bob\"}, {\"id\": 3, \"name\": \"Charlie\"}]"
  }

def userByIdHandler (request : WebHttpRequest) : WebHttpResponse :=
  -- Simple path parameter extraction
  let pathParts := request.path.splitOn "/"
  if pathParts.length >= 4 && pathParts[3]! == "123" then
    {
      statusCode := 200
      headers := [("Content-Type", "application/json")]
      body := "{\"id\": 123, \"name\": \"Alice\", \"email\": \"alice@example.com\"}"
    }
  else
    {
      statusCode := 404
      headers := [("Content-Type", "application/json")]
      body := "{\"error\": \"User not found\"}"
    }

def createUserHandler (_request : WebHttpRequest) : WebHttpResponse :=
  -- For now, just return a success response (in a real app, we'd parse the request body)
  {
    statusCode := 201
    headers := [("Content-Type", "application/json")]
    body := "{\"id\": 4, \"name\": \"New User\", \"email\": \"new@example.com\", \"message\": \"User created successfully\"}"
  }

def rootHandler (_request : WebHttpRequest) : WebHttpResponse :=
  {
    statusCode := 200
    headers := [("Content-Type", "text/html")]
    body := "<h1>Hello from LeanServer!</h1><p>This is a working web application with real HTTP connections.</p><p>Try: <a href='/health'>/health</a> | <a href='/api/users'>/api/users</a> | <a href='/api/users/123'>/api/users/123</a></p>"
  }

-- Web Application
structure WebApplication where
  routes : List (String × String × (WebHttpRequest → WebHttpResponse)) := []

def initWebApplication : IO WebApplication := do
  IO.println "🚀 Initializing Web Application"
  return { routes := [] }

def addRoute (app : WebApplication) (method : String) (path : String) (handler : WebHttpRequest → WebHttpResponse) : WebApplication :=
  { app with routes := (method, path, handler) :: app.routes }

def handleWebRequest (app : WebApplication) (request : WebHttpRequest) : WebHttpResponse :=
  match app.routes.find? (fun (method, path, _) => method == request.method && path == request.path) with
  | some (_, _, handler) => handler request
  | none => {
      statusCode := 404
      headers := [("Content-Type", "text/plain")]
      body := "Route not found: " ++ request.method ++ " " ++ request.path
    }

-- Convert WebHttpResponse to raw HTTP response string
def httpResponseToString (response : WebHttpResponse) : String :=
  let statusText := match response.statusCode with
  | 200 => "OK"
  | 201 => "Created"
  | 400 => "Bad Request"
  | 404 => "Not Found"
  | 500 => "Internal Server Error"
  | _ => "Unknown"

  let statusLine := "HTTP/1.1 " ++ toString response.statusCode ++ " " ++ statusText ++ "\r\n"

  let headerLines := response.headers.map (fun (key, value) => key ++ ": " ++ value ++ "\r\n")
  let headersStr := String.join headerLines

  let contentLength := "Content-Length: " ++ toString response.body.length ++ "\r\n"

  statusLine ++ headersStr ++ contentLength ++ "\r\n" ++ response.body

-- Parse HTTP request from raw string
def parseHttpRequest (data : String) : Option WebHttpRequest :=
  let lines := data.splitOn "\r\n"
  if lines.isEmpty then
    none
  else
    -- Parse request line (e.g., "GET /health HTTP/1.1")
    let requestLine := lines[0]!
    let parts := requestLine.splitOn " "
    if parts.length >= 2 then
      let method := parts[0]!
      let path := parts[1]!
      some {
        method := method
        path := path
        headers := []  -- Simplified, not parsing headers
        body := ""     -- Simplified, not parsing body
      }
    else
      none

-- Simple connection handler
def handleConnection (clientSock : UInt64) (app : WebApplication) : IO Unit := do
  -- Create buffer for receiving data
  let bufSize : UInt32 := 1024
  let buf := ByteArray.mk (List.replicate bufSize.toNat (0 : UInt8)).toArray

  -- Receive HTTP request
  let recvRes ← socketRecv clientSock buf bufSize 0

  if recvRes > 0 then
    -- Extract received data
    let receivedData := buf.extract 0 recvRes.toNat
    let requestStr := String.fromUTF8! receivedData

    IO.println ("📩 Received request (" ++ toString recvRes ++ " bytes)")

    -- Try safe parsing first (compile-time guarantees)
    match parseSafeHttpRequest requestStr with
    | some safeRequest =>
      IO.println ("🔒 Safe parsed request: " ++ toString safeRequest.method ++ " " ++ safeRequest.path.val)

      -- Handle with safe handlers
      let safeResponse := handleSafeWebRequest safeRequest
      let response := safeResponseToLegacy safeResponse
      let responseStr := httpResponseToString response
      let responseBytes := String.toUTF8 responseStr

      -- Send HTTP response
      let sendRes ← socketSend clientSock responseBytes responseBytes.size.toUInt32 0
      IO.println ("📤 Sent SAFE response (" ++ toString sendRes ++ " bytes) - Status: " ++ toString response.statusCode)

    | none =>
      -- Fallback to legacy parsing
      IO.println "⚠️ Safe parsing failed, trying legacy parsing..."
      match parseHttpRequest requestStr with
      | some parsedRequest =>
        IO.println ("🔍 Legacy parsed request: " ++ parsedRequest.method ++ " " ++ parsedRequest.path)

        -- Handle request through web application framework
        let response := handleWebRequest app parsedRequest
        let responseStr := httpResponseToString response
        let responseBytes := String.toUTF8 responseStr

        -- Send HTTP response
        let sendRes ← socketSend clientSock responseBytes responseBytes.size.toUInt32 0
        IO.println ("📤 Sent legacy response (" ++ toString sendRes ++ " bytes) - Status: " ++ toString response.statusCode)
      | none =>
        IO.println "❌ Failed to parse HTTP request with both safe and legacy parsers"
        -- Send 400 Bad Request
        let errorResponse := "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 15\r\n\r\nBad Request"
        let errorBytes := String.toUTF8 errorResponse
        let _ ← socketSend clientSock errorBytes errorBytes.size.toUInt32 0
  else
    IO.println "⚠️ Receive failed"

  -- Close client socket
  let _ ← socketClose clientSock

-- Accept connections loop
partial def acceptLoop (serverSock : UInt64) (app : WebApplication) : IO Unit := do
  let clientSock ← socketAccept serverSock
  if clientSock != (0-1 : UInt64) then
    IO.println ("✨ Connection accepted (Socket: " ++ toString clientSock ++ ")")

    -- Handle the client connection
    handleConnection clientSock app

    -- Continue accepting connections
    acceptLoop serverSock app
  else
    -- Small delay to prevent busy waiting
    IO.sleep 100  -- 100ms
    -- Continue accepting connections
    acceptLoop serverSock app

-- Main function
def main : IO Unit := do
  IO.println "🚀 Starting LeanServer Web Application Server"
  IO.println "Features: Type-safe routing, REST API framework"
  IO.println ""

  -- Initialize Winsock
  wsInit
  IO.println "✅ Winsock initialized"

  let app ← initWebApplication
  let app := addRoute app "GET" "/health" healthCheckHandler
  let app := addRoute app "GET" "/" rootHandler
  let app := addRoute app "GET" "/api/users" usersHandler
  let app := addRoute app "GET" "/api/users/123" userByIdHandler
  let app := addRoute app "POST" "/api/users" createUserHandler

  -- Create socket
  let serverSock ← socketCreate 0
  if serverSock == (0-1 : UInt64) then
    IO.println "❌ Socket creation failed"
    let _ ← wsCleanup
    return

  IO.println ("✅ Socket created: " ++ toString serverSock)

  -- Bind to port 8081
  try
    socketBind serverSock 8081
  catch _ =>
    IO.println "❌ Bind failed"
    let _ ← socketClose serverSock
    let _ ← wsCleanup
    return

  IO.println "✅ Bound to port 8081"

  -- Listen
  try
    socketListen serverSock 10
  catch _ =>
    IO.println "❌ Listen failed"
    let _ ← socketClose serverSock
    let _ ← wsCleanup
    return

  IO.println "✅ Listening on port 8081..."
  IO.println "📊 Routes configured"
  IO.println "🌐 Ready to accept HTTP connections"
  IO.println "Test with: curl http://localhost:8081/"
  IO.println "Press Ctrl+C to stop..."
  IO.println ""

  -- Start accepting connections
  acceptLoop serverSock app

  -- Cleanup
  let _ ← socketClose serverSock
  let _ ← wsCleanup
  IO.println "Web server stopped"
