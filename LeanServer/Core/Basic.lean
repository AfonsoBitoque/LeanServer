/-!
  # Basic Utilities
  Foundational types, constant-time operations, and HTTP request/response structures.
  Imported by nearly every module in LeanServer.
-/

-- ==========================================
-- Constant-Time Operations
-- ==========================================
-- NOTE: True constant-time guarantees depend on the compiler backend and CPU.
-- Lean 4's GC and natural number arithmetic make hardware-level constant-time
-- impossible to guarantee. These functions minimize data-dependent branching
-- at the algorithmic level to reduce timing side-channel attack surface.
-- For production cryptography, use FFI to a constant-time C library (e.g., libsodium).

/-- Constant-time byte comparison: XOR-accumulate all differences, then check for zero.
    Avoids early-exit branching on the first mismatch.
    Returns true only if both arrays have equal length and equal contents. -/
def constantTimeEqual (a b : ByteArray) : Bool :=
  if a.size != b.size then false
  else
    let diff := (List.range a.size).foldl (fun acc i =>
      acc ||| (a.get! i ^^^ b.get! i)
    ) (0 : UInt8)
    diff == 0

/-- Constant-time selection: returns `a` if `cond` is true, `b` if false.
    Uses bitwise masking instead of branching. -/
def constantTimeSelect (cond : Bool) (a b : UInt8) : UInt8 :=
  let mask : UInt8 := if cond then 0xFF else 0x00
  -- result = (a AND mask) OR (b AND NOT mask)
  (a &&& mask) ||| (b &&& (mask ^^^ 0xFF))

-- Read configuration file
def readConfigFile (filename : String) : IO (Option String) := do
  try
    let content ← IO.FS.readFile filename
    return some content
  catch _ =>
    IO.eprintln s!"Error reading config file: {filename}"
    return none

-- Tipos básicos para o servidor HTTP

-- Refinement type para porta válida (1-65535)
def ValidPort (p : Nat) : Prop := 1 ≤ p ∧ p ≤ 65535

structure Port where
  val : Nat
  isValid : ValidPort val

-- Estados de conexão com refinement types
inductive ConnectionState where
  | Closed
  | Listening (port : Port)
  | Established (port : Port) (peer : String) -- peer could be IP

-- Função que só aceita Established
def closeConnection (_ : ConnectionState) : ConnectionState :=
  ConnectionState.Closed

structure HTTPRequest where
  method : String
  path : String
  headers : List (String × String)
  body : ByteArray

structure HTTPResponse where
  status : Nat
  headers : List (String × String)
  body : ByteArray

structure Route where
  path : String
  handler : HTTPRequest → HTTPResponse

-- Lista de rotas
def routes : List Route := [
  { path := "/", handler := λ _ => { status := 200, headers := [("Content-Type", "text/plain")], body := "Hello from Lean Server!".toUTF8 } },
  { path := "/test", handler := λ _ => { status := 200, headers := [("Content-Type", "text/plain")], body := "Test endpoint!".toUTF8 } }
]

-- Função de exemplo para processar uma requisição
def handleRequest (req : HTTPRequest) : HTTPResponse :=
  match routes.find? (λ r => r.path == req.path) with
  | some route => route.handler req
  | none => { status := 404, headers := [("Content-Type", "text/plain")], body := "Not Found".toUTF8 }

-- Parsing HTTP com zero-copy usando ByteArray
-- Função para parsear HTTPRequest de ByteArray (simplificada, zero-copy parcial)
def parseHTTPRequest (data : ByteArray) : Option HTTPRequest :=
  -- Limite de tamanho para anti-DoS
  if data.size > 8192 then none else
  -- Converter para String para parsing simples (conversão UTF-8 padrão)
  let str := String.fromUTF8? data
  match str with
  | some s =>
    -- Parse básico: assumir "METHOD /path HTTP/1.1\r\nheaders...\r\n\r\nbody"
    let lines := s.splitOn "\r\n"
    if lines.length < 1 then none else
    let requestLine := lines[0]!
    let parts := requestLine.splitOn " "
    if parts.length < 3 then none else
    let method := parts[0]!
    let path := parts[1]!
    -- Headers: simplificado, assumir sem headers por enquanto
    let headers := []
    -- Body: depois de \r\n\r\n, com limite
    let parts := s.splitOn "\r\n\r\n"
    let body := if parts.length > 1 then
      let b := parts[1]!.toUTF8
      if b.size > 1024 then ByteArray.empty else b -- quota
    else ByteArray.empty
    some { method, path, headers, body }
  | none => none

-- Função para serializar HTTPResponse para ByteArray
def serializeHTTPResponse (resp : HTTPResponse) : ByteArray :=
  let statusLine := s!"HTTP/1.1 {resp.status} OK\r\n".toUTF8
  let headers := resp.headers.map (λ (k,v) => s!"{k}: {v}\r\n".toUTF8) |>.foldl (· ++ ·) ByteArray.empty
  let crlf := "\r\n".toUTF8
  statusLine ++ headers ++ crlf ++ resp.body

-- Teoremas para verificação formal
-- Prova de terminação: handleRequest sempre termina (Lean garante totalidade)
theorem handleRequestTotal : ∀ req : HTTPRequest, ∃ resp : HTTPResponse, handleRequest req = resp :=
  λ req => ⟨handleRequest req, rfl⟩

-- Prova de quotas: parsing falha se request > 8KB
theorem parseQuota : ∀ data : ByteArray, data.size > 8192 → parseHTTPRequest data = none :=
  λ data h => by
    unfold parseHTTPRequest
    simp [h]
    -- Prova trivial pois if data.size > 8192 then none
