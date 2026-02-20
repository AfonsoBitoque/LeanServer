import LeanServer.Server.HTTPServer

/-!
  # Distributed Tracing — Re-export Module
  W3C Trace Context propagation and request correlation.

  ## Key Types
  - `TraceContext` — W3C traceparent components

  ## Key Functions
  - `newTraceContext` — Create or propagate trace context
  - `findTraceparent` — Find traceparent header
  - `addTracingHeaders` — Add tracing headers to response
  - `generateHexId` — Generate hex identifier
  - `logRequest` — Log a completed request with timing
-/

namespace LeanServer.Tracing

/-- Create new trace context, optionally propagating from incoming traceparent -/
@[inline] def newContext (incomingTraceparent : Option String := none) : IO LeanServer.TraceContext :=
  LeanServer.newTraceContext incomingTraceparent

/-- Find traceparent from list of headers -/
@[inline] def findTraceparent (headers : List (String × String)) : Option String :=
  LeanServer.findTraceparent headers

/-- Add tracing headers to response -/
@[inline] def addHeaders (resp : LeanServer.HTTPResponse) (ctx : LeanServer.TraceContext) : LeanServer.HTTPResponse :=
  LeanServer.addTracingHeaders resp ctx

/-- Generate hex ID of specified byte length -/
@[inline] def generateId (numBytes : Nat) : IO String :=
  LeanServer.generateHexId numBytes

/-- Log a completed request -/
@[inline] def logRequest (method path proto status : String) (bodyLen connId : Nat) (clientIP : String := "?") : IO Unit :=
  LeanServer.logRequest method path proto status bodyLen connId clientIP

end LeanServer.Tracing
