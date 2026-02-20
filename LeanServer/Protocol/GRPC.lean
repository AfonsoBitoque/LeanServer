-- gRPC Protocol Implementation
-- Based on gRPC over HTTP/2 specification

import LeanServer.Core.Basic
import LeanServer.Protocol.HTTP2
import LeanServer.Protocol.HPACK

namespace LeanServer

-- gRPC Message Types
inductive GRPCMessageType where
  | REQUEST : GRPCMessageType
  | RESPONSE : GRPCMessageType
  | ERROR : GRPCMessageType
  deriving Repr, BEq

instance : ToString GRPCMessageType where
  toString := fun
    | .REQUEST => "REQUEST"
    | .RESPONSE => "RESPONSE"
    | .ERROR => "ERROR"

-- gRPC Status Codes (based on gRPC specification)
inductive GRPCStatus where
  | OK : GRPCStatus
  | CANCELLED : GRPCStatus
  | UNKNOWN : GRPCStatus
  | INVALID_ARGUMENT : GRPCStatus
  | DEADLINE_EXCEEDED : GRPCStatus
  | NOT_FOUND : GRPCStatus
  | ALREADY_EXISTS : GRPCStatus
  | PERMISSION_DENIED : GRPCStatus
  | RESOURCE_EXHAUSTED : GRPCStatus
  | FAILED_PRECONDITION : GRPCStatus
  | ABORTED : GRPCStatus
  | OUT_OF_RANGE : GRPCStatus
  | UNIMPLEMENTED : GRPCStatus
  | INTERNAL : GRPCStatus
  | UNAVAILABLE : GRPCStatus
  | DATA_LOSS : GRPCStatus
  | UNAUTHENTICATED : GRPCStatus
  deriving Repr, BEq

instance : ToString GRPCStatus where
  toString := fun
    | .OK => "OK"
    | .CANCELLED => "CANCELLED"
    | .UNKNOWN => "UNKNOWN"
    | .INVALID_ARGUMENT => "INVALID_ARGUMENT"
    | .DEADLINE_EXCEEDED => "DEADLINE_EXCEEDED"
    | .NOT_FOUND => "NOT_FOUND"
    | .ALREADY_EXISTS => "ALREADY_EXISTS"
    | .PERMISSION_DENIED => "PERMISSION_DENIED"
    | .RESOURCE_EXHAUSTED => "RESOURCE_EXHAUSTED"
    | .FAILED_PRECONDITION => "FAILED_PRECONDITION"
    | .ABORTED => "ABORTED"
    | .OUT_OF_RANGE => "OUT_OF_RANGE"
    | .UNIMPLEMENTED => "UNIMPLEMENTED"
    | .INTERNAL => "INTERNAL"
    | .UNAVAILABLE => "UNAVAILABLE"
    | .DATA_LOSS => "DATA_LOSS"
    | .UNAUTHENTICATED => "UNAUTHENTICATED"

-- Convert GRPCStatus to integer code
def GRPCStatus.toCode (status : GRPCStatus) : UInt32 :=
  match status with
  | OK => 0
  | CANCELLED => 1
  | UNKNOWN => 2
  | INVALID_ARGUMENT => 3
  | DEADLINE_EXCEEDED => 4
  | NOT_FOUND => 5
  | ALREADY_EXISTS => 6
  | PERMISSION_DENIED => 7
  | RESOURCE_EXHAUSTED => 8
  | FAILED_PRECONDITION => 9
  | ABORTED => 10
  | OUT_OF_RANGE => 11
  | UNIMPLEMENTED => 12
  | INTERNAL => 13
  | UNAVAILABLE => 14
  | DATA_LOSS => 15
  | UNAUTHENTICATED => 16

-- gRPC Message structure
structure GRPCMessage where
  messageType : GRPCMessageType
  payload : ByteArray
  compressed : Bool

instance : Inhabited GRPCMessage where
  default := {
    messageType := .REQUEST
    payload := ByteArray.empty
    compressed := false
  }

-- gRPC Method structure
structure GRPCMethod where
  serviceName : String
  methodName : String
  deriving Repr, BEq

instance : ToString GRPCMethod where
  toString m := s!"{m.serviceName}.{m.methodName}"

instance : Inhabited GRPCMethod where
  default := {
    serviceName := ""
    methodName := ""
  }

-- gRPC Request structure
structure GRPCRequest where
  method : GRPCMethod
  message : GRPCMessage
  metadata : Array (String × String)

instance : Inhabited GRPCRequest where
  default := {
    method := default
    message := default
    metadata := #[]
  }

-- gRPC Response structure
structure GRPCResponse where
  message : GRPCMessage
  status : GRPCStatus
  statusMessage : String
  metadata : Array (String × String)

instance : Inhabited GRPCResponse where
  default := {
    message := default
    status := .OK
    statusMessage := ""
    metadata := #[]
  }

-- gRPC Service Handler type
abbrev GRPCServiceHandler := GRPCRequest → IO GRPCResponse

-- gRPC Service Registry
structure GRPCServiceRegistry where
  handlers : Array (GRPCMethod × GRPCServiceHandler)

instance : Inhabited GRPCServiceRegistry where
  default := {
    handlers := #[]
  }

-- Create empty gRPC service registry
def createGRPCServiceRegistry : GRPCServiceRegistry := {
  handlers := #[]
}

-- Register a gRPC service handler
def registerGRPCHandler (registry : GRPCServiceRegistry) (method : GRPCMethod) (handler : GRPCServiceHandler) : GRPCServiceRegistry := {
  handlers := registry.handlers.push (method, handler)
}

-- Find handler for a method
def findGRPCHandler (registry : GRPCServiceRegistry) (method : GRPCMethod) : Option GRPCServiceHandler :=
  registry.handlers.find? (fun (m, _) => m == method) |>.map Prod.snd

-- Encode gRPC message to HTTP/2 DATA frame payload
def encodeGRPCMessage (msg : GRPCMessage) : ByteArray :=
  let compressedFlag : UInt8 := if msg.compressed then 1 else 0
  let length := msg.payload.size.toUInt32

  -- gRPC message format: compressed-flag (1 byte) + message-length (4 bytes) + message
  let lengthBytes := ByteArray.mk #[
    ((length.toNat >>> 24) &&& 0xFF).toUInt8,
    ((length.toNat >>> 16) &&& 0xFF).toUInt8,
    ((length.toNat >>> 8) &&& 0xFF).toUInt8,
    (length.toNat &&& 0xFF).toUInt8
  ]
  let result := ByteArray.empty
  let result := result.push compressedFlag
  let result := result ++ lengthBytes
  let result := result ++ msg.payload
  result

-- Decode gRPC message from HTTP/2 DATA frame payload
def decodeGRPCMessage (data : ByteArray) : Option GRPCMessage :=
  if data.size < 5 then
    none
  else
    let compressedFlag := data.get! 0
    let lengthBytes := data.extract 1 5
    let length := (lengthBytes[0]!.toNat <<< 24) + (lengthBytes[1]!.toNat <<< 16) +
                  (lengthBytes[2]!.toNat <<< 8) + lengthBytes[3]!.toNat
    let messageData := data.extract 5 (5 + length)

    if messageData.size != length then
      none
    else
      some {
        messageType := .REQUEST  -- Will be determined by context
        payload := messageData
        compressed := compressedFlag == 1
      }

-- Parse gRPC method from HTTP/2 path
def parseGRPCMethod (path : String) : Option GRPCMethod :=
  -- gRPC path format: /ServiceName/MethodName
  let parts := path.splitOn "/"
  if parts.length >= 3 && parts[0]! == "" then
    let serviceName := parts[1]!
    let methodName := parts[2]!
    some {
      serviceName := serviceName
      methodName := methodName
    }
  else
    none

-- Create gRPC response headers for HTTP/2
def createGRPCResponseHeaders (status : GRPCStatus) : Array (String × String) :=
  #[
    ("content-type", "application/grpc+proto"),
    ("grpc-status", toString status.toCode),
    ("grpc-message", "")
  ]

-- Process gRPC request over HTTP/2
def processGRPCRequest (registry : GRPCServiceRegistry) (http2Request : HTTP2Request) : IO HTTP2Response := do
  -- Parse gRPC method from path
  match parseGRPCMethod http2Request.path with
  | none => pure {
      streamId := http2Request.streamId
      statusCode := 404
      headers := #[("content-type", "application/grpc+proto"), ("grpc-status", "12")]
      body := ByteArray.empty
    }
  | some method =>
    -- Find handler
    match findGRPCHandler registry method with
    | none => pure {
        streamId := http2Request.streamId
        statusCode := 404
        headers := #[("content-type", "application/grpc+proto"), ("grpc-status", "12")]
        body := ByteArray.empty
      }
    | some handler =>
      -- Decode gRPC message from body
      match decodeGRPCMessage http2Request.body with
      | none => pure {
          streamId := http2Request.streamId
          statusCode := 400
          headers := #[("content-type", "application/grpc+proto"), ("grpc-status", "13")]
          body := ByteArray.empty
        }
      | some grpcMsg =>
        -- Create gRPC request
        let grpcRequest : GRPCRequest := {
          method := method
          message := { grpcMsg with messageType := .REQUEST }
          metadata := http2Request.headers
        }

        -- Call handler
        let grpcResponse ← handler grpcRequest

        -- Encode response
        let responseBody := encodeGRPCMessage grpcResponse.message
        let responseHeaders := createGRPCResponseHeaders grpcResponse.status ++
                              grpcResponse.metadata

        pure {
          streamId := http2Request.streamId
          statusCode := 200
          headers := responseHeaders
          body := responseBody
        }

-- gRPC Server structure
structure GRPCServer where
  http2Server : HTTP2Server
  serviceRegistry : GRPCServiceRegistry

instance : Inhabited GRPCServer where
  default := {
    http2Server := default
    serviceRegistry := default
  }

-- Create gRPC server
def createGRPCServer : IO GRPCServer := do
  let http2Server ← createHTTP2Server
  pure {
    http2Server := http2Server
    serviceRegistry := createGRPCServiceRegistry
  }

-- Register gRPC service
def registerGRPCService (server : GRPCServer) (method : GRPCMethod) (handler : GRPCServiceHandler) : GRPCServer := {
  http2Server := server.http2Server
  serviceRegistry := registerGRPCHandler server.serviceRegistry method handler
}

-- Start gRPC server
def startGRPCServer (server : GRPCServer) : IO Unit := do
  let grpcHandler := processGRPCRequest server.serviceRegistry
  let http2ServerWithHandler := setHTTP2RequestHandler server.http2Server grpcHandler
  IO.eprintln s!"🚀 Starting gRPC Server on port {http2ServerWithHandler.port}"
  startHTTP2Server http2ServerWithHandler

-- Stop gRPC server
def stopGRPCServer (server : GRPCServer) : IO Unit := do
  stopHTTP2Server server.http2Server

end LeanServer
