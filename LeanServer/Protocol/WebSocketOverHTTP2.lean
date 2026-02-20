-- WebSocket over HTTP/2 Integration
-- Contains functions that integrate WebSocket with HTTP/2

import LeanServer.Protocol.HTTP2
import LeanServer.Protocol.WebSocket

namespace LeanServer

-- HTTP/2 Connection with WebSocket support
structure HTTP2ConnectionWithWebSocket where
  baseConnection : HTTP2Connection
  webSocketConnections : Array WebSocketConnection
  webSocketEnabled : Bool

-- Initialize HTTP/2 connection with WebSocket support
def initHTTP2ConnectionWithWebSocket : HTTP2ConnectionWithWebSocket := {
  baseConnection := initHTTP2Connection
  webSocketConnections := #[]
  webSocketEnabled := true
}

-- Check if request is WebSocket upgrade
def isWebSocketUpgradeRequest (request : HttpRequest) : Bool :=
  isValidWebSocketUpgrade request

-- Create simple error response
def createErrorResponse (statusCode : UInt16) (message : String) : HttpResponse := {
  statusCode := statusCode
  headers := #[{ name := "content-type", value := "text/plain" : HeaderField }]
  body := message.toUTF8
  streamId := 1
}

-- Process WebSocket upgrade request
def processWebSocketUpgrade (connection : HTTP2ConnectionWithWebSocket) (request : HttpRequest) (streamId : UInt32) : HTTP2ConnectionWithWebSocket × HttpResponse × Option WebSocketConnection :=
  if ¬connection.webSocketEnabled ∨ ¬isWebSocketUpgradeRequest request then
    (connection, createErrorResponse 400 "Bad Request", none)
  else
    let response := createWebSocketHandshakeResponse (request.headers.map (fun h => (h.name, h.value)))
    let wsConnection := initWebSocketConnection streamId
    let updatedWSConnections := connection.webSocketConnections.push wsConnection
    let updatedConnection := { connection with webSocketConnections := updatedWSConnections }

    (updatedConnection, { response with streamId := streamId }, some wsConnection)

-- Process WebSocket data frame
def processWebSocketData (connection : HTTP2ConnectionWithWebSocket) (streamId : UInt32) (data : ByteArray) : HTTP2ConnectionWithWebSocket × Array WebSocketMessage × Array HTTP2Frame :=
  let wsConn := connection.webSocketConnections.find? (fun ws => ws.streamId = streamId)
  match wsConn with
  | none => (connection, #[], #[])  -- No WebSocket connection on this stream
  | some wsConnection =>
    let frame := parseWebSocketFrame data
    match frame with
    | none => (connection, #[], #[])  -- Invalid frame
    | some wsFrame =>
      let (updatedWSConn, messages, responseFrames) := processWebSocketFrame wsConnection wsFrame

      -- Update WebSocket connection in the array
      let updatedWSConnections := connection.webSocketConnections.map (fun ws =>
        if ws.streamId = streamId then updatedWSConn else ws
      )

      let updatedConnection := { connection with webSocketConnections := updatedWSConnections }

      -- Convert WebSocket frames to HTTP/2 DATA frames
      let http2Frames := responseFrames.map (fun wsFrame =>
        let serialized := serializeWebSocketFrame wsFrame
        createHTTP2Frame FrameType.DATA 0 streamId serialized
      )

      (updatedConnection, messages, http2Frames)

-- Send WebSocket message
def sendWebSocketMessage (connection : HTTP2ConnectionWithWebSocket) (streamId : UInt32) (message : WebSocketMessage) : HTTP2ConnectionWithWebSocket × Array HTTP2Frame :=
  let wsConn := connection.webSocketConnections.find? (fun ws => ws.streamId = streamId)
  match wsConn with
  | none => (connection, #[])
  | some _ =>
    let frame := match message with
    | .TEXT text => createTextMessage text
    | .BINARY data => createBinaryMessage data
    | .PING data => createPingFrame data
    | .PONG data => createPongFrame data
    | .CLOSE code reason => createCloseFrame code reason

    let serialized := serializeWebSocketFrame frame
    let dataFrame := createHTTP2Frame FrameType.DATA 0 streamId serialized

    (connection, #[dataFrame])

-- Get WebSocket connection state
def getWebSocketConnectionState (connection : HTTP2ConnectionWithWebSocket) (streamId : UInt32) : Option WebSocketState :=
  let wsConn := connection.webSocketConnections.find? (fun ws => ws.streamId = streamId)
  wsConn.map (fun ws => ws.state)

-- Add required instances for connection pooling
instance : Inhabited HTTP2ConnectionWithWebSocket where
  default := initHTTP2ConnectionWithWebSocket

instance : BEq HTTP2ConnectionWithWebSocket where
  beq a b := a.webSocketEnabled == b.webSocketEnabled &&
             a.webSocketConnections.size == b.webSocketConnections.size

end LeanServer
