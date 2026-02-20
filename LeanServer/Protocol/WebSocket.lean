-- WebSocket Protocol Implementation over HTTP/2
-- Implements RFC 6455 WebSocket protocol with HTTP/2 transport

import LeanServer.Protocol.HTTP2
import LeanServer.Crypto.Crypto

namespace LeanServer

-- Add Repr instance for ByteArray
deriving instance Repr for ByteArray

-- WebSocket Frame Types (RFC 6455)
inductive WebSocketFrameType where
  | CONTINUATION : WebSocketFrameType
  | TEXT : WebSocketFrameType
  | BINARY : WebSocketFrameType
  | CLOSE : WebSocketFrameType
  | PING : WebSocketFrameType
  | PONG : WebSocketFrameType
  deriving Repr, BEq

-- WebSocket Frame
structure WebSocketFrame where
  fin : Bool                    -- Final fragment flag
  rsv1 : Bool                   -- Extension flag 1
  rsv2 : Bool                   -- Extension flag 2
  rsv3 : Bool                   -- Extension flag 3
  opcode : WebSocketFrameType   -- Frame type
  mask : Bool                   -- Mask flag (client frames)
  payloadLength : UInt64        -- Length of payload
  maskingKey : Option UInt32    -- Masking key (if masked)
  payload : ByteArray           -- Frame payload

-- WebSocket Connection State
inductive WebSocketState where
  | CONNECTING : WebSocketState     -- Initial handshake in progress
  | OPEN : WebSocketState          -- Connection established
  | CLOSING : WebSocketState       -- Close handshake in progress
  | CLOSED : WebSocketState        -- Connection closed
  deriving Repr, BEq

-- WebSocket Close Codes (RFC 6455)
inductive WebSocketCloseCode : UInt16 → Type where
  | NORMAL_CLOSURE : WebSocketCloseCode 1000
  | GOING_AWAY : WebSocketCloseCode 1001
  | PROTOCOL_ERROR : WebSocketCloseCode 1002
  | UNSUPPORTED_DATA : WebSocketCloseCode 1003
  | NO_STATUS_RECEIVED : WebSocketCloseCode 1005
  | ABNORMAL_CLOSURE : WebSocketCloseCode 1006
  | INVALID_FRAME_PAYLOAD_DATA : WebSocketCloseCode 1007
  | POLICY_VIOLATION : WebSocketCloseCode 1008
  | MESSAGE_TOO_BIG : WebSocketCloseCode 1009
  | MANDATORY_EXTENSION : WebSocketCloseCode 1010
  | INTERNAL_ERROR : WebSocketCloseCode 1011
  | SERVICE_RESTART : WebSocketCloseCode 1012
  | TRY_AGAIN_LATER : WebSocketCloseCode 1013
  | BAD_GATEWAY : WebSocketCloseCode 1014
  | TLS_HANDSHAKE : WebSocketCloseCode 1015

-- WebSocket Connection
structure WebSocketConnection where
  streamId : UInt32                    -- HTTP/2 stream ID
  state : WebSocketState              -- Connection state
  subprotocol : Option String         -- Negotiated subprotocol
  extensions : Array String           -- Negotiated extensions
  messageBuffer : ByteArray           -- Buffer for fragmented messages
  pendingFrames : Array WebSocketFrame -- Frames waiting to be sent
  lastPongTime : UInt64               -- Timestamp of last pong received
  pingInterval : UInt64               -- Ping interval in milliseconds
  maxMessageSize : UInt64             -- Maximum message size

-- WebSocket Message Types
inductive WebSocketMessage where
  | TEXT : String → WebSocketMessage
  | BINARY : ByteArray → WebSocketMessage
  | CLOSE : UInt16 → String → WebSocketMessage
  | PING : ByteArray → WebSocketMessage
  | PONG : ByteArray → WebSocketMessage
  deriving Repr, Inhabited

-- Initialize WebSocket connection
def initWebSocketConnection (streamId : UInt32) : WebSocketConnection := {
  streamId := streamId
  state := WebSocketState.CONNECTING
  subprotocol := none
  extensions := #[]
  messageBuffer := ByteArray.mk #[]
  pendingFrames := #[]
  lastPongTime := 0  -- Updated on PONG receive with monoTimeMs from caller
  pingInterval := 30000  -- 30 seconds
  maxMessageSize := 1048576  -- 1MB
}

-- SHA-1 implementation (RFC 3174) for WebSocket handshake (RFC 6455)
private def sha1_rotl32 (x : UInt32) (n : UInt32) : UInt32 :=
  (x <<< n) ||| (x >>> (32 - n))

def sha1 (input : ByteArray) : ByteArray :=
  -- Initial hash values
  let h0 : UInt32 := 0x67452301
  let h1 : UInt32 := 0xEFCDAB89
  let h2 : UInt32 := 0x98BADCFE
  let h3 : UInt32 := 0x10325476
  let h4 : UInt32 := 0xC3D2E1F0

  -- Message padding: append 0x80, pad to 56 mod 64, append 64-bit bit-length
  let msgLen := input.size
  let bitLen : UInt64 := msgLen.toUInt64 * 8
  let padded := input.push 0x80
  let padZeros := (120 - (padded.size % 64)) % 64
  let padded := padded ++ ByteArray.mk (List.replicate padZeros (0 : UInt8)).toArray
  let padded := padded ++ ByteArray.mk #[
    ((bitLen >>> 56) &&& 0xFF).toUInt8,
    ((bitLen >>> 48) &&& 0xFF).toUInt8,
    ((bitLen >>> 40) &&& 0xFF).toUInt8,
    ((bitLen >>> 32) &&& 0xFF).toUInt8,
    ((bitLen >>> 24) &&& 0xFF).toUInt8,
    ((bitLen >>> 16) &&& 0xFF).toUInt8,
    ((bitLen >>> 8) &&& 0xFF).toUInt8,
    (bitLen &&& 0xFF).toUInt8
  ]

  -- Process each 64-byte (512-bit) block
  let numBlocks := padded.size / 64
  let (rh0, rh1, rh2, rh3, rh4) := (List.range numBlocks).foldl (fun (ah0, ah1, ah2, ah3, ah4) blockIdx =>
    let offset := blockIdx * 64
    -- Prepare message schedule W[0..79]
    -- W[0..15] from block (big-endian 32-bit words)
    let w : Array UInt32 := (List.range 16).foldl (fun acc i =>
      let b0 := padded[offset + i * 4]!.toUInt32
      let b1 := padded[offset + i * 4 + 1]!.toUInt32
      let b2 := padded[offset + i * 4 + 2]!.toUInt32
      let b3 := padded[offset + i * 4 + 3]!.toUInt32
      acc.push ((b0 <<< 24) ||| (b1 <<< 16) ||| (b2 <<< 8) ||| b3)
    ) #[]
    -- W[16..79] = ROTL1(W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16])
    let w := (List.range 64).foldl (fun (wa : Array UInt32) i =>
      let t := i + 16
      let val := wa[t - 3]! ^^^ wa[t - 8]! ^^^ wa[t - 14]! ^^^ wa[t - 16]!
      wa.push (sha1_rotl32 val 1)
    ) w

    -- Initialize working variables
    let (a, b, c, d, e) := (ah0, ah1, ah2, ah3, ah4)

    -- 80 rounds
    let (a, b, c, d, e) := (List.range 80).foldl (fun (a, b, c, d, e) t =>
      let (f, k) :=
        if t < 20 then
          ((b &&& c) ||| ((~~~ b) &&& d), (0x5A827999 : UInt32))     -- Ch
        else if t < 40 then
          (b ^^^ c ^^^ d, (0x6ED9EBA1 : UInt32))                     -- Parity
        else if t < 60 then
          ((b &&& c) ||| (b &&& d) ||| (c &&& d), (0x8F1BBCDC : UInt32)) -- Maj
        else
          (b ^^^ c ^^^ d, (0xCA62C1D6 : UInt32))                     -- Parity
      let temp := sha1_rotl32 a 5 + f + e + k + w[t]!
      (temp, a, sha1_rotl32 b 30, c, d)
    ) (a, b, c, d, e)

    (ah0 + a, ah1 + b, ah2 + c, ah3 + d, ah4 + e)
  ) (h0, h1, h2, h3, h4)

  -- Produce 20-byte (160-bit) digest
  let toBytes (v : UInt32) : Array UInt8 := #[
    ((v >>> 24) &&& 0xFF).toUInt8,
    ((v >>> 16) &&& 0xFF).toUInt8,
    ((v >>> 8) &&& 0xFF).toUInt8,
    (v &&& 0xFF).toUInt8
  ]
  ByteArray.mk (toBytes rh0 ++ toBytes rh1 ++ toBytes rh2 ++ toBytes rh3 ++ toBytes rh4)

-- Base64 encoding (RFC 4648)
def base64Chars : String := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def base64Encode (data : ByteArray) : String := Id.run do
  let charArray := base64Chars.toList.toArray
  let getChar (idx : Nat) : Char := if h : idx < charArray.size then charArray[idx] else '?'
  let mut result := ""
  let mut i := 0
  while i + 2 < data.size do
    let b0 := data.get! i
    let b1 := data.get! (i + 1)
    let b2 := data.get! (i + 2)
    let idx0 := (b0 >>> 2).toNat
    let idx1 := (((b0 &&& 0x03) <<< 4) ||| (b1 >>> 4)).toNat
    let idx2 := (((b1 &&& 0x0F) <<< 2) ||| (b2 >>> 6)).toNat
    let idx3 := (b2 &&& 0x3F).toNat
    result := result ++ s!"{getChar idx0}{getChar idx1}{getChar idx2}{getChar idx3}"
    i := i + 3
  -- Handle remaining bytes
  if i + 1 == data.size then
    let b0 := data.get! i
    let idx0 := (b0 >>> 2).toNat
    let idx1 := ((b0 &&& 0x03) <<< 4).toNat
    result := result ++ s!"{getChar idx0}{getChar idx1}=="
  else if i + 2 == data.size then
    let b0 := data.get! i
    let b1 := data.get! (i + 1)
    let idx0 := (b0 >>> 2).toNat
    let idx1 := (((b0 &&& 0x03) <<< 4) ||| (b1 >>> 4)).toNat
    let idx2 := ((b1 &&& 0x0F) <<< 2).toNat
    result := result ++ s!"{getChar idx0}{getChar idx1}{getChar idx2}="
  return result

-- Generate Sec-WebSocket-Accept key (RFC 6455)
def generateWebSocketAcceptKey (requestHeaders : Array (String × String)) : String :=
  let keyHeader := requestHeaders.find? (fun (name, _) => name = "sec-websocket-key")
  match keyHeader with
  | some (_, key) =>
    let magicString := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    let concatenated := key ++ magicString
    let hash := sha1 concatenated.toUTF8
    base64Encode hash
  | none => ""

-- Create WebSocket handshake response
def createWebSocketHandshakeResponse (requestHeaders : Array (String × String)) : HttpResponse :=
  let responseHeaders := #[
    { name := "Upgrade", value := "websocket" : HeaderField },
    { name := "Connection", value := "Upgrade" : HeaderField },
    { name := "Sec-WebSocket-Accept", value := generateWebSocketAcceptKey requestHeaders : HeaderField },
    { name := "Sec-WebSocket-Version", value := "13" : HeaderField }
  ]

  -- Check for subprotocol negotiation
  let subprotocol := requestHeaders.find? (fun (name, _) => name = "sec-websocket-protocol")
  let finalHeaders := match subprotocol with
  | some (_, value) => responseHeaders.push { name := "Sec-WebSocket-Protocol", value := value : HeaderField }
  | none => responseHeaders

  {
    statusCode := 101
    headers := finalHeaders
    body := ByteArray.mk #[]
    streamId := 1  -- Will be set by HTTP/2 layer
  }

-- Unmask WebSocket payload (RFC 6455)
def unmaskPayload (payload : ByteArray) (maskingKey : UInt32) : ByteArray :=
  let maskBytes := #[
    ((maskingKey >>> 24) &&& 0xFF).toUInt8,
    ((maskingKey >>> 16) &&& 0xFF).toUInt8,
    ((maskingKey >>> 8) &&& 0xFF).toUInt8,
    (maskingKey &&& 0xFF).toUInt8
  ]

  let unmasked := List.range payload.size |>.map (fun i =>
    let byte := payload[i]!
    let maskByte := maskBytes[i % 4]!
    byte ^^^ maskByte
  )
  ByteArray.mk unmasked.toArray

-- Check if frame type is a control frame (RFC 6455 §5.5)
def isControlFrame (frameType : WebSocketFrameType) : Bool :=
  match frameType with
  | .CLOSE | .PING | .PONG => true
  | _ => false

-- Parse WebSocket frame from HTTP/2 DATA frame
def parseWebSocketFrame (data : ByteArray) : Option WebSocketFrame :=
  if data.size < 2 then none
  else
    let firstByte := data[0]!
    let secondByte := data[1]!

    let fin := (firstByte &&& 0x80) ≠ 0
    let rsv1 := (firstByte &&& 0x40) ≠ 0
    let rsv2 := (firstByte &&& 0x20) ≠ 0
    let rsv3 := (firstByte &&& 0x10) ≠ 0
    let opcode := firstByte &&& 0x0F

    let mask := (secondByte &&& 0x80) ≠ 0
    let payloadLength7 := secondByte &&& 0x7F

    let frameType := match opcode with
    | 0 => WebSocketFrameType.CONTINUATION
    | 1 => WebSocketFrameType.TEXT
    | 2 => WebSocketFrameType.BINARY
    | 8 => WebSocketFrameType.CLOSE
    | 9 => WebSocketFrameType.PING
    | 10 => WebSocketFrameType.PONG
    | _ => WebSocketFrameType.TEXT  -- Default to text

    -- RFC 6455 §5.5: Control frames MUST NOT be fragmented
    if isControlFrame frameType && !fin then none
    -- RFC 6455 §5.5: Control frame payload MUST NOT exceed 125 bytes
    else if isControlFrame frameType && payloadLength7 > 125 then none
    else
    let (actualPayloadLen, headerLen) :=
      if payloadLength7 <= 125 then
        (payloadLength7.toNat, 2)
      else if payloadLength7 == 126 then
        -- 16-bit extended payload length
        if data.size < 4 then (0, 0)
        else
          let len := (data[2]!.toNat <<< 8) ||| data[3]!.toNat
          (len, 4)
      else  -- payloadLength7 == 127
        -- 64-bit extended payload length
        if data.size < 10 then (0, 0)
        else
          let len := (data[2]!.toNat <<< 56) ||| (data[3]!.toNat <<< 48) |||
                    (data[4]!.toNat <<< 40) ||| (data[5]!.toNat <<< 32) |||
                    (data[6]!.toNat <<< 24) ||| (data[7]!.toNat <<< 16) |||
                    (data[8]!.toNat <<< 8) ||| data[9]!.toNat
          (len, 10)

    if headerLen == 0 then none  -- Insufficient data for extended length
    else if data.size >= headerLen + (if mask then 4 else 0) + actualPayloadLen then
      let maskingKey := if mask then
        let keyPos := headerLen
        let key := (data[keyPos]!.toNat <<< 24) |||
                  (data[keyPos+1]!.toNat <<< 16) |||
                  (data[keyPos+2]!.toNat <<< 8) |||
                  data[keyPos+3]!.toNat
        some key.toUInt32
      else none

      let payloadStart := headerLen + (if mask then 4 else 0)
      let payload := data.extract payloadStart (payloadStart + actualPayloadLen)

      -- Unmask payload if masked
      let finalPayload := match maskingKey with
      | some key => unmaskPayload payload key
      | none => payload

      some {
        fin := fin
        rsv1 := rsv1
        rsv2 := rsv2
        rsv3 := rsv3
        opcode := frameType
        mask := mask
        payloadLength := actualPayloadLen.toUInt64
        maskingKey := maskingKey
        payload := finalPayload
      }
    else none

-- Create WebSocket frame
def createWebSocketFrame (opcode : WebSocketFrameType) (payload : ByteArray) (fin : Bool := true) : WebSocketFrame := {
  fin := fin
  rsv1 := false
  rsv2 := false
  rsv3 := false
  opcode := opcode
  mask := false  -- Server frames are not masked
  payloadLength := payload.size.toUInt64
  maskingKey := none
  payload := payload
}

-- Serialize WebSocket frame to bytes
def serializeWebSocketFrame (frame : WebSocketFrame) : ByteArray :=
  let result := ByteArray.mk #[]

  -- First byte: FIN + RSV + opcode
  let firstByte := (if frame.fin then 0x80 else 0) |||
                  (if frame.rsv1 then 0x40 else 0) |||
                  (if frame.rsv2 then 0x20 else 0) |||
                  (if frame.rsv3 then 0x10 else 0) |||
                  (match frame.opcode with
                   | .CONTINUATION => 0
                   | .TEXT => 1
                   | .BINARY => 2
                   | .CLOSE => 8
                   | .PING => 9
                   | .PONG => 10)
  let result := result.push firstByte

  -- Second byte: MASK + payload length
  let payloadLen := frame.payload.size
  let secondByte := (if frame.mask then 0x80 else 0) |||
                   (if payloadLen <= 125 then payloadLen.toUInt8
                    else if payloadLen <= 65535 then 126
                    else 127)
  let result := result.push secondByte

  -- Extended length if needed
  let result := if payloadLen > 125 then
    if payloadLen <= 65535 then
      -- 16-bit length
      result.push ((payloadLen >>> 8) &&& 0xFF).toUInt8
             |>.push (payloadLen &&& 0xFF).toUInt8
    else
      -- 64-bit length (RFC 6455 §5.2: network byte order, 8 bytes)
      result.push ((payloadLen >>> 56) &&& 0xFF).toUInt8
             |>.push ((payloadLen >>> 48) &&& 0xFF).toUInt8
             |>.push ((payloadLen >>> 40) &&& 0xFF).toUInt8
             |>.push ((payloadLen >>> 32) &&& 0xFF).toUInt8
             |>.push ((payloadLen >>> 24) &&& 0xFF).toUInt8
             |>.push ((payloadLen >>> 16) &&& 0xFF).toUInt8
             |>.push ((payloadLen >>> 8) &&& 0xFF).toUInt8
             |>.push (payloadLen &&& 0xFF).toUInt8
  else result

  -- Add payload
  result ++ frame.payload

-- Create text message frame
def createTextMessage (text : String) : WebSocketFrame :=
  createWebSocketFrame WebSocketFrameType.TEXT text.toUTF8

-- Create binary message frame
def createBinaryMessage (data : ByteArray) : WebSocketFrame :=
  createWebSocketFrame WebSocketFrameType.BINARY data

-- Create ping frame
def createPingFrame (data : ByteArray := ByteArray.mk #[]) : WebSocketFrame :=
  createWebSocketFrame WebSocketFrameType.PING data

-- Create pong frame
def createPongFrame (data : ByteArray := ByteArray.mk #[]) : WebSocketFrame :=
  createWebSocketFrame WebSocketFrameType.PONG data

-- Create close frame
def createCloseFrame (code : UInt16 := 1000) (reason : String := "") : WebSocketFrame :=
  let payload := ByteArray.mk #[
    ((code >>> 8) &&& 0xFF).toUInt8,
    (code &&& 0xFF).toUInt8
  ] ++ reason.toUTF8
  createWebSocketFrame WebSocketFrameType.CLOSE payload

-- Process WebSocket frame and update connection
def processWebSocketFrame (connection : WebSocketConnection) (frame : WebSocketFrame) : WebSocketConnection × Array WebSocketMessage × Array WebSocketFrame :=
  match frame.opcode with
  | .TEXT =>
    if frame.fin then
      -- RFC 6455 §8.1: TEXT frames MUST be valid UTF-8
      match String.fromUTF8? frame.payload with
      | some text =>
        let message := WebSocketMessage.TEXT text
        (connection, #[message], #[])
      | none =>
        -- Invalid UTF-8: close with code 1007 (INVALID_FRAME_PAYLOAD_DATA)
        let closeFrame := createCloseFrame 1007 "Invalid UTF-8"
        let newConnection := { connection with state := WebSocketState.CLOSING }
        (newConnection, #[], #[closeFrame])
    else
      -- Fragmented message - buffer and wait for continuation
      let newConnection := { connection with messageBuffer := connection.messageBuffer ++ frame.payload }
      (newConnection, #[], #[])
  | .BINARY =>
    if frame.fin then
      let message := WebSocketMessage.BINARY frame.payload
      (connection, #[message], #[])
    else
      let newConnection := { connection with messageBuffer := connection.messageBuffer ++ frame.payload }
      (newConnection, #[], #[])
  | .CONTINUATION =>
    if frame.fin then
      -- End of fragmented message
      let completePayload := connection.messageBuffer ++ frame.payload
      let newConnection := { connection with messageBuffer := ByteArray.mk #[] }
      -- RFC 6455 §8.1: validate UTF-8 on completed text messages
      match String.fromUTF8? completePayload with
      | some text =>
        let message := WebSocketMessage.TEXT text
        (newConnection, #[message], #[])
      | none =>
        -- Invalid UTF-8: close with code 1007
        let closeFrame := createCloseFrame 1007 "Invalid UTF-8"
        let closingConnection := { newConnection with state := WebSocketState.CLOSING }
        (closingConnection, #[], #[closeFrame])
    else
      let newConnection := { connection with messageBuffer := connection.messageBuffer ++ frame.payload }
      (newConnection, #[], #[])
  | .PING =>
    let pongFrame := createPongFrame frame.payload
    (connection, #[WebSocketMessage.PING frame.payload], #[pongFrame])
  | .PONG =>
    let updatedConnection := { connection with lastPongTime := 0 }  -- Caller should update with monoTimeMs
    (updatedConnection, #[WebSocketMessage.PONG frame.payload], #[])
  | .CLOSE =>
    let closeCode := if frame.payload.size >= 2 then
      ((frame.payload[0]!.toNat <<< 8) + frame.payload[1]!.toNat).toUInt16
    else 1000
    let reason := if frame.payload.size > 2 then
      match String.fromUTF8? (frame.payload.extract 2 frame.payload.size) with
      | some r => r
      | none => ""
    else ""
    let closeMessage := WebSocketMessage.CLOSE closeCode reason
    let closeFrame := createCloseFrame closeCode reason
    let newConnection := { connection with state := WebSocketState.CLOSING }
    (newConnection, #[closeMessage], #[closeFrame])

-- Check if WebSocket upgrade request is valid
def isValidWebSocketUpgrade (request : HttpRequest) : Bool :=
  let hasUpgrade := request.headers.any (fun field =>
    field.name = "upgrade" ∧ field.value = "websocket")
  let hasConnection := request.headers.any (fun field =>
    field.name = "connection" ∧ field.value = "upgrade")
  let hasKey := request.headers.any (fun field => field.name = "sec-websocket-key")
  let hasVersion := request.headers.any (fun field =>
    field.name = "sec-websocket-version" ∧ field.value = "13")

  hasUpgrade ∧ hasConnection ∧ hasKey ∧ hasVersion

end LeanServer
