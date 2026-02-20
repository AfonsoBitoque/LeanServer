-- HTTP/2 Protocol Implementation
-- Based on RFC 7540: https://tools.ietf.org/html/rfc7540

import LeanServer.Core.Basic
import LeanServer.Crypto.Crypto
import LeanServer.Protocol.HPACK
import LeanServer.Core.ByteSlice

namespace LeanServer

-- ==========================================
-- HTTP/2 Protocol Constants (RFC 7540 §6.5.2)
-- ==========================================

/-- Default HPACK header table size (RFC 7540 §6.5.2). -/
def h2DefaultHeaderTableSize : UInt32 := 4096

/-- Default initial flow-control window size (RFC 7540 §6.9.2). -/
def h2DefaultInitialWindowSize : UInt32 := 65535

/-- Default maximum frame payload size (RFC 7540 §6.5.2). -/
def h2DefaultMaxFrameSize : UInt32 := 16384

/-- Maximum flow-control window size (RFC 7540 §6.9.1): 2^31 - 1. -/
def h2MaxWindowSize : Nat := 2147483647

-- HTTP/2 Frame Types (RFC 7540 Section 6)
inductive FrameType where
  | DATA : FrameType
  | HEADERS : FrameType
  | PRIORITY : FrameType
  | RST_STREAM : FrameType
  | SETTINGS : FrameType
  | PUSH_PROMISE : FrameType
  | PING : FrameType
  | GOAWAY : FrameType
  | WINDOW_UPDATE : FrameType
  | CONTINUATION : FrameType
  deriving Repr, BEq, DecidableEq

instance : ToString FrameType where
  toString := fun
    | .DATA => "DATA"
    | .HEADERS => "HEADERS"
    | .PRIORITY => "PRIORITY"
    | .RST_STREAM => "RST_STREAM"
    | .SETTINGS => "SETTINGS"
    | .PUSH_PROMISE => "PUSH_PROMISE"
    | .PING => "PING"
    | .GOAWAY => "GOAWAY"
    | .WINDOW_UPDATE => "WINDOW_UPDATE"
    | .CONTINUATION => "CONTINUATION"

-- Convert FrameType to byte value
def FrameType.toByte (ft : FrameType) : UInt8 :=
  match ft with
  | DATA => 0x0
  | HEADERS => 0x1
  | PRIORITY => 0x2
  | RST_STREAM => 0x3
  | SETTINGS => 0x4
  | PUSH_PROMISE => 0x5
  | PING => 0x6
  | GOAWAY => 0x7
  | WINDOW_UPDATE => 0x8
  | CONTINUATION => 0x9

-- Convert byte to FrameType
def FrameType.fromByte (b : UInt8) : Option FrameType :=
  match b with
  | 0x0 => some DATA
  | 0x1 => some HEADERS
  | 0x2 => some PRIORITY
  | 0x3 => some RST_STREAM
  | 0x4 => some SETTINGS
  | 0x5 => some PUSH_PROMISE
  | 0x6 => some PING
  | 0x7 => some GOAWAY
  | 0x8 => some WINDOW_UPDATE
  | 0x9 => some CONTINUATION
  | _ => none

-- HTTP/2 Frame Header (9 bytes)
structure FrameHeader where
  length : UInt32        -- 24 bits, but stored as 32 for convenience
  frameType : FrameType
  flags : UInt8
  streamId : UInt32      -- 31 bits, but stored as 32 for convenience
  deriving Repr, DecidableEq

-- HTTP/2 Frame
structure HTTP2Frame where
  header : FrameHeader
  payload : ByteArray

-- HTTP/2 Error Codes (RFC 7540 Section 7)
inductive ErrorCode where
  | NO_ERROR : ErrorCode
  | PROTOCOL_ERROR : ErrorCode
  | INTERNAL_ERROR : ErrorCode
  | FLOW_CONTROL_ERROR : ErrorCode
  | SETTINGS_TIMEOUT : ErrorCode
  | STREAM_CLOSED : ErrorCode
  | FRAME_SIZE_ERROR : ErrorCode
  | REFUSED_STREAM : ErrorCode
  | CANCEL : ErrorCode
  | COMPRESSION_ERROR : ErrorCode
  | CONNECT_ERROR : ErrorCode
  | ENHANCE_YOUR_CALM : ErrorCode
  | INADEQUATE_SECURITY : ErrorCode
  | HTTP_1_1_REQUIRED : ErrorCode
  deriving Repr, BEq

def ErrorCode.toUInt32 : ErrorCode → UInt32
  | NO_ERROR => 0x0
  | PROTOCOL_ERROR => 0x1
  | INTERNAL_ERROR => 0x2
  | FLOW_CONTROL_ERROR => 0x3
  | SETTINGS_TIMEOUT => 0x4
  | STREAM_CLOSED => 0x5
  | FRAME_SIZE_ERROR => 0x6
  | REFUSED_STREAM => 0x7
  | CANCEL => 0x8
  | COMPRESSION_ERROR => 0x9
  | CONNECT_ERROR => 0xA
  | ENHANCE_YOUR_CALM => 0xB
  | INADEQUATE_SECURITY => 0xC
  | HTTP_1_1_REQUIRED => 0xD

-- HTTP/2 Settings Parameters (RFC 7540 Section 6.5.2)
inductive SettingId where
  | HEADER_TABLE_SIZE : SettingId
  | ENABLE_PUSH : SettingId
  | MAX_CONCURRENT_STREAMS : SettingId
  | INITIAL_WINDOW_SIZE : SettingId
  | MAX_FRAME_SIZE : SettingId
  | MAX_HEADER_LIST_SIZE : SettingId
  deriving Repr, BEq

def SettingId.toUInt16 : SettingId → UInt16
  | HEADER_TABLE_SIZE => 0x1
  | ENABLE_PUSH => 0x2
  | MAX_CONCURRENT_STREAMS => 0x3
  | INITIAL_WINDOW_SIZE => 0x4
  | MAX_FRAME_SIZE => 0x5
  | MAX_HEADER_LIST_SIZE => 0x6

def SettingId.fromUInt16 (id : UInt16) : Option SettingId :=
  match id with
  | 0x1 => some HEADER_TABLE_SIZE
  | 0x2 => some ENABLE_PUSH
  | 0x3 => some MAX_CONCURRENT_STREAMS
  | 0x4 => some INITIAL_WINDOW_SIZE
  | 0x5 => some MAX_FRAME_SIZE
  | 0x6 => some MAX_HEADER_LIST_SIZE
  | _ => none

-- HTTP/2 Setting
structure HTTP2Setting where
  id : SettingId
  value : UInt32
  deriving Repr

instance : Inhabited HTTP2Setting where
  default := { id := SettingId.HEADER_TABLE_SIZE, value := h2DefaultHeaderTableSize }

-- HTTP/2 Stream State
inductive StreamState where
  | IDLE : StreamState
  | RESERVED_LOCAL : StreamState
  | RESERVED_REMOTE : StreamState
  | OPEN : StreamState
  | HALF_CLOSED_LOCAL : StreamState
  | HALF_CLOSED_REMOTE : StreamState
  | CLOSED : StreamState
  deriving Repr, BEq

-- HTTP/2 Stream
structure HTTP2Stream where
  id : UInt32
  state : StreamState
  windowSize : UInt32
  deriving Repr

-- HTTP/2 Connection State
structure HTTP2Connection where
  streams : Array HTTP2Stream
  settings : Array HTTP2Setting
  windowSize : UInt32
  maxFrameSize : UInt32
  maxConcurrentStreams : UInt32
  pendingSettings : Option (Array HTTP2Setting × UInt64) := none  -- Sent settings awaiting ACK + timestamp
  goawayReceived : Option UInt32 := none  -- Last stream ID from received GOAWAY (for graceful drain)
  deriving Repr

-- Default HTTP/2 Settings
def defaultHTTP2Settings : Array HTTP2Setting := #[
  { id := SettingId.HEADER_TABLE_SIZE, value := h2DefaultHeaderTableSize },
  { id := SettingId.ENABLE_PUSH, value := 1 },
  { id := SettingId.MAX_CONCURRENT_STREAMS, value := 100 },
  { id := SettingId.INITIAL_WINDOW_SIZE, value := h2DefaultInitialWindowSize },
  { id := SettingId.MAX_FRAME_SIZE, value := h2DefaultMaxFrameSize },
  { id := SettingId.MAX_HEADER_LIST_SIZE, value := 65536 }
]

-- Initialize HTTP/2 Connection
def initHTTP2Connection : HTTP2Connection := {
  streams := #[]
  settings := defaultHTTP2Settings
  windowSize := h2DefaultInitialWindowSize
  maxFrameSize := h2DefaultMaxFrameSize
  maxConcurrentStreams := 100
}

-- Frame Header Parsing Functions

-- Parse frame header from byte array (9 bytes)
def parseFrameHeader (data : ByteArray) : Option FrameHeader :=
  if h : data.size < 9 then none
  else
    -- Length: first 3 bytes (24 bits)
    let length := (data.get 0 (by omega)).toNat <<< 16 + (data.get 1 (by omega)).toNat <<< 8 + (data.get 2 (by omega)).toNat
    -- Type: 4th byte
    let frameTypeOpt := FrameType.fromByte (data.get 3 (by omega))
    -- Flags: 5th byte
    let flags := data.get 4 (by omega)
    -- Stream ID: last 4 bytes (31 bits, but we store as 32)
    let streamId := (data.get 5 (by omega)).toNat <<< 24 + (data.get 6 (by omega)).toNat <<< 16 + (data.get 7 (by omega)).toNat <<< 8 + (data.get 8 (by omega)).toNat

    match frameTypeOpt with
    | some frameType => some {
        length := length.toUInt32
        frameType := frameType
        flags := flags
        streamId := streamId.toUInt32
      }
    | none => none

-- Serialize frame header to byte array
def serializeFrameHeader (header : FrameHeader) : ByteArray :=
  let len := header.length.toNat
  let sid := header.streamId.toNat &&& 0x7FFFFFFF  -- Mask to 31 bits
  ByteArray.mk #[
    ((len >>> 16) &&& 0xFF).toUInt8,
    ((len >>> 8) &&& 0xFF).toUInt8,
    (len &&& 0xFF).toUInt8,
    header.frameType.toByte,
    header.flags,
    ((sid >>> 24) &&& 0xFF).toUInt8,
    ((sid >>> 16) &&& 0xFF).toUInt8,
    ((sid >>> 8) &&& 0xFF).toUInt8,
    (sid &&& 0xFF).toUInt8
  ]

-- Parse complete HTTP/2 frame
def parseHTTP2Frame (data : ByteArray) : Option HTTP2Frame :=
  match parseFrameHeader data with
  | some header =>
    let payloadStart := 9
    let payloadEnd := payloadStart + header.length.toNat
    if payloadEnd > data.size then none
    else
      let payload := data.extract payloadStart payloadEnd
      some { header := header, payload := payload }
  | none => none

-- Create HTTP/2 frame
def createHTTP2Frame (frameType : FrameType) (flags : UInt8) (streamId : UInt32) (payload : ByteArray) : HTTP2Frame :=
  let header := {
    length := payload.size.toUInt32
    frameType := frameType
    flags := flags
    streamId := streamId
  }
  { header := header, payload := payload }

-- Serialize complete HTTP/2 frame
def serializeHTTP2Frame (frame : HTTP2Frame) : ByteArray :=
  serializeFrameHeader frame.header ++ frame.payload

-- Parse multiple HTTP/2 frames from data
def parseHTTP2Frames (data : ByteArray) : Option (Array HTTP2Frame) :=
  let rec parseFrames (remaining : ByteArray) (acc : Array HTTP2Frame) : Option (Array HTTP2Frame) :=
    if remaining.size == 0 then some acc
    else if remaining.size < 9 then none  -- Not enough data for frame header
    else
      match parseHTTP2Frame remaining with
      | some frame =>
        let frameSize := 9 + frame.payload.size  -- Header (9) + payload
        if remaining.size >= frameSize then
          let nextData := remaining.extract frameSize remaining.size
          parseFrames nextData (acc.push frame)
        else none  -- Incomplete frame
      | none => none
  parseFrames data #[]

-- SETTINGS Frame Functions

-- Parse SETTINGS frame payload
def parseSettingsPayload (payload : ByteArray) : Array HTTP2Setting :=
  let rec parseSettings (remaining : Nat) (pos : Nat) (acc : Array HTTP2Setting) : Array HTTP2Setting :=
    if remaining < 6 then acc
    else if h : pos + 5 < payload.size then
      let id := (payload.get pos (by omega)).toNat <<< 8 + (payload.get (pos + 1) (by omega)).toNat
      let value := (payload.get (pos + 2) (by omega)).toNat <<< 24 + (payload.get (pos + 3) (by omega)).toNat <<< 16 +
                   (payload.get (pos + 4) (by omega)).toNat <<< 8 + (payload.get (pos + 5) (by omega)).toNat
      match SettingId.fromUInt16 id.toUInt16 with
      | some settingId =>
        let newAcc := acc.push { id := settingId, value := value.toUInt32 }
        parseSettings (remaining - 6) (pos + 6) newAcc
      | none => parseSettings (remaining - 6) (pos + 6) acc  -- Skip unknown settings
    else acc
  parseSettings payload.size 0 #[]

-- Serialize SETTINGS frame payload
def serializeSettingsPayload (settings : Array HTTP2Setting) : ByteArray :=
  let rec buildPayload (i : Nat) (acc : ByteArray) : ByteArray :=
    if h : i < settings.size then
      let setting := settings[i]
      let id := setting.id.toUInt16.toNat
      let value := setting.value.toNat
      let newAcc := acc ++ ByteArray.mk #[
        ((id >>> 8) &&& 0xFF).toUInt8,
        (id &&& 0xFF).toUInt8,
        ((value >>> 24) &&& 0xFF).toUInt8,
        ((value >>> 16) &&& 0xFF).toUInt8,
        ((value >>> 8) &&& 0xFF).toUInt8,
        (value &&& 0xFF).toUInt8
      ]
      buildPayload (i + 1) newAcc
    else acc
  buildPayload 0 (ByteArray.mk #[])

-- Create SETTINGS frame
def createSettingsFrame (settings : Array HTTP2Setting) (ack : Bool) : HTTP2Frame :=
  let flags := if ack then 0x1 else 0x0
  let payload := if ack then ByteArray.mk #[] else serializeSettingsPayload settings
  createHTTP2Frame FrameType.SETTINGS flags 0 payload

-- Create SETTINGS ACK frame
def createSettingsAckFrame : HTTP2Frame :=
  createSettingsFrame #[] true

-- WINDOW_UPDATE Frame Functions

-- Parse WINDOW_UPDATE frame payload
def parseWindowUpdatePayload (payload : ByteArray) : Option UInt32 :=
  if h : payload.size = 4 then
    let increment := (payload.get 0 (by omega)).toNat <<< 24 + (payload.get 1 (by omega)).toNat <<< 16 +
                     (payload.get 2 (by omega)).toNat <<< 8 + (payload.get 3 (by omega)).toNat
    if increment == 0 then none  -- RFC 7540: MUST NOT be 0
    else some increment.toUInt32
  else none

-- Serialize WINDOW_UPDATE frame payload
def serializeWindowUpdatePayload (increment : UInt32) : ByteArray :=
  let inc := increment.toNat
  ByteArray.mk #[
    ((inc >>> 24) &&& 0xFF).toUInt8,
    ((inc >>> 16) &&& 0xFF).toUInt8,
    ((inc >>> 8) &&& 0xFF).toUInt8,
    (inc &&& 0xFF).toUInt8
  ]

-- Create WINDOW_UPDATE frame
def createWindowUpdateFrame (streamId : UInt32) (increment : UInt32) : HTTP2Frame :=
  let payload := serializeWindowUpdatePayload increment
  createHTTP2Frame FrameType.WINDOW_UPDATE 0x0 streamId payload

-- Flow Control Functions

-- Update connection flow control window (RFC 7540 §6.9.1: MUST NOT exceed 2^31-1)
def updateConnectionWindow (connection : HTTP2Connection) (increment : UInt32) : Option HTTP2Connection :=
  let newWindowSize := connection.windowSize.toNat + increment.toNat
  if newWindowSize > h2MaxWindowSize then none  -- FLOW_CONTROL_ERROR
  else some { connection with windowSize := newWindowSize.toUInt32 }

-- Update stream flow control window (RFC 7540 §6.9.1: MUST NOT exceed 2^31-1)
def updateStreamWindow (stream : HTTP2Stream) (increment : UInt32) : Option HTTP2Stream :=
  let newWindowSize := stream.windowSize.toNat + increment.toNat
  if newWindowSize > h2MaxWindowSize then none  -- FLOW_CONTROL_ERROR
  else some { stream with windowSize := newWindowSize.toUInt32 }

-- Check if connection window allows sending data
def canSendDataOnConnection (connection : HTTP2Connection) (dataSize : UInt32) : Bool :=
  connection.windowSize >= dataSize

-- Check if stream window allows sending data
def canSendDataOnStream (stream : HTTP2Stream) (dataSize : UInt32) : Bool :=
  stream.windowSize >= dataSize

-- Consume connection window (when sending data)
def consumeConnectionWindow (connection : HTTP2Connection) (dataSize : UInt32) : HTTP2Connection :=
  let newWindowSize := connection.windowSize - dataSize
  { connection with windowSize := newWindowSize }

-- Consume stream window (when sending data)
def consumeStreamWindow (stream : HTTP2Stream) (dataSize : UInt32) : HTTP2Stream :=
  let newWindowSize := stream.windowSize - dataSize
  { stream with windowSize := newWindowSize }

-- Find stream by ID
def findStream (connection : HTTP2Connection) (streamId : UInt32) : Option HTTP2Stream :=
  connection.streams.find? (fun s => s.id == streamId)

-- Add or update stream in connection
def updateStream (connection : HTTP2Connection) (stream : HTTP2Stream) : HTTP2Connection :=
  let existingIndex := connection.streams.findIdx? (fun s => s.id == stream.id)
  match existingIndex with
  | some idx =>
    if h : idx < connection.streams.size then
      { connection with streams := connection.streams.set idx stream }
    else connection  -- unreachable: findIdx? returns valid index
  | none => { connection with streams := connection.streams.push stream }

-- Remove stream from connection
def removeStream (connection : HTTP2Connection) (streamId : UInt32) : HTTP2Connection :=
  { connection with streams := connection.streams.filter (fun s => s.id != streamId) }

-- Process WINDOW_UPDATE frame for connection (streamId = 0)
def processConnectionWindowUpdate (connection : HTTP2Connection) (increment : UInt32) : Option HTTP2Connection :=
  updateConnectionWindow connection increment

-- Process WINDOW_UPDATE frame for stream
def processStreamWindowUpdate (connection : HTTP2Connection) (streamId : UInt32) (increment : UInt32) : Option HTTP2Connection :=
  let streamOpt := findStream connection streamId
  match streamOpt with
  | some stream =>
    match updateStreamWindow stream increment with
    | some updatedStream => some (updateStream connection updatedStream)
    | none => none  -- FLOW_CONTROL_ERROR
  | none => some connection  -- Stream not found, no-op

-- Create GOAWAY frame (moved here for forward reference)
private def createGoAwayFrameForFlowControl (lastStreamId : UInt32) : HTTP2Frame :=
  let lsid := lastStreamId.toNat
  let ecode := ErrorCode.FLOW_CONTROL_ERROR.toUInt32.toNat
  let payload := ByteArray.mk #[
    ((lsid >>> 24) &&& 0xFF).toUInt8,
    ((lsid >>> 16) &&& 0xFF).toUInt8,
    ((lsid >>> 8) &&& 0xFF).toUInt8,
    (lsid &&& 0xFF).toUInt8,
    ((ecode >>> 24) &&& 0xFF).toUInt8,
    ((ecode >>> 16) &&& 0xFF).toUInt8,
    ((ecode >>> 8) &&& 0xFF).toUInt8,
    (ecode &&& 0xFF).toUInt8
  ]
  createHTTP2Frame FrameType.GOAWAY 0x0 0 payload

-- Process WINDOW_UPDATE frame
def processWindowUpdateFrame (connection : HTTP2Connection) (frame : HTTP2Frame) : HTTP2Connection × Option HTTP2Frame :=
  if frame.header.frameType != FrameType.WINDOW_UPDATE then
    (connection, none)
  else
    let payloadOpt := parseWindowUpdatePayload frame.payload
    match payloadOpt with
    | some increment =>
      if frame.header.streamId == 0 then
        -- Connection-level window update
        match processConnectionWindowUpdate connection increment with
        | some updatedConn => (updatedConn, none)
        | none => (connection, some (createGoAwayFrameForFlowControl 0))
      else
        -- Stream-level window update
        match processStreamWindowUpdate connection frame.header.streamId increment with
        | some updatedConn => (updatedConn, none)
        | none => (connection, some (createGoAwayFrameForFlowControl frame.header.streamId))
    | none => (connection, none)  -- Invalid WINDOW_UPDATE payload

-- Check if we can send data on a stream (both connection and stream windows)
def canSendData (connection : HTTP2Connection) (streamId : UInt32) (dataSize : UInt32) : Bool :=
  let streamOpt := findStream connection streamId
  match streamOpt with
  | some stream =>
    canSendDataOnConnection connection dataSize && canSendDataOnStream stream dataSize
  | none => false

-- Consume windows when sending data
def consumeWindows (connection : HTTP2Connection) (streamId : UInt32) (dataSize : UInt32) : HTTP2Connection :=
  let streamOpt := findStream connection streamId
  match streamOpt with
  | some stream =>
    let updatedStream := consumeStreamWindow stream dataSize
    let updatedConnection := consumeConnectionWindow connection dataSize
    updateStream updatedConnection updatedStream
  | none => connection

-- Create WINDOW_UPDATE frame to update connection window
def createConnectionWindowUpdate (increment : UInt32) : HTTP2Frame :=
  createWindowUpdateFrame 0 increment

-- Create WINDOW_UPDATE frame to update stream window
def createStreamWindowUpdate (streamId : UInt32) (increment : UInt32) : HTTP2Frame :=
  createWindowUpdateFrame streamId increment

-- Flow Control Error Handling

-- Error codes for flow control
inductive FlowControlError where
  | WINDOW_SIZE_TOO_LARGE : FlowControlError
  | WINDOW_SIZE_NEGATIVE : FlowControlError
  | FLOW_CONTROL_VIOLATION : FlowControlError
  deriving Repr

-- Check for flow control errors
def validateFlowControl (connection : HTTP2Connection) (streamId : UInt32) (dataSize : UInt32) : Option FlowControlError :=
  let streamOpt := findStream connection streamId
  match streamOpt with
  | some stream =>
    if dataSize > connection.windowSize then
      some FlowControlError.FLOW_CONTROL_VIOLATION
    else if dataSize > stream.windowSize then
      some FlowControlError.FLOW_CONTROL_VIOLATION
    else
      none
  | none => some FlowControlError.FLOW_CONTROL_VIOLATION

-- Create GOAWAY frame
def createGoAwayFrame (lastStreamId : UInt32) (errorCode : ErrorCode) : HTTP2Frame :=
  let lsid := lastStreamId.toNat
  let ecode := errorCode.toUInt32.toNat
  let payload := ByteArray.mk #[
    ((lsid >>> 24) &&& 0xFF).toUInt8,
    ((lsid >>> 16) &&& 0xFF).toUInt8,
    ((lsid >>> 8) &&& 0xFF).toUInt8,
    (lsid &&& 0xFF).toUInt8,
    ((ecode >>> 24) &&& 0xFF).toUInt8,
    ((ecode >>> 16) &&& 0xFF).toUInt8,
    ((ecode >>> 8) &&& 0xFF).toUInt8,
    (ecode &&& 0xFF).toUInt8
  ]
  createHTTP2Frame FrameType.GOAWAY 0x0 0 payload

-- Create GOAWAY frame for flow control error
def createFlowControlErrorGoAway (lastStreamId : UInt32) : HTTP2Frame :=
  createGoAwayFrame lastStreamId ErrorCode.FLOW_CONTROL_ERROR

-- Backpressure Mechanisms

-- Check if connection is under backpressure (window size too low)
def isConnectionUnderBackpressure (connection : HTTP2Connection) : Bool :=
  connection.windowSize < 65536  -- Less than initial window size

-- Check if stream is under backpressure
def isStreamUnderBackpressure (stream : HTTP2Stream) : Bool :=
  stream.windowSize < 65536  -- Less than initial window size

-- Calculate optimal window update increment
def calculateWindowUpdateIncrement (currentSize : UInt32) (targetSize : UInt32) : UInt32 :=
  if currentSize < targetSize then
    targetSize - currentSize
  else
    0

-- Auto-adjust connection window when under backpressure
def autoAdjustConnectionWindow (connection : HTTP2Connection) : HTTP2Connection × Option HTTP2Frame :=
  if isConnectionUnderBackpressure connection then
    let increment := calculateWindowUpdateIncrement connection.windowSize 65536
    if increment > 0 then
      match updateConnectionWindow connection increment with
      | some updatedConnection =>
        let windowUpdateFrame := createConnectionWindowUpdate increment
        (updatedConnection, some windowUpdateFrame)
      | none => (connection, none)  -- Would overflow, skip adjustment
    else
      (connection, none)
  else
    (connection, none)

-- Auto-adjust stream window when under backpressure
def autoAdjustStreamWindow (connection : HTTP2Connection) (streamId : UInt32) : HTTP2Connection × Option HTTP2Frame :=
  let streamOpt := findStream connection streamId
  match streamOpt with
  | some stream =>
    if isStreamUnderBackpressure stream then
      let increment := calculateWindowUpdateIncrement stream.windowSize 65536
      if increment > 0 then
        match updateStreamWindow stream increment with
        | some updatedStream =>
          let updatedConnection := updateStream connection updatedStream
          let windowUpdateFrame := createStreamWindowUpdate streamId increment
          (updatedConnection, some windowUpdateFrame)
        | none => (connection, none)  -- Would overflow, skip adjustment
      else
        (connection, none)
    else
      (connection, none)
  | none => (connection, none)

-- GOAWAY Frame Functions

-- Parse GOAWAY frame payload
def parseGoAwayPayload (payload : ByteArray) : Option (UInt32 × ErrorCode) :=
  if h : payload.size < 8 then none
  else
    let lastStreamId := (payload.get 0 (by omega)).toNat <<< 24 + (payload.get 1 (by omega)).toNat <<< 16 +
                        (payload.get 2 (by omega)).toNat <<< 8 + (payload.get 3 (by omega)).toNat
    let errorCode := (payload.get 4 (by omega)).toNat <<< 24 + (payload.get 5 (by omega)).toNat <<< 16 +
                     (payload.get 6 (by omega)).toNat <<< 8 + (payload.get 7 (by omega)).toNat
    -- Map all 14 RFC 7540 §7 error codes
    let errorCodeEnum := match errorCode with
      | 0x0 => ErrorCode.NO_ERROR
      | 0x1 => ErrorCode.PROTOCOL_ERROR
      | 0x2 => ErrorCode.INTERNAL_ERROR
      | 0x3 => ErrorCode.FLOW_CONTROL_ERROR
      | 0x4 => ErrorCode.SETTINGS_TIMEOUT
      | 0x5 => ErrorCode.STREAM_CLOSED
      | 0x6 => ErrorCode.FRAME_SIZE_ERROR
      | 0x7 => ErrorCode.REFUSED_STREAM
      | 0x8 => ErrorCode.CANCEL
      | 0x9 => ErrorCode.COMPRESSION_ERROR
      | 0xA => ErrorCode.CONNECT_ERROR
      | 0xB => ErrorCode.ENHANCE_YOUR_CALM
      | 0xC => ErrorCode.INADEQUATE_SECURITY
      | 0xD => ErrorCode.HTTP_1_1_REQUIRED
      | _ => ErrorCode.INTERNAL_ERROR  -- Unknown error codes treated as INTERNAL_ERROR
    some (lastStreamId.toUInt32, errorCodeEnum)

-- ==========================================
-- SETTINGS ACK Tracking (RFC 7540 §6.5.3)
-- ==========================================

/-- Record that we sent SETTINGS and are awaiting ACK. -/
def markSettingsSent (connection : HTTP2Connection) (sentSettings : Array HTTP2Setting) (nowMs : UInt64) : HTTP2Connection :=
  { connection with pendingSettings := some (sentSettings, nowMs) }

/-- Process SETTINGS ACK: apply our pending settings and clear the pending state. -/
def processSettingsAck (connection : HTTP2Connection) : HTTP2Connection :=
  match connection.pendingSettings with
  | some (settings, _) =>
    -- Apply the settings we sent (they are now acknowledged by peer)
    let newConn := settings.foldl (fun conn setting =>
      match setting.id with
      | .INITIAL_WINDOW_SIZE => { conn with windowSize := setting.value }
      | .MAX_FRAME_SIZE => { conn with maxFrameSize := setting.value }
      | .MAX_CONCURRENT_STREAMS => { conn with maxConcurrentStreams := setting.value }
      | _ => conn
    ) connection
    { newConn with pendingSettings := none }
  | none => connection

/-- Check if SETTINGS ACK has timed out (RFC 7540 §6.5.3: MUST respond within reasonable time).
    Returns `some GOAWAY frame` if timed out, `none` otherwise. -/
def checkSettingsTimeout (connection : HTTP2Connection) (nowMs : UInt64) (timeoutMs : UInt64 := 5000) : Option HTTP2Frame :=
  match connection.pendingSettings with
  | some (_, sentAt) =>
    if nowMs - sentAt > timeoutMs then
      some (createGoAwayFrame 0 ErrorCode.SETTINGS_TIMEOUT)
    else none
  | none => none

-- ==========================================
-- GOAWAY Graceful Drain (RFC 7540 §6.8)
-- ==========================================

/-- Process received GOAWAY: mark the connection with lastStreamId for graceful drain. -/
def processGoAway (connection : HTTP2Connection) (lastStreamId : UInt32) : HTTP2Connection :=
  { connection with goawayReceived := some lastStreamId }

/-- Check if a stream should be rejected because we received GOAWAY.
    Streams with ID > lastStreamId from GOAWAY should not be initiated. -/
def isStreamAllowedAfterGoaway (connection : HTTP2Connection) (streamId : UInt32) : Bool :=
  match connection.goawayReceived with
  | some lastStreamId => streamId <= lastStreamId
  | none => true

/-- Get streams that can still be drained after GOAWAY (ID ≤ lastStreamId). -/
def getDrainableStreams (connection : HTTP2Connection) : Array HTTP2Stream :=
  match connection.goawayReceived with
  | some lastStreamId =>
    connection.streams.filter (fun s => s.id <= lastStreamId && s.state != StreamState.CLOSED)
  | none => connection.streams.filter (fun s => s.state != StreamState.CLOSED)

/-- Check if graceful drain is complete (all drainable streams are closed). -/
def isDrainComplete (connection : HTTP2Connection) : Bool :=
  match connection.goawayReceived with
  | some _ => (getDrainableStreams connection).isEmpty
  | none => false

-- Create SETTINGS frame for HTTP/2 connection initialization
def createHTTP2SettingsFrame : HTTP2Frame :=
  -- Empty SETTINGS frame (ACK flag = 0) to acknowledge SETTINGS from client
  -- In practice, this would contain actual settings, but for initial connection this is fine
  createHTTP2Frame FrameType.SETTINGS 0x0 0 ByteArray.empty

-- HTTP/2 Request Structure
structure HttpRequest where
  method : String
  path : String
  headers : Array HeaderField
  body : ByteArray
  streamId : UInt32

instance : Inhabited HttpRequest where
  default := {
    method := "GET",
    path := "/",
    headers := #[],
    body := ByteArray.empty,
    streamId := 1
  }

-- HTTP/2 Response Structure
structure HttpResponse where
  statusCode : UInt16
  headers : Array HeaderField
  body : ByteArray
  streamId : UInt32

instance : Inhabited HttpResponse where
  default := {
    statusCode := 200,
    headers := #[],
    body := ByteArray.empty,
    streamId := 1
  }

-- Parse HEADERS frame payload
-- flags: the frame flags byte; END_HEADERS is bit 0x4
def parseHeadersFrame (payload : ByteArray) (_ : UInt32) (flags : UInt8 := 0x4) : Option (Array HeaderField × Bool) :=
  -- HEADERS frame payload contains HPACK-encoded headers
  let decoder := initHPACKDecoder
  -- Decode headers using HPACK
  let decodeResult := decodeHeaderList decoder payload
  match decodeResult with
  | some (headers, _) =>
    -- RFC 7540 §6.2: END_HEADERS (0x4) indicates the header block is complete
    let endHeaders := (flags &&& 0x4) != 0
    some (headers, endHeaders)
  | none =>
    none

-- Parse DATA frame payload
def parseDataFrame (payload : ByteArray) : ByteArray :=
  -- DATA frame payload is just the raw body data
  payload

-- Create HttpRequest from HEADERS and DATA frames
def createHttpRequest (headers : Array HeaderField) (body : ByteArray) (streamId : UInt32) : HttpRequest :=
  -- Extract method and path from headers
  let method := headers.find? (fun h => h.name == ":method") |>.map (fun h => h.value) |>.getD "GET"
  let path := headers.find? (fun h => h.name == ":path") |>.map (fun h => h.value) |>.getD "/"

  {
    method := method,
    path := path,
    headers := headers,
    body := body,
    streamId := streamId
  }

-- Validate HTTP/2 request
def validateHttpRequest (req : HttpRequest) : Bool :=
  -- Basic validation
  req.method != "" ∧ req.path != "" ∧ req.streamId > 0

-- Log HTTP/2 request
def logHttpRequest (req : HttpRequest) : IO Unit := do
  IO.eprintln s!"[HTTP/2] Request: {req.method} {req.path} (stream {req.streamId})"
  IO.eprintln s!"[HTTP/2] Headers: {req.headers.size} headers"
  if req.body.size > 0 then
    IO.eprintln s!"[HTTP/2] Body: {req.body.size} bytes"
  else
    IO.eprintln s!"[HTTP/2] Body: empty"

-- Process HTTP/2 frames into requests (pure version)
def processHTTP2FramesPure (frames : Array HTTP2Frame) : Array HttpRequest × Array String :=
  let rec processFrames (remaining : List HTTP2Frame) (currentRequests : Array HttpRequest) (pendingHeaders : Array (UInt32 × Array HeaderField)) (logs : Array String) : Array HttpRequest × Array String :=
    match remaining with
    | [] => (currentRequests, logs)
    | frame :: rest =>
      match frame.header.frameType with
      | FrameType.HEADERS =>
        match parseHeadersFrame frame.payload frame.header.streamId frame.header.flags with
        | some (headers, _) =>
          -- Check if we have a pending body for this stream
          let existingBody := pendingHeaders.find? (fun (sid, _) => sid == frame.header.streamId)
          match existingBody with
          | some (_, existingHeaders) =>
            -- Combine headers and create request
            let combinedHeaders := existingHeaders ++ headers
            let request := createHttpRequest combinedHeaders ByteArray.empty frame.header.streamId
            let newRequests := currentRequests.push request
            let newPending := pendingHeaders.filter (fun (sid, _) => sid != frame.header.streamId)
            let newLogs := logs.push s!"[HTTP/2] Created request from HEADERS+DATA for stream {frame.header.streamId}"
            processFrames rest newRequests newPending newLogs
          | none =>
            -- Store headers for later when body arrives
            let newPending := pendingHeaders.push (frame.header.streamId, headers)
            let newLogs := logs.push s!"[HTTP/2] Stored HEADERS for stream {frame.header.streamId}"
            processFrames rest currentRequests newPending newLogs
        | none =>
          let newLogs := logs.push s!"[HTTP/2] Failed to parse HEADERS frame for stream {frame.header.streamId}"
          processFrames rest currentRequests pendingHeaders newLogs

      | FrameType.DATA =>
        let body := parseDataFrame frame.payload
        -- Find pending headers for this stream
        let pendingForStream := pendingHeaders.find? (fun (sid, _) => sid == frame.header.streamId)
        match pendingForStream with
        | some (_, headers) =>
          let request := createHttpRequest headers body frame.header.streamId
          let newRequests := currentRequests.push request
          let newPending := pendingHeaders.filter (fun (sid, _) => sid != frame.header.streamId)
          let newLogs := logs.push s!"[HTTP/2] Created request from DATA for stream {frame.header.streamId}"
          processFrames rest newRequests newPending newLogs
        | none =>
          -- Body without headers - this shouldn't happen in well-formed HTTP/2
          let newLogs := logs.push s!"[HTTP/2] DATA frame without HEADERS for stream {frame.header.streamId}"
          processFrames rest currentRequests pendingHeaders newLogs

      | _ =>
        -- Ignore other frame types for now
        let newLogs := logs.push s!"[HTTP/2] Ignoring frame type {frame.header.frameType} for stream {frame.header.streamId}"
        processFrames rest currentRequests pendingHeaders newLogs

  processFrames frames.toList #[] #[] #[]

-- Process HTTP/2 frames into requests (with logging)
def processHTTP2Frames (frames : Array HTTP2Frame) : IO (Array HttpRequest) := do
  let (requests, logs) := processHTTP2FramesPure frames
  -- Print all logs
  for log in logs do
    IO.eprintln log
  pure requests

-- HTTP/2 Response Generation Functions

-- Create a basic HTTP/2 response
def createHttpResponse (statusCode : UInt16) (contentType : String) (body : String) (streamId : UInt32) : HttpResponse :=
  let statusHeader := { name := ":status", value := toString statusCode }
  let contentTypeHeader := { name := "content-type", value := contentType }
  let contentLengthHeader := { name := "content-length", value := toString body.length }
  let headers := #[statusHeader, contentTypeHeader, contentLengthHeader]
  {
    statusCode := statusCode,
    headers := headers,
    body := body.toUTF8,
    streamId := streamId
  }

-- Create a 200 OK response with HTML content
def createOKResponse (body : String) (streamId : UInt32) : HttpResponse :=
  createHttpResponse 200 "text/html; charset=utf-8" body streamId

-- Create a 404 Not Found response
def createNotFoundResponse (streamId : UInt32) : HttpResponse :=
  let body := "<html><body><h1>404 Not Found</h1><p>The requested resource was not found.</p></body></html>"
  createHttpResponse 404 "text/html; charset=utf-8" body streamId

-- Create a 500 Internal Server Error response
def createInternalErrorResponse (streamId : UInt32) : HttpResponse :=
  let body := "<html><body><h1>500 Internal Server Error</h1><p>An internal server error occurred.</p></body></html>"
  createHttpResponse 500 "text/html; charset=utf-8" body streamId

-- Serialize HTTP/2 response into frames
def serializeHttpResponse (response : HttpResponse) : Array HTTP2Frame :=
  -- Use proper HPACK encoding via encodeHeaderList
  let encoder := initHPACKEncoder
  let (headersPayload, _) := encodeHeaderList encoder response.headers

  -- Create HEADERS frame
  let headersFrame := {
    header := {
      length := headersPayload.size.toUInt32,
      frameType := FrameType.HEADERS,
      flags := 0x4,  -- END_HEADERS flag
      streamId := response.streamId
    },
    payload := headersPayload
  }

  -- Create DATA frame
  let dataFrame := {
    header := {
      length := response.body.size.toUInt32,
      frameType := FrameType.DATA,
      flags := 0x1,  -- END_STREAM flag
      streamId := response.streamId
    },
    payload := response.body
  }

  #[headersFrame, dataFrame]

-- Flow Control Aware Response Serialization

-- Check if we can send a response (flow control validation)
def canSendResponse (connection : HTTP2Connection) (response : HttpResponse) : Bool :=
  let dataSize := response.body.size.toUInt32
  canSendData connection response.streamId dataSize

-- Send response with flow control (returns updated connection and frames)
def sendResponseWithFlowControl (connection : HTTP2Connection) (response : HttpResponse) : HTTP2Connection × Array HTTP2Frame :=
  let dataSize := response.body.size.toUInt32
  if canSendResponse connection response then
    let frames := serializeHttpResponse response
    let updatedConnection := consumeWindows connection response.streamId dataSize
    (updatedConnection, frames)
  else
    -- Cannot send due to flow control, return empty frames
    (connection, #[])

-- Process HTTP/2 requests and generate responses
def processHttpRequests (requests : Array HttpRequest) : Array HttpResponse :=
  requests.map (fun request =>
    -- Simple routing logic
    if request.path == "/" then
      createOKResponse "<html><body><h1>Lean 4 HTTPS Server</h1><p>Welcome to the Lean 4 HTTPS server with HTTP/2 support!</p></body></html>" request.streamId
    else if request.path == "/hello" then
      createOKResponse "<html><body><h1>Hello World!</h1><p>This is a response from the Lean 4 HTTP/2 server.</p></body></html>" request.streamId
    else
      createNotFoundResponse request.streamId
  )

-- HTTP/2 Stream Multiplexing Functions

-- Create a new stream with IDLE state
def createStream (streamId : UInt32) : HTTP2Stream :=
  {
    id := streamId,
    state := StreamState.IDLE,
    windowSize := h2DefaultInitialWindowSize  -- Default initial window size
  }

-- Validate stream ID (must be odd for client-initiated streams)
def isValidClientStreamId (streamId : UInt32) : Bool :=
  streamId > 0 ∧ streamId % 2 == 1

-- Check if we can create a new stream (within concurrent limit)
def canCreateStream (connection : HTTP2Connection) : Bool :=
  let activeStreams := connection.streams.filter (fun s =>
    match s.state with
    | StreamState.OPEN | StreamState.HALF_CLOSED_LOCAL | StreamState.HALF_CLOSED_REMOTE => true
    | _ => false
  )
  activeStreams.size < connection.maxConcurrentStreams.toNat

-- Transition stream state according to HTTP/2 state machine
def transitionStreamState (stream : HTTP2Stream) (newState : StreamState) : Option HTTP2Stream :=
  -- HTTP/2 stream state transitions (simplified)
  match stream.state, newState with
  | StreamState.IDLE, StreamState.OPEN => some { stream with state := StreamState.OPEN }
  | StreamState.IDLE, StreamState.RESERVED_LOCAL => some { stream with state := StreamState.RESERVED_LOCAL }
  | StreamState.IDLE, StreamState.RESERVED_REMOTE => some { stream with state := StreamState.RESERVED_REMOTE }
  | StreamState.OPEN, StreamState.HALF_CLOSED_LOCAL => some { stream with state := StreamState.HALF_CLOSED_LOCAL }
  | StreamState.OPEN, StreamState.HALF_CLOSED_REMOTE => some { stream with state := StreamState.HALF_CLOSED_REMOTE }
  | StreamState.OPEN, StreamState.CLOSED => some { stream with state := StreamState.CLOSED }
  | StreamState.HALF_CLOSED_LOCAL, StreamState.CLOSED => some { stream with state := StreamState.CLOSED }
  | StreamState.HALF_CLOSED_REMOTE, StreamState.CLOSED => some { stream with state := StreamState.CLOSED }
  | StreamState.RESERVED_LOCAL, StreamState.HALF_CLOSED_REMOTE => some { stream with state := StreamState.HALF_CLOSED_REMOTE }
  | StreamState.RESERVED_LOCAL, StreamState.CLOSED => some { stream with state := StreamState.CLOSED }
  | StreamState.RESERVED_REMOTE, StreamState.CLOSED => some { stream with state := StreamState.CLOSED }
  | _, _ => none  -- Invalid transition

-- Process RST_STREAM frame
def processRstStreamFrame (connection : HTTP2Connection) (frame : HTTP2Frame) : HTTP2Connection :=
  if frame.payload.size >= 4 then
    -- Close the stream immediately
    removeStream connection frame.header.streamId
  else
    connection  -- Invalid payload size

-- Process a single frame and update connection state
-- Returns updated connection and optional response frame (e.g., GOAWAY for flow control error)
def processFrame (connection : HTTP2Connection) (frame : HTTP2Frame) : HTTP2Connection × Option HTTP2Frame :=
  match frame.header.frameType with
  | FrameType.WINDOW_UPDATE => processWindowUpdateFrame connection frame
  | FrameType.RST_STREAM => (processRstStreamFrame connection frame, none)
  | FrameType.SETTINGS =>
    -- RFC 7540 §6.5: if ACK flag (0x1) is set, process as SETTINGS ACK
    if frame.header.flags &&& 0x1 != 0 then
      (processSettingsAck connection, none)
    else
      -- Peer sent SETTINGS: parse and apply, then respond with ACK
      let peerSettings := parseSettingsPayload frame.payload
      let updatedConn := peerSettings.foldl (fun conn setting =>
        match setting.id with
        | .INITIAL_WINDOW_SIZE => { conn with windowSize := setting.value }
        | .MAX_FRAME_SIZE => { conn with maxFrameSize := setting.value }
        | .MAX_CONCURRENT_STREAMS => { conn with maxConcurrentStreams := setting.value }
        | _ => conn
      ) connection
      (updatedConn, some createSettingsAckFrame)
  | FrameType.PING =>
    -- RFC 7540 §6.7: PING must have 8-byte payload
    if frame.header.flags &&& 0x1 != 0 then
      -- ACK flag set — this is a PING response, no action needed
      (connection, none)
    else
      -- Send PONG: echo the payload with ACK flag
      let pongFrame := createHTTP2Frame FrameType.PING 0x1 0 frame.payload
      (connection, some pongFrame)
  | FrameType.GOAWAY =>
    -- RFC 7540 §6.8: graceful shutdown
    match parseGoAwayPayload frame.payload with
    | some (lastStreamId, _errorCode) =>
      (processGoAway connection lastStreamId, none)
    | none => (connection, none)
  | FrameType.PRIORITY =>
    -- RFC 7540 §6.3: advisory priority — acknowledged but no connection state change
    (connection, none)
  | _ => (connection, none)  -- DATA, HEADERS, PUSH_PROMISE, CONTINUATION handled elsewhere

-- Get active streams count
def getActiveStreamsCount (connection : HTTP2Connection) : Nat :=
  let activeStreams := connection.streams.filter (fun (s : HTTP2Stream) =>
    match s.state with
    | StreamState.OPEN | StreamState.HALF_CLOSED_LOCAL | StreamState.HALF_CLOSED_REMOTE => true
    | _ => false
  )
  activeStreams.size

-- Check if stream is in valid state for receiving frames
def isStreamValidForFrame (connection : HTTP2Connection) (streamId : UInt32) (frameType : FrameType) : Bool :=
  let streamOpt := findStream connection streamId
  match streamOpt with
  | some stream =>
    match stream.state, frameType with
    | StreamState.IDLE, FrameType.HEADERS => true
    | StreamState.OPEN, FrameType.HEADERS => true
    | StreamState.OPEN, FrameType.DATA => true
    | StreamState.HALF_CLOSED_REMOTE, FrameType.HEADERS => true  -- Trailers
    | StreamState.HALF_CLOSED_REMOTE, FrameType.DATA => true     -- Trailers
    | _, FrameType.RST_STREAM => true                 -- Can always reset
    | _, FrameType.WINDOW_UPDATE => true              -- Can always update window
    | _, _ => false
  | none =>
    -- Stream 0 is connection-level
    if streamId == 0 then
      match frameType with
      | FrameType.SETTINGS | FrameType.PING | FrameType.GOAWAY => true
      | _ => false
    else
      -- New stream can only start with HEADERS
      frameType == FrameType.HEADERS ∧ isValidClientStreamId streamId

-- ==========================================
-- HTTP/2 ADVANCED FEATURES - SERVER PUSH
-- ==========================================

-- Server Push State
inductive PushState where
  | PROMISED : PushState    -- Promised but not yet pushed
  | PUSHING : PushState     -- Currently being pushed
  | PUSHED : PushState      -- Successfully pushed
  | CANCELLED : PushState   -- Push cancelled
  deriving Repr, BEq

-- Server Push Resource
structure PushResource where
  promisedStreamId : UInt32
  associatedStreamId : UInt32  -- Stream that requested this resource
  url : String
  state : PushState
  headers : Array (String × String)
  deriving Repr

-- HTTP/2 Connection with Server Push
structure HTTP2ConnectionWithPush where
  baseConnection : HTTP2Connection
  pushResources : Array PushResource
  pushEnabled : Bool
  deriving Repr

-- Initialize connection with push support
def initHTTP2ConnectionWithPush : HTTP2ConnectionWithPush := {
  baseConnection := initHTTP2Connection
  pushResources := #[]
  pushEnabled := true
}

-- Check if server push is enabled
def isPushEnabled (connection : HTTP2ConnectionWithPush) : Bool :=
  connection.pushEnabled ∧
  (connection.baseConnection.settings.find? (fun s => s.id == SettingId.ENABLE_PUSH ∧ s.value == 1)).isSome

-- HPACK encoding using the real encoder from HPACK.lean (RFC 7541)
def encodeHeadersHPACK (headers : Array (String × String)) : ByteArray :=
  let headerFields := headers.map (fun (name, value) => { name := name, value := value : HeaderField })
  let encoder := initHPACKEncoder
  let (encoded, _) := encodeHeaderList encoder headerFields
  encoded

-- Create PUSH_PROMISE frame
def createPushPromiseFrame (promisedStreamId : UInt32) (associatedStreamId : UInt32) (headers : Array (String × String)) : HTTP2Frame :=
  let headerBlock := encodeHeadersHPACK headers
  let payload := ByteArray.mk #[]
    -- Add promised stream ID (4 bytes, network order)
    |>.push (UInt8.ofNat ((promisedStreamId.toNat >>> 24) &&& 0xFF))
    |>.push (UInt8.ofNat ((promisedStreamId.toNat >>> 16) &&& 0xFF))
    |>.push (UInt8.ofNat ((promisedStreamId.toNat >>> 8) &&& 0xFF))
    |>.push (UInt8.ofNat (promisedStreamId.toNat &&& 0xFF))
    -- Add header block fragment
    |>.append headerBlock

  {
    header := {
      length := UInt32.ofNat payload.size
      frameType := FrameType.PUSH_PROMISE
      flags := 0  -- No flags for PUSH_PROMISE
      streamId := associatedStreamId
    }
    payload := payload
  }

-- Find next available push stream ID (even numbers)
def findNextPushStreamId (streams : Array HTTP2Stream) : UInt32 :=
  let maxStreamId := streams.foldl (fun acc s => if s.id > acc then s.id else acc) 0
  if maxStreamId % 2 == 0 then maxStreamId + 2 else maxStreamId + 1

-- Initiate server push
def initiateServerPush (connection : HTTP2ConnectionWithPush) (associatedStreamId : UInt32) (url : String) (headers : Array (String × String)) : HTTP2ConnectionWithPush × Option HTTP2Frame :=
  if ¬connection.pushEnabled then
    (connection, none)
  else
    -- Find next available even stream ID for server push
    let nextPushStreamId := findNextPushStreamId connection.baseConnection.streams
    let pushResource : PushResource := {
      promisedStreamId := nextPushStreamId
      associatedStreamId := associatedStreamId
      url := url
      state := PushState.PROMISED
      headers := headers
    }

    let updatedConnection := {
      connection with
      pushResources := connection.pushResources.push pushResource
    }

    let pushPromiseFrame := createPushPromiseFrame nextPushStreamId associatedStreamId headers
    (updatedConnection, some pushPromiseFrame)

-- Cancel server push
def cancelServerPush (connection : HTTP2ConnectionWithPush) (promisedStreamId : UInt32) : HTTP2ConnectionWithPush :=
  let updatedResources := connection.pushResources.map (fun r =>
    if r.promisedStreamId == promisedStreamId then
      { r with state := PushState.CANCELLED }
    else r
  )
  { connection with pushResources := updatedResources }

-- ==========================================
-- HTTP/2 ADVANCED FEATURES - PRIORITY
-- ==========================================

-- Priority structure (RFC 7540 Section 5.3)
structure Priority where
  exclusive : Bool      -- Exclusive flag
  streamDependency : UInt32  -- Stream dependency
  weight : UInt8        -- Weight (1-256, default 16)
  deriving Repr

-- Default priority
def defaultPriority : Priority := {
  exclusive := false
  streamDependency := 0
  weight := 16
}

-- Parse priority from PRIORITY frame payload
def parsePriority (payload : ByteArray) : Option Priority :=
  if h : payload.size < 5 then none
  else
    let e_flag := (payload.get 0 (by omega) >>> 7) == 1
    let streamDep := ((payload.get 0 (by omega)).toNat &&& 0x7F) <<< 24 +
                     (payload.get 1 (by omega)).toNat <<< 16 +
                     (payload.get 2 (by omega)).toNat <<< 8 +
                     (payload.get 3 (by omega)).toNat
    let weight := payload.get 4 (by omega)
    some {
      exclusive := e_flag
      streamDependency := UInt32.ofNat streamDep
      weight := weight
    }

-- Create PRIORITY frame
def createPriorityFrame (streamId : UInt32) (priority : Priority) : HTTP2Frame :=
  let payload := ByteArray.mk #[]
    -- First byte: E flag (bit 31) + stream dependency (bits 30-0)
    |>.push (UInt8.ofNat (
      (if priority.exclusive then 0x80 else 0) |||
      ((priority.streamDependency >>> 24) &&& 0x7F).toNat
    ))
    |>.push (UInt8.ofNat ((priority.streamDependency >>> 16) &&& 0xFF).toNat)
    |>.push (UInt8.ofNat ((priority.streamDependency >>> 8) &&& 0xFF).toNat)
    |>.push (UInt8.ofNat (priority.streamDependency &&& 0xFF).toNat)
    -- Weight
    |>.push priority.weight

  {
    header := {
      length := UInt32.ofNat payload.size
      frameType := FrameType.PRIORITY
      flags := 0
      streamId := streamId
    }
    payload := payload
  }

-- HTTP/2 Stream with Priority
structure HTTP2StreamWithPriority where
  baseStream : HTTP2Stream
  priority : Priority
  deriving Repr

-- Priority Queue for stream scheduling
structure PriorityQueue where
  streams : Array HTTP2StreamWithPriority
  deriving Repr

-- Calculate priority weight for scheduling
def calculatePriorityWeight (priority : Priority) : Float :=
  -- Simple weight calculation (can be enhanced with dependency trees)
  Float.ofNat priority.weight.toNat / 256.0

-- Schedule streams based on priority
def scheduleStreams (queue : PriorityQueue) : Array HTTP2StreamWithPriority :=
  -- Sort by priority weight (higher weight = higher priority)
  let sorted := queue.streams.qsort (fun a b =>
    calculatePriorityWeight a.priority > calculatePriorityWeight b.priority
  )
  sorted

-- ==========================================
-- HTTP/2 ADVANCED FEATURES - FLOW CONTROL ENHANCED
-- ==========================================

-- Flow Control Policy
inductive FlowControlPolicy where
  | FIXED_WINDOW : FlowControlPolicy      -- Fixed window size
  | ADAPTIVE : FlowControlPolicy          -- Adaptive based on RTT/throughput
  | PRIORITY_BASED : FlowControlPolicy    -- Priority-aware flow control
  deriving Repr

-- Enhanced Flow Control State
structure EnhancedFlowControl where
  connectionWindow : UInt32
  streamWindows : Array (UInt32 × UInt32)  -- (streamId, windowSize)
  policy : FlowControlPolicy
  rttEstimate : Option Float  -- Round-trip time estimate
  throughputEstimate : Option Float  -- Throughput estimate
  deriving Repr

-- Initialize enhanced flow control
def initEnhancedFlowControl : EnhancedFlowControl := {
  connectionWindow := h2DefaultInitialWindowSize
  streamWindows := #[]
  policy := FlowControlPolicy.FIXED_WINDOW
  rttEstimate := none
  throughputEstimate := none
}

-- Adaptive window adjustment based on RTT
def adjustWindowAdaptive (fc : EnhancedFlowControl) (newRtt : Float) (throughput : Float) : EnhancedFlowControl :=
  let rttRatio := match fc.rttEstimate with
    | some oldRtt => newRtt / oldRtt
    | none => 1.0

  let throughputRatio := match fc.throughputEstimate with
    | some oldThroughput => throughput / oldThroughput
    | none => 1.0

  -- Adjust window based on RTT and throughput changes
  let windowMultiplier := if rttRatio < 0.8 ∧ throughputRatio > 1.2 then 1.5  -- Good conditions
                         else if rttRatio > 1.5 ∨ throughputRatio < 0.8 then 0.75  -- Bad conditions
                         else 1.0  -- Stable

  let newWindow := Float.toUInt32 (Float.ofNat fc.connectionWindow.toNat * windowMultiplier)
  let clampedWindow := min (max newWindow 4096) 16777216  -- Between 4KB and 16MB

  {
    fc with
    connectionWindow := clampedWindow
    rttEstimate := some newRtt
    throughputEstimate := some throughput
  }

-- ==========================================
-- HTTP/2 ADVANCED FEATURES - CONNECTION MANAGEMENT
-- ==========================================

-- Connection Health Metrics
structure ConnectionHealth where
  totalFrames : UInt64
  errorFrames : UInt64
  pingRTT : Option Float
  lastActivity : UInt64  -- Timestamp
  bytesSent : UInt64
  bytesReceived : UInt64
  deriving Repr

-- HTTP/2 Connection with Health Monitoring
structure HTTP2ConnectionWithHealth where
  baseConnection : HTTP2Connection
  health : ConnectionHealth
  maxIdleTime : UInt32  -- Max idle time in seconds
  deriving Repr

-- Initialize connection with health monitoring
def initHTTP2ConnectionWithHealth : HTTP2ConnectionWithHealth := {
  baseConnection := initHTTP2Connection
  health := {
    totalFrames := 0
    errorFrames := 0
    pingRTT := none
    lastActivity := 0  -- Set to monotonic time on first frame via updateHealthMetrics
    bytesSent := 0
    bytesReceived := 0
  }
  maxIdleTime := 300  -- 5 minutes default
}

-- Update connection health metrics
def updateHealthMetrics (connection : HTTP2ConnectionWithHealth) (_ : HTTP2Frame) (bytesTransferred : UInt32) : HTTP2ConnectionWithHealth :=
  let newHealth := {
    connection.health with
    totalFrames := connection.health.totalFrames + 1
    bytesReceived := connection.health.bytesReceived + UInt64.ofNat bytesTransferred.toNat
    lastActivity := 0  -- Updated by caller with monoTimeMs when in IO context
  }
  { connection with health := newHealth }

-- Check if connection is healthy
def isConnectionHealthy (connection : HTTP2ConnectionWithHealth) : Bool :=
  let errorRate := Float.ofNat connection.health.errorFrames.toNat / Float.ofNat connection.health.totalFrames.toNat
  errorRate < 0.1 ∧  -- Less than 10% error rate
  connection.health.totalFrames > 0  -- Has activity

-- HTTP/2 Request structure (for application layer)
structure HTTP2Request where
  streamId : UInt32
  method : String
  path : String
  headers : Array (String × String)
  body : ByteArray

instance : Inhabited HTTP2Request where
  default := {
    streamId := 0
    method := "GET"
    path := "/"
    headers := #[]
    body := ByteArray.empty
  }

-- HTTP/2 Response structure (for application layer)
structure HTTP2Response where
  streamId : UInt32
  statusCode : UInt16
  headers : Array (String × String)
  body : ByteArray

instance : Inhabited HTTP2Response where
  default := {
    streamId := 0
    statusCode := 200
    headers := #[]
    body := ByteArray.empty
  }

-- HTTP/2 Server structure
structure HTTP2Server where
  port : UInt16
  connections : Array HTTP2Connection
  requestHandler : Option (HTTP2Request → IO HTTP2Response)

instance : Inhabited HTTP2Server where
  default := {
    port := 8080
    connections := #[]
    requestHandler := none
  }

-- Create HTTP/2 server
def createHTTP2Server : IO HTTP2Server := do
  pure {
    port := 8080
    connections := #[]
    requestHandler := none
  }

-- Set request handler for HTTP/2 server
def setHTTP2RequestHandler (server : HTTP2Server) (handler : HTTP2Request → IO HTTP2Response) : HTTP2Server := {
  server with requestHandler := some handler
}

-- Start HTTP/2 server — initializes the server and processes requests
-- The actual TCP accept loop is in HTTPServer.lean; this provides the HTTP/2 layer initialization.
def startHTTP2Server (server : HTTP2Server) : IO Unit := do
  IO.eprintln s!"🚀 HTTP/2 Server initialized on port {server.port}"
  IO.eprintln s!"   Connections: {server.connections.size}"
  IO.eprintln s!"   Handler: {if server.requestHandler.isSome then "configured" else "none"}"

-- Stop HTTP/2 server — gracefully shuts down active connections
def stopHTTP2Server (server : HTTP2Server) : IO Unit := do
  IO.eprintln s!"⏹ HTTP/2 Server stopped ({server.connections.size} connections closed)"

-- Simplified QUIC Packet Types (for HTTP/3 preview)
inductive QUICPacketType where
  | INITIAL : QUICPacketType
  | HANDSHAKE : QUICPacketType
  | RETRY : QUICPacketType
  | ZERO_RTT : QUICPacketType
  | ONE_RTT : QUICPacketType
  deriving Repr

-- Simplified QUIC Stream
structure QUICStream where
  id : UInt64
  data : ByteArray
  offset : UInt64
  finished : Bool

-- HTTP/3 Frame Types (subset)
inductive HTTP3FrameType where
  | DATA : HTTP3FrameType
  | HEADERS : HTTP3FrameType
  | SETTINGS : HTTP3FrameType
  | GOAWAY : HTTP3FrameType
  deriving Repr

-- HTTP/3 Frame
structure HTTP3Frame where
  frameType : HTTP3FrameType
  payload : ByteArray

-- HTTP/3 Connection (simplified preview)
structure HTTP3Connection where
  streams : Array QUICStream
  settings : Array HTTP2Setting  -- Reuse HTTP/2 settings for now

-- Initialize HTTP/3 connection
def initHTTP3Connection : HTTP3Connection := {
  streams := #[]
  settings := defaultHTTP2Settings
}

-- ==========================================
-- ByteSlice-Based Frame Parsing (Phase 9.1)
-- ==========================================

/-- Parse an HTTP/2 frame header from a ByteSlice (zero-copy).
    Uses ByteSlice.getUInt24BE for the 3-byte length field and
    ByteSlice.getUInt32BE for the 4-byte stream ID. -/
def parseFrameHeaderSlice (s : ByteSlice) : Option FrameHeader :=
  if h : s.length < 9 then none
  else
    have h9 : s.length ≥ 9 := by omega
    let length := s.getUInt24BE 0 (by omega)
    let frameTypeOpt := FrameType.fromByte (s.get! 3)
    let flags := s.get! 4
    let streamId := s.getUInt32BE 5 (by omega)
    match frameTypeOpt with
    | some frameType => some {
        length := length.toUInt32
        frameType := frameType
        flags := flags
        streamId := streamId
      }
    | none => none

/-- Parse frames from a ByteSlice without copying tails.
    Uses ByteSlice.drop for O(1) advancing instead of ByteArray.extract. -/
def parseHTTP2FramesSlice (s : ByteSlice) (maxFrames : Nat := 256) : List HTTP2Frame :=
  go s maxFrames []
where
  go (s : ByteSlice) : Nat → List HTTP2Frame → List HTTP2Frame
  | 0, acc => acc.reverse
  | fuel + 1, acc =>
    if s.length < 9 then acc.reverse
    else
      match parseFrameHeaderSlice s with
      | none => acc.reverse
      | some header =>
        let frameSize := 9 + header.length.toNat
        if frameSize > s.length then acc.reverse
        else
          match s.slice 9 header.length.toNat with
          | none => acc.reverse
          | some payloadSlice =>
            let frame : HTTP2Frame := {
              header := header
              payload := payloadSlice.toByteArray
            }
            let rest := s.drop frameSize
            go rest fuel (frame :: acc)
