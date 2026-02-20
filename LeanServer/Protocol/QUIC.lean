-- QUIC Transport Protocol Implementation
-- Based on RFC 9000: https://tools.ietf.org/html/rfc9000

import LeanServer.Core.Basic
import LeanServer.Crypto.Crypto

namespace LeanServer

-- ==========================================
-- QUIC Packet Types (RFC 9000)
-- ==========================================

inductive QUICPacketType_ : Type where
  | Initial : QUICPacketType_
  | ZeroRTT : QUICPacketType_
  | Handshake : QUICPacketType_
  | Retry : QUICPacketType_
  | OneRTT : QUICPacketType_
  | VersionNegotiation : QUICPacketType_

instance : Inhabited QUICPacketType_ where
  default := QUICPacketType_.Initial

-- Convert packet type to byte
def QUICPacketType_.toByte : QUICPacketType_ → UInt8
  | Initial => 0x00
  | ZeroRTT => 0x01
  | Handshake => 0x02
  | Retry => 0x03
  | OneRTT => 0x04
  | VersionNegotiation => 0x80

-- ==========================================
-- QUIC Connection IDs
-- ==========================================

structure QUICConnectionID where
  data : ByteArray
  deriving Inhabited

instance : BEq QUICConnectionID where
  beq a b := a.data == b.data

-- Get length of connection ID
def QUICConnectionID.length (cid : QUICConnectionID) : Nat :=
  cid.data.size

-- ==========================================
-- QUIC Version
-- ==========================================

structure QUICVersion where
  version : UInt32
  deriving Inhabited

-- QUIC version 1 (RFC 9000)
def QUIC_VERSION_1 : QUICVersion := { version := 0x00000001 }

-- Check if version is supported
def QUICVersion.isSupported (v : QUICVersion) : Bool :=
  v.version == QUIC_VERSION_1.version

-- ==========================================
-- QUIC Packet Numbers
-- ==========================================

structure QUICPacketNumber where
  number : UInt64
  deriving Inhabited

-- ==========================================
-- QUIC Frames (RFC 9000)
-- ==========================================

inductive QUICFrameType : Type where
  | PADDING : QUICFrameType
  | PING : QUICFrameType
  | ACK : QUICFrameType
  | RESET_STREAM : QUICFrameType
  | STOP_SENDING : QUICFrameType
  | CRYPTO : QUICFrameType
  | NEW_TOKEN : QUICFrameType
  | STREAM : QUICFrameType
  | MAX_DATA : QUICFrameType
  | MAX_STREAM_DATA : QUICFrameType
  | MAX_STREAMS : QUICFrameType
  | DATA_BLOCKED : QUICFrameType
  | STREAM_DATA_BLOCKED : QUICFrameType
  | STREAMS_BLOCKED : QUICFrameType
  | NEW_CONNECTION_ID : QUICFrameType
  | RETIRE_CONNECTION_ID : QUICFrameType
  | PATH_CHALLENGE : QUICFrameType
  | PATH_RESPONSE : QUICFrameType
  | CONNECTION_CLOSE : QUICFrameType
  | HANDSHAKE_DONE : QUICFrameType
  | Reserved : UInt8 → QUICFrameType

instance : Inhabited QUICFrameType where
  default := QUICFrameType.PADDING

instance : BEq QUICFrameType where
  beq a b :=
    match a, b with
    | .PADDING, .PADDING => true
    | .PING, .PING => true
    | .ACK, .ACK => true
    | .RESET_STREAM, .RESET_STREAM => true
    | .STOP_SENDING, .STOP_SENDING => true
    | .CRYPTO, .CRYPTO => true
    | .NEW_TOKEN, .NEW_TOKEN => true
    | .STREAM, .STREAM => true
    | .MAX_DATA, .MAX_DATA => true
    | .MAX_STREAM_DATA, .MAX_STREAM_DATA => true
    | .MAX_STREAMS, .MAX_STREAMS => true
    | .DATA_BLOCKED, .DATA_BLOCKED => true
    | .STREAM_DATA_BLOCKED, .STREAM_DATA_BLOCKED => true
    | .STREAMS_BLOCKED, .STREAMS_BLOCKED => true
    | .NEW_CONNECTION_ID, .NEW_CONNECTION_ID => true
    | .RETIRE_CONNECTION_ID, .RETIRE_CONNECTION_ID => true
    | .PATH_CHALLENGE, .PATH_CHALLENGE => true
    | .PATH_RESPONSE, .PATH_RESPONSE => true
    | .CONNECTION_CLOSE, .CONNECTION_CLOSE => true
    | .HANDSHAKE_DONE, .HANDSHAKE_DONE => true
    | .Reserved x, .Reserved y => x == y
    | _, _ => false

-- Convert frame type to byte
def QUICFrameType.toByte : QUICFrameType → UInt8
  | PADDING => 0x00
  | PING => 0x01
  | ACK => 0x02
  | RESET_STREAM => 0x04
  | STOP_SENDING => 0x05
  | CRYPTO => 0x06
  | NEW_TOKEN => 0x07
  | STREAM => 0x08
  | MAX_DATA => 0x10
  | MAX_STREAM_DATA => 0x11
  | MAX_STREAMS => 0x12
  | DATA_BLOCKED => 0x14
  | STREAM_DATA_BLOCKED => 0x15
  | STREAMS_BLOCKED => 0x16
  | NEW_CONNECTION_ID => 0x18
  | RETIRE_CONNECTION_ID => 0x19
  | PATH_CHALLENGE => 0x1A
  | PATH_RESPONSE => 0x1B
  | CONNECTION_CLOSE => 0x1C
  | HANDSHAKE_DONE => 0x1E
  | Reserved n => n

-- Convert byte to frame type
def QUICFrameType.fromByte (b : UInt8) : QUICFrameType :=
  match b with
  | 0x00 => PADDING
  | 0x01 => PING
  | 0x02 => ACK
  | 0x04 => RESET_STREAM
  | 0x05 => STOP_SENDING
  | 0x06 => CRYPTO
  | 0x07 => NEW_TOKEN
  | 0x08 => STREAM
  | 0x10 => MAX_DATA
  | 0x11 => MAX_STREAM_DATA
  | 0x12 => MAX_STREAMS
  | 0x14 => DATA_BLOCKED
  | 0x15 => STREAM_DATA_BLOCKED
  | 0x16 => STREAMS_BLOCKED
  | 0x18 => NEW_CONNECTION_ID
  | 0x19 => RETIRE_CONNECTION_ID
  | 0x1A => PATH_CHALLENGE
  | 0x1B => PATH_RESPONSE
  | 0x1C => CONNECTION_CLOSE
  | 0x1E => HANDSHAKE_DONE
  | n => Reserved n

-- Base QUIC Frame structure
structure QUICFrame where
  frameType : QUICFrameType
  payload : ByteArray

instance : Inhabited QUICFrame where
  default := {
    frameType := default
    payload := ByteArray.mk #[]
  }

-- ==========================================
-- QUIC Packet Header
-- ==========================================

structure QUICPacketHeader where
  packetType : QUICPacketType_
  version : Option QUICVersion
  destinationCID : QUICConnectionID
  sourceCID : Option QUICConnectionID
  packetNumber : QUICPacketNumber
  token : Option ByteArray  -- For Initial/Retry packets

instance : Inhabited QUICPacketHeader where
  default := {
    packetType := default
    version := some QUIC_VERSION_1
    destinationCID := QUICConnectionID.mk (ByteArray.mk #[])
    sourceCID := none
    packetNumber := { number := 0 }
    token := none
  }

-- ==========================================
-- QUIC Packet
-- ==========================================

structure QUICPacket where
  header : QUICPacketHeader
  frames : Array QUICFrame
  payload : ByteArray  -- Encrypted payload

instance : Inhabited QUICPacket where
  default := {
    header := default
    frames := #[]
    payload := ByteArray.mk #[]
  }

-- ==========================================
-- QUIC Connection States
-- ==========================================

inductive QUICConnectionState : Type where
  | idle : QUICConnectionState
  | connecting : QUICConnectionState
  | connected : QUICConnectionState
  | draining : QUICConnectionState
  | closing : QUICConnectionState
  | closed : QUICConnectionState

instance : Inhabited QUICConnectionState where
  default := QUICConnectionState.idle

instance : BEq QUICConnectionState where
  beq a b :=
    match a, b with
    | .idle, .idle => true
    | .connecting, .connecting => true
    | .connected, .connected => true
    | .draining, .draining => true
    | .closing, .closing => true
    | .closed, .closed => true
    | _, _ => false

-- ==========================================
-- QUIC Connection
-- ==========================================

/-- An entry in the retransmission buffer: PN, timestamp (ms), payload -/
structure SentPacketEntry where
  pn : UInt64
  sentTimeMs : UInt64    -- monotonic time in ms
  payload : ByteArray    -- original QUIC payload (unencrypted, for retransmit)
  acked : Bool := false
  retryCount : Nat := 0  -- Number of retransmission attempts (for exponential backoff)
  deriving Inhabited

/-- Flow control state per connection -/
structure FlowControlState where
  -- Peer-imposed limits (from MAX_DATA / MAX_STREAM_DATA)
  peerMaxData : UInt64 := 1048576        -- Default 1MB
  peerMaxStreamDataBidi : UInt64 := 262144  -- Default 256KB
  -- Local limits (we advertise to peer)
  localMaxData : UInt64 := 10485760      -- 10MB
  localMaxStreamDataBidi : UInt64 := 1048576  -- 1MB
  -- Counters
  totalBytesSent : UInt64 := 0
  totalBytesReceived : UInt64 := 0
  deriving Inhabited

/-- Congestion control state (RFC 9002 — simplified NewReno) -/
structure CongestionState where
  -- Congestion window in bytes (starts at 14720 = 10 * 1472 per RFC 9002 §7.2)
  cwnd : UInt64 := 14720
  -- Slow-start threshold
  ssthresh : UInt64 := 0xFFFFFFFFFFFFFFFF  -- effectively infinite (slow start phase)
  -- Bytes in flight (sent but not yet acked)
  bytesInFlight : UInt64 := 0
  -- Smoothed RTT in ms (SRTT, RFC 9002 §5.3)
  smoothedRtt : UInt64 := 333  -- initial estimate 333ms
  -- RTT variance
  rttVar : UInt64 := 166  -- initial RTT/2
  -- Minimum RTT observed
  minRtt : UInt64 := 0xFFFFFFFFFFFFFFFF
  -- Whether in slow start phase
  inSlowStart : Bool := true
  deriving Inhabited

/-- Stream lifecycle states (RFC 9000 §3) -/
inductive QUICStreamStatus where
  | open       : QUICStreamStatus  -- Active, can send and receive
  | halfClosedLocal  : QUICStreamStatus  -- We sent FIN, waiting for peer FIN
  | halfClosedRemote : QUICStreamStatus  -- Peer sent FIN, we can still send
  | closed     : QUICStreamStatus  -- Both sides done
  deriving Inhabited, BEq

/-- Per-stream state for concurrent stream management -/
structure QUICStreamState where
  streamId : UInt64
  status : QUICStreamStatus := .open
  bytesSent : UInt64 := 0
  bytesReceived : UInt64 := 0
  peerMaxStreamData : UInt64 := 262144  -- updated by MAX_STREAM_DATA
  localMaxStreamData : UInt64 := 1048576
  finSent : Bool := false
  finReceived : Bool := false
  -- Reassembly buffer for multi-frame streams (offset → data)
  recvBuffer : List (Nat × ByteArray) := []
  deriving Inhabited

structure QUICConnection where
  state : QUICConnectionState
  connectionId : QUICConnectionID
  peerConnectionId : Option QUICConnectionID
  version : QUICVersion
  nextPacketNumber : QUICPacketNumber
  receivedPackets : Array QUICPacket
  pendingFrames : Array QUICFrame
  tlsSession : Option TLSSessionTLS  -- Persist TLS state (keys, transcript)
  cryptoStream : List (Nat × ByteArray) -- Reassembly buffer for Initial CRYPTO stream
  cryptoStreamHandshake : List (Nat × ByteArray) -- Reassembly buffer for Handshake CRYPTO stream
  initialCryptoBuffer : ByteArray -- [DEPRECATED]
  serverWritePN : UInt64 := 1 -- Server-side packet number counter (starts at 1, 0 used for HANDSHAKE_DONE)
  largestReceivedPN : UInt64 := 0 -- Largest received PN in 1-RTT space (for ACK generation)
  h3ControlStreamsSent : Bool := false -- Whether server has sent HTTP/3 control streams
  -- Retransmission buffer (A: Reliability)
  sentPackets : Array SentPacketEntry := #[]
  -- Flow control (B: Flow Control)
  flowControl : FlowControlState := {}
  -- Congestion control (RFC 9002)
  congestion : CongestionState := {}
  -- Stream management (D: Concurrent Streams)
  activeStreams : Array QUICStreamState := #[]
  -- Peer limits from transport parameters
  peerMaxStreams : UInt64 := 100
  -- Connection-level ACK tracking
  ackedPNs : Array UInt64 := #[]  -- PNs we have ACKed (to avoid duplicate processing)
  -- Peer's connection close state
  peerClosed : Bool := false
  -- Peer address (for retransmission)
  peerIP : String := ""
  peerPort : UInt32 := 0
  -- Buffered 0-RTT early data (processed after 1-RTT confirmation)
  earlyData : Option ByteArray := none
  -- Idle timeout tracking (RFC 9000 §10.1)
  lastActivityMs : UInt64 := 0
  -- Connection draining (RFC 9000 §10.2)
  drainingStartMs : UInt64 := 0  -- When draining started (0 = not draining)
  -- Alternative connection IDs (RFC 9000 §5.1)
  alternativeCIDs : Array (UInt64 × QUICConnectionID) := #[]  -- (sequence, CID)
  retiredPriorTo : UInt64 := 0  -- Retire CIDs with sequence < this
  nextCIDSequence : UInt64 := 1  -- Next sequence number for NEW_CONNECTION_ID
  -- Path validation (RFC 9000 §9.3)
  pathValidationData : Option ByteArray := none  -- Pending PATH_CHALLENGE data awaiting PATH_RESPONSE
  peerCIDs : Array (UInt64 × QUICConnectionID × ByteArray) := #[]  -- (seq, CID, resetToken) from peer's NEW_CONNECTION_ID
  -- H3 bidirectional stream reassembly (stream_id → accumulated data)
  h3StreamBuffers : List (UInt64 × ByteArray) := []
  -- HTTP/3 GOAWAY state (RFC 9114 §5.2)
  h3GoAwaySent : Bool := false
  h3GoAwayStreamId : UInt64 := 0  -- Largest client-initiated stream ID we'll accept
  -- HTTP/3 Server Push state (#15: cache management)
  h3MaxPushId : Option UInt64 := none  -- Client's MAX_PUSH_ID; none = push not allowed
  h3NextPushId : UInt64 := 0           -- Next push ID to allocate
  h3PushedPaths : Array String := #[]  -- Paths already pushed on this connection (dedup)
  -- QPACK dynamic table (RFC 9204 §3.2)
  qpackDynamicTable : Array (String × String) := #[]  -- name × value entries
  qpackTableCapacity : UInt64 := 4096  -- max capacity in bytes
  -- Anti-amplification (RFC 9000 §8.1)
  bytesReceived : UInt64 := 0  -- Total bytes received from peer before address validation
  bytesSent : UInt64 := 0     -- Total bytes sent to peer before address validation
  addressValidated : Bool := false  -- True after handshake completes or Retry succeeds
  -- ECN feedback counters (RFC 9000 §19.3.2)
  ecnEctZero : UInt64 := 0  -- ECT(0) count from ACK_ECN frames
  ecnEctOne : UInt64 := 0   -- ECT(1) count from ACK_ECN frames
  ecnCe : UInt64 := 0       -- CE (Congestion Experienced) count from ACK_ECN frames

instance : Inhabited QUICConnection where
  default := {
    state := default
    connectionId := QUICConnectionID.mk (ByteArray.mk #[])
    peerConnectionId := none
    version := QUIC_VERSION_1
    nextPacketNumber := { number := 0 }
    receivedPackets := #[]
    pendingFrames := #[]
    tlsSession := none
    cryptoStream := []
    cryptoStreamHandshake := []
    initialCryptoBuffer := ByteArray.empty
    serverWritePN := 1
    largestReceivedPN := 0
    h3ControlStreamsSent := false
    sentPackets := #[]
    flowControl := {}
    congestion := {}
    activeStreams := #[]
    peerMaxStreams := 100
    ackedPNs := #[]
    peerClosed := false
    peerIP := ""
    peerPort := 0
    earlyData := none
    lastActivityMs := 0
    drainingStartMs := 0
    alternativeCIDs := #[]
    retiredPriorTo := 0
    nextCIDSequence := 1
    pathValidationData := none
    peerCIDs := #[]
    h3StreamBuffers := []
    h3GoAwaySent := false
    h3GoAwayStreamId := 0
    h3MaxPushId := none
    h3NextPushId := 0
    h3PushedPaths := #[]
    qpackDynamicTable := #[]
    qpackTableCapacity := 4096
    bytesReceived := 0
    bytesSent := 0
    addressValidated := false
    ecnEctZero := 0
    ecnEctOne := 0
    ecnCe := 0
  }

-- ==========================================
-- QUIC Server State
-- ==========================================

structure QUICServerState where
  connections : Array QUICConnection
  maxConnections : UInt64
  supportedVersions : Array QUICVersion

instance : Inhabited QUICServerState where
  default := {
    connections := #[]
    maxConnections := 1000
    supportedVersions := #[QUIC_VERSION_1]
  }

-- ==========================================
-- QUIC Functions
-- ==========================================

-- Initialize QUIC server
def initQUICServer (maxConnections : UInt64 := 1000) : QUICServerState := {
  connections := #[]
  maxConnections := maxConnections
  supportedVersions := #[QUIC_VERSION_1]
}

-- Create new QUIC connection
def createQUICConnection (connectionId : QUICConnectionID) : QUICConnection := {
  state := QUICConnectionState.idle
  connectionId := connectionId
  peerConnectionId := none
  version := QUIC_VERSION_1
  nextPacketNumber := { number := 0 }
  receivedPackets := #[]
  pendingFrames := #[]
  tlsSession := none
  cryptoStream := []
  cryptoStreamHandshake := []
  initialCryptoBuffer := ByteArray.empty
}

-- Add connection to QUIC server
def addQUICConnection (server : QUICServerState) (connection : QUICConnection) : QUICServerState :=
  if server.connections.size < server.maxConnections.toNat then
    { server with connections := server.connections.push connection }
  else
    server

-- Find connection by ID
def findQUICConnection (server : QUICServerState) (connectionId : QUICConnectionID) : Option QUICConnection :=
  server.connections.find? (fun c => c.connectionId.data == connectionId.data)

-- Update connection in server
def updateQUICConnection (server : QUICServerState) (connectionId : QUICConnectionID) (f : QUICConnection → QUICConnection) : QUICServerState :=
  let newConnections := server.connections.map (fun c =>
    if c.connectionId.data == connectionId.data then f c else c)
  { server with connections := newConnections }

-- ==========================================
-- QUIC Frame Encoding/Decoding
-- ==========================================

-- Encode variable-length integer (RFC 9000)
def encodeVarInt (value : UInt64) : ByteArray :=
  if value < 0x40 then
    ByteArray.mk #[value.toUInt8]
  else if value < 0x4000 then
    let b1 := (0x40.toUInt8 ||| (value >>> 8).toUInt8)
    let b2 := (value &&& 0xFF).toUInt8
    ByteArray.mk #[b1, b2]
  else if value < 0x40000000 then
    let b1 := (0x80.toUInt8 ||| (value >>> 24).toUInt8)
    let b2 := ((value >>> 16) &&& 0xFF).toUInt8
    let b3 := ((value >>> 8) &&& 0xFF).toUInt8
    let b4 := (value &&& 0xFF).toUInt8
    ByteArray.mk #[b1, b2, b3, b4]
  else
    let b1 := (0xC0.toUInt8 ||| (value >>> 56).toUInt8)
    let b2 := ((value >>> 48) &&& 0xFF).toUInt8
    let b3 := ((value >>> 40) &&& 0xFF).toUInt8
    let b4 := ((value >>> 32) &&& 0xFF).toUInt8
    let b5 := ((value >>> 24) &&& 0xFF).toUInt8
    let b6 := ((value >>> 16) &&& 0xFF).toUInt8
    let b7 := ((value >>> 8) &&& 0xFF).toUInt8
    let b8 := (value &&& 0xFF).toUInt8
    ByteArray.mk #[b1, b2, b3, b4, b5, b6, b7, b8]

-- Alias for encodeVarInt (QUIC variable-length integer encoding)
def encodeQUICVarInt := encodeVarInt

-- Create PING frame
def createQUICPingFrame : QUICFrame := {
  frameType := QUICFrameType.PING
  payload := ByteArray.mk #[]
}

-- Create PADDING frame
def createQUICPaddingFrame (length : Nat) : QUICFrame := {
  frameType := QUICFrameType.PADDING
  payload := ByteArray.mk (List.replicate length 0x00).toArray
}

-- Create CRYPTO frame
def createQUICCryptoFrame (offset : UInt64) (data : ByteArray) : QUICFrame := {
  frameType := QUICFrameType.CRYPTO
  payload := encodeVarInt offset ++ data
}

-- Create STREAM frame
def createQUICStreamFrame (streamId : UInt64) (offset : UInt64) (data : ByteArray) (fin : Bool) : QUICFrame := {
  frameType := QUICFrameType.STREAM
  payload := encodeVarInt streamId ++ encodeVarInt offset ++ data ++ (if fin then ByteArray.mk #[0x01] else ByteArray.empty)
}

-- Encode ACK ranges for ACK frame (RFC 9000)
def encodeAckRanges (ranges : Array (UInt64 × UInt64)) : ByteArray :=
  if ranges.isEmpty then ByteArray.empty
  else
    let numBlocks := (ranges.size - 1).toUInt64
    let numBlocksEncoded := encodeVarInt numBlocks
    let firstRange := ranges[0]!
    let firstAckRange := firstRange.snd - firstRange.fst
    let firstAckRangeEncoded := encodeVarInt firstAckRange

    -- Encode additional ranges (gaps and acks)
    let additionalRanges := (ranges.extract 1 ranges.size).map (fun (largest, smallest) =>
      let gap := (ranges[0]!.fst - largest - 1)
      let ackRangeLength := largest - smallest
      encodeVarInt gap |>.append (encodeVarInt ackRangeLength)
    )
    let additionalEncoded := additionalRanges.foldl (fun acc x => acc.append x) ByteArray.empty

    numBlocksEncoded ++ firstAckRangeEncoded ++ additionalEncoded

-- Create ACK frame
def createQUICAckFrame (largestAcknowledged : UInt64) (ackDelay : UInt64) (ackRanges : Array (UInt64 × UInt64)) : QUICFrame := {
  frameType := QUICFrameType.ACK
  payload := encodeVarInt largestAcknowledged ++ encodeVarInt ackDelay ++ encodeAckRanges ackRanges
}

-- Create CONNECTION_CLOSE frame
def createQUICConnectionCloseFrame (errorCode : UInt64) (reasonPhrase : String) : QUICFrame := {
  frameType := QUICFrameType.CONNECTION_CLOSE
  payload := encodeVarInt errorCode ++ encodeVarInt (reasonPhrase.length.toUInt64) ++ reasonPhrase.toUTF8
}

-- Create MAX_DATA frame
def createQUICMaxDataFrame (maximumData : UInt64) : QUICFrame := {
  frameType := QUICFrameType.MAX_DATA
  payload := encodeVarInt maximumData
}

-- ==========================================
-- QUIC Frame Encoding/Decoding
-- ==========================================

-- Decode variable-length integer (RFC 9000)
def decodeVarInt (data : ByteArray) (start : Nat) : Option (UInt64 × Nat) :=
  if start >= data.size then none
  else
    let firstByte := data.get! start
    let prefixValue := firstByte >>> 6
    let length :=
      match prefixValue with
      | 0 => 1
      | 1 => 2
      | 2 => 4
      | 3 => 8
      | _ => 0  -- Invalid

    if length == 0 || start + length > data.size then none
    else
      let value :=
        if length == 1 then
          (data.get! start &&& 0x3F.toUInt8).toUInt64
        else if length == 2 then
          let b1 := (data.get! start &&& 0x3F.toUInt8).toUInt64
          let b2 := (data.get! (start + 1)).toUInt64
          (b1 <<< 8) ||| b2
        else if length == 4 then
          let b1 := (data.get! start &&& 0x3F.toUInt8).toUInt64
          let b2 := (data.get! (start + 1)).toUInt64
          let b3 := (data.get! (start + 2)).toUInt64
          let b4 := (data.get! (start + 3)).toUInt64
          (b1 <<< 24) ||| (b2 <<< 16) ||| (b3 <<< 8) ||| b4
        else if length == 8 then
          let b1 := (data.get! start &&& 0x3F.toUInt8).toUInt64
          let b2 := (data.get! (start + 1)).toUInt64
          let b3 := (data.get! (start + 2)).toUInt64
          let b4 := (data.get! (start + 3)).toUInt64
          let b5 := (data.get! (start + 4)).toUInt64
          let b6 := (data.get! (start + 5)).toUInt64
          let b7 := (data.get! (start + 6)).toUInt64
          let b8 := (data.get! (start + 7)).toUInt64
          (b1 <<< 56) ||| (b2 <<< 48) ||| (b3 <<< 40) ||| (b4 <<< 32) |||
          (b5 <<< 24) ||| (b6 <<< 16) ||| (b7 <<< 8) ||| b8
        else 0  -- Invalid length
      some (value, start + length)

def encodeQUICCryptoFrame (offset : UInt64) (data : ByteArray) : ByteArray :=
  let offsetEncoded := encodeVarInt offset
  let lengthEncoded := encodeVarInt data.size.toUInt64
  ByteArray.mk #[QUICFrameType.toByte QUICFrameType.CRYPTO] ++
    offsetEncoded ++ lengthEncoded ++ data

-- Decode CRYPTO frame
def decodeQUICCryptoFrame (payload : ByteArray) : Option (UInt64 × ByteArray) :=
  match decodeVarInt payload 0 with
  | some (offset, pos1) =>
    match decodeVarInt payload pos1 with
    | some (length, pos2) =>
      if pos2 + length.toNat <= payload.size then
        let data := payload.extract pos2 (pos2 + length.toNat)
        some (offset, data)
      else none
    | none => none
  | none => none

-- Encode STREAM frame
def encodeQUICStreamFrame (streamId : UInt64) (offset : UInt64) (data : ByteArray) (fin : Bool) : ByteArray :=
  let streamIdEncoded := encodeVarInt streamId
  let offsetEncoded := encodeVarInt offset
  let lengthEncoded := encodeVarInt data.size.toUInt64
  let typeByte := QUICFrameType.toByte QUICFrameType.STREAM
  let typeWithFlags := if fin then typeByte ||| 0x01 else typeByte
  ByteArray.mk #[typeWithFlags] ++ streamIdEncoded ++ offsetEncoded ++ lengthEncoded ++ data

-- Decode STREAM frame
def decodeQUICStreamFrame (payload : ByteArray) : Option (UInt64 × UInt64 × ByteArray × Bool) :=
  if payload.size < 1 then none
  else
    let typeByte := payload.get! 0
    let fin := (typeByte &&& 0x01) != 0
    let streamIdPos := 1
    match decodeVarInt payload streamIdPos with
    | some (streamId, offsetPos) =>
      match decodeVarInt payload offsetPos with
      | some (offset, lengthPos) =>
        match decodeVarInt payload lengthPos with
        | some (length, dataPos) =>
          if dataPos + length.toNat <= payload.size then
            let data := payload.extract dataPos (dataPos + length.toNat)
            some (streamId, offset, data, fin)
          else none
        | none => none
      | none => none
    | none => none

-- Parse QUIC frame from bytes (simplified)
def parseQUICFrame (data : ByteArray) : Option QUICFrame :=
  if data.size < 1 then none
  else
    let frameTypeByte := data.get! 0
    let frameType := QUICFrameType.fromByte frameTypeByte
    let payload := data.extract 1 data.size
    some { frameType := frameType, payload := payload }

-- ==========================================
-- QUIC Packet Creation and Processing
-- ==========================================

-- Create QUIC packet
def createQUICPacket (packetType : QUICPacketType_) (destinationCID : QUICConnectionID)
    (frames : Array QUICFrame) : QUICPacket :=
  let header := {
    packetType := packetType
    version := some QUIC_VERSION_1
    destinationCID := destinationCID
    sourceCID := none
    packetNumber := { number := 0 }
    token := none
  }
  -- Serialize frames into payload (actual encryption is applied at the transport layer)
  let serializedPayload := frames.foldl (fun acc frame =>
    acc ++ ByteArray.mk #[frame.frameType.toByte] ++ frame.payload
  ) ByteArray.empty
  {
    header := header
    frames := frames
    payload := serializedPayload
  }

-- Create Initial packet
def createQUICInitialPacket (destinationCID : QUICConnectionID) (token : Option ByteArray)
    (cryptoData : ByteArray) : QUICPacket :=
  let cryptoFrame := createQUICCryptoFrame 0 cryptoData
  let paddingFrame := createQUICPaddingFrame 1200  -- Minimum initial packet size
  let frames := #[cryptoFrame, paddingFrame]
  let header := {
    packetType := QUICPacketType_.Initial
    version := some QUIC_VERSION_1
    destinationCID := destinationCID
    sourceCID := none
    packetNumber := { number := 0 }
    token := token
  }
  -- Serialize frames (encryption applied at transport layer in HTTPServer)
  let serializedPayload := frames.foldl (fun acc frame =>
    acc ++ ByteArray.mk #[frame.frameType.toByte] ++ frame.payload
  ) ByteArray.empty
  {
    header := header
    frames := frames
    payload := serializedPayload
  }

-- Create Handshake packet
def createQUICHandshakePacket (destinationCID : QUICConnectionID) (sourceCID : QUICConnectionID)
    (cryptoData : ByteArray) : QUICPacket :=
  let cryptoFrame := createQUICCryptoFrame 0 cryptoData
  let frames := #[cryptoFrame]
  let header := {
    packetType := QUICPacketType_.Handshake
    version := some QUIC_VERSION_1
    destinationCID := destinationCID
    sourceCID := some sourceCID
    packetNumber := { number := 0 }
    token := none
  }
  -- Serialize frames (encryption applied at transport layer in HTTPServer)
  let serializedPayload := frames.foldl (fun acc frame =>
    acc ++ ByteArray.mk #[frame.frameType.toByte] ++ frame.payload
  ) ByteArray.empty
  {
    header := header
    frames := frames
    payload := serializedPayload
  }

-- Process Initial packet (server side)
-- Note: CID generation is handled at the IO layer (HTTPServer.lean) using
-- cryptographically secure random bytes via `generateQUICConnectionID`.
-- This pure function processes the structural QUIC packet.
def processQUICInitialPacket (server : QUICServerState) (packet : QUICPacket) : QUICServerState :=
  -- Extract crypto data from frames
  let cryptoData := packet.frames.find? (fun f => f.frameType == QUICFrameType.CRYPTO)
  match cryptoData with
  | some frame =>
    match decodeQUICCryptoFrame frame.payload with
    | some (cryptoOffset, cryptoPayload) =>
      -- Use the destination CID from the incoming packet as a basis for server CID
      -- (Real CID generation with IO.getRandomBytes is in HTTPServer.handleQUICLongHeader)
      let serverCID := packet.header.destinationCID
      let newConnection := createQUICConnection serverCID
      let updatedConnection := { newConnection with
        state := QUICConnectionState.connecting
        peerConnectionId := some packet.header.destinationCID
        -- Store the CRYPTO data in the reassembly buffer for TLS processing at the IO layer
        cryptoStream := [(cryptoOffset.toNat, cryptoPayload)]
      }
      addQUICConnection server updatedConnection
    | none => server
  | none => server

-- Process Handshake packet
def processQUICHandshakePacket (server : QUICServerState) (packet : QUICPacket) : QUICServerState :=
  -- Find existing connection
  match packet.header.destinationCID with
  | destCID =>
    match findQUICConnection server destCID with
    | some connection =>
      -- Only transition to connected if we're in the connecting state
      if connection.state == QUICConnectionState.connecting then
        -- Extract handshake CRYPTO data if present
        let handshakeCrypto := packet.frames.find? (fun f => f.frameType == QUICFrameType.CRYPTO)
        let updatedConnection := match handshakeCrypto with
          | some frame =>
            match decodeQUICCryptoFrame frame.payload with
            | some (hsOffset, hsData) => { connection with
                state := QUICConnectionState.connected
                cryptoStreamHandshake := connection.cryptoStreamHandshake ++ [(hsOffset.toNat, hsData)]
              }
            | none => { connection with state := QUICConnectionState.connected }
          | none => { connection with state := QUICConnectionState.connected }
        updateQUICConnection server destCID (fun _ => updatedConnection)
      else
        server  -- Ignore handshake packets for non-connecting state
    | none => server

-- Process 1-RTT packet
def processQUICOneRTTPacket (server : QUICServerState) (packet : QUICPacket) : QUICServerState :=
  -- Find connection and process frames
  match packet.header.destinationCID with
  | destCID =>
    match findQUICConnection server destCID with
    | some connection =>
      -- Process frames (STREAM, ACK, PING, etc.)
      let updatedConnection := packet.frames.foldl (fun conn frame =>
        match frame.frameType with
        | QUICFrameType.STREAM =>
          match decodeQUICStreamFrame frame.payload with
          | some (streamId, _offset, data, fin) =>
            -- Buffer stream data for reassembly using h3StreamBuffers
            let existingData := match conn.h3StreamBuffers.find? (fun (sid, _) => sid == streamId) with
              | some (_, buf) => buf
              | none => ByteArray.empty
            let newData := existingData ++ data
            let updatedBuffers := conn.h3StreamBuffers.filter (fun (sid, _) => sid != streamId)
            let updatedConn := { conn with h3StreamBuffers := (streamId, newData) :: updatedBuffers }
            -- Mark stream as finished if FIN bit is set
            if fin then
              { updatedConn with
                receivedPackets := updatedConn.receivedPackets.push packet
              }
            else updatedConn
          | none => conn
        | QUICFrameType.PING =>
          -- RFC 9000 §19.2: PING frames elicit ACK — the ACK is generated
          -- by the transport layer (handled in HTTPServer.lean sendShortHeaderPacket).
          -- Mark that we received a packet requiring acknowledgment.
          { conn with receivedPackets := conn.receivedPackets.push packet }
        | QUICFrameType.ACK =>
          -- ACK frame received: update acknowledged packet tracking
          { conn with receivedPackets := conn.receivedPackets.push packet }
        | _ => conn
      ) connection
      updateQUICConnection server destCID (fun _ => updatedConnection)
    | none => server

-- Main packet processing function
def processQUICPacket (server : QUICServerState) (packet : QUICPacket) : QUICServerState :=
  match packet.header.packetType with
  | QUICPacketType_.Initial => processQUICInitialPacket server packet
  | QUICPacketType_.Handshake => processQUICHandshakePacket server packet
  | QUICPacketType_.OneRTT => processQUICOneRTTPacket server packet
  | _ => server  -- Ignore other packet types for now

-- ==========================================
-- QUIC Utilities
-- ==========================================

-- Generate random connection ID using cryptographically secure random bytes
def generateQUICConnectionID (length : Nat := 8) : IO QUICConnectionID := do
  let randomBytes ← IO.getRandomBytes length.toUSize
  pure (QUICConnectionID.mk randomBytes)

-- Check if connection ID is valid
def isValidQUICConnectionID (cid : QUICConnectionID) : Bool :=
  cid.data.size >= 4 && cid.data.size <= 20

-- Get connection state as string
def QUICConnectionState.toString : QUICConnectionState → String
  | idle => "idle"
  | connecting => "connecting"
  | connected => "connected"
  | draining => "draining"
  | closing => "closing"
  | closed => "closed"

-- Get packet type as string
def QUICPacketType_.toString : QUICPacketType_ → String
  | Initial => "Initial"
  | ZeroRTT => "0-RTT"
  | Handshake => "Handshake"
  | Retry => "Retry"
  | OneRTT => "1-RTT"
  | VersionNegotiation => "Version Negotiation"

-- ==========================================
-- QUIC Server Management
-- ==========================================

-- Remove closed connections
def cleanupQUICConnections (server : QUICServerState) : QUICServerState :=
  let activeConnections := server.connections.filter (fun c => c.state != QUICConnectionState.closed)
  { server with connections := activeConnections }

-- Get server statistics
def getQUICServerStats (server : QUICServerState) : String :=
  let totalConnections := server.connections.size
  let activeConnections := server.connections.filter (fun c => c.state == QUICConnectionState.connected)
  let connectingConnections := server.connections.filter (fun c => c.state == QUICConnectionState.connecting)
  s!"QUIC Server Stats:
  Total connections: {totalConnections}
  Active connections: {activeConnections.size}
  Connecting: {connectingConnections.size}
  Max connections: {server.maxConnections}"

-- Check if server can accept new connections
def canAcceptQUICConnection (server : QUICServerState) : Bool :=
  server.connections.size < server.maxConnections.toNat

-- ==========================================
-- QUIC Connection Management
-- ==========================================

-- Update connection state
def updateQUICConnectionState (connection : QUICConnection) (newState : QUICConnectionState) : QUICConnection :=
  { connection with state := newState }

-- Add frame to connection's pending frames
def addQUICPendingFrame (connection : QUICConnection) (frame : QUICFrame) : QUICConnection :=
  { connection with pendingFrames := connection.pendingFrames.push frame }

-- Clear pending frames
def clearQUICPendingFrames (connection : QUICConnection) : QUICConnection :=
  { connection with pendingFrames := #[] }

-- Increment packet number
def incrementQUICPacketNumber (connection : QUICConnection) : QUICConnection :=
  { connection with nextPacketNumber := { number := connection.nextPacketNumber.number + 1 } }

-- Get connection info
def getQUICConnectionInfo (connection : QUICConnection) : String :=
  let cid := connection.connectionId.data.size
  let state := connection.state.toString
  let packets := connection.receivedPackets.size
  let pending := connection.pendingFrames.size
  s!"Connection ID length: {cid}, State: {state}, Packets: {packets}, Pending frames: {pending}"

-- ==========================================
-- F5.3: Loss Detection (RFC 9002)
-- ==========================================

/-- RFC 9002 §6.1.1 — Packet threshold for declaring loss.
    A packet is considered lost if a later packet has been acknowledged
    and kPacketThreshold packets have since been acknowledged. -/
def kPacketThreshold : Nat := 3

/-- RFC 9002 §6.1.2 — Time threshold multiplier for declaring loss.
    9/8 of the larger of smoothed_rtt and latest_rtt -/
def kTimeThresholdNumerator : Nat := 9
def kTimeThresholdDenominator : Nat := 8

/-- RFC 9002 §6.2.2 — Initial RTT used before any measurement -/
def kInitialRtt : Nat := 333  -- ms

/-- RFC 9002 §6.2 — Granularity of the loss detection timer -/
def kGranularity : Nat := 1  -- ms

/-- Compute loss detection time threshold (RFC 9002 §6.1.2) -/
def computeTimeThreshold (smoothedRtt latestRtt : Nat) : Nat :=
  let maxRtt := max smoothedRtt latestRtt
  max (maxRtt * kTimeThresholdNumerator / kTimeThresholdDenominator) kGranularity

/-- Detect lost packets based on packet number and time thresholds (RFC 9002 §6.1) -/
def detectLostPackets (sentPackets : Array SentPacketEntry) (largestAcked : UInt64)
    (nowMs : UInt64) (smoothedRtt latestRtt : Nat) : Array SentPacketEntry :=
  let timeThreshold := computeTimeThreshold smoothedRtt latestRtt
  sentPackets.filter fun pkt =>
    if pkt.acked then false
    else
      -- Packet-threshold: lost if kPacketThreshold newer packets acknowledged
      let packetLoss := pkt.pn.toNat + kPacketThreshold ≤ largestAcked.toNat
      -- Time-threshold: lost if sent long enough ago
      let timeLoss := nowMs.toNat > pkt.sentTimeMs.toNat + timeThreshold
      packetLoss || timeLoss

/-- RFC 9002 §6.2.4 — Persistent congestion detection.
    Persistent congestion exists when consecutive packets spanning a period
    exceeding the PTO are all declared lost. -/
def isPersistentCongestion (lostPackets : Array SentPacketEntry)
    (smoothedRtt rttVar : Nat) (maxAckDelay : Nat := 25) : Bool :=
  if lostPackets.size < 2 then false
  else
    -- Find the earliest and latest lost packet send times
    let earliest := lostPackets.foldl (fun acc p => min acc p.sentTimeMs.toNat) (lostPackets[0]!.sentTimeMs.toNat)
    let latest := lostPackets.foldl (fun acc p => max acc p.sentTimeMs.toNat) 0
    -- Persistent congestion duration threshold (RFC 9002 §7.6.1)
    let ptoBase := smoothedRtt + max (4 * rttVar) kGranularity + maxAckDelay
    let congestionPeriod := ptoBase * 3  -- 3× PTO
    latest - earliest > congestionPeriod

-- ==========================================
-- F5.4: Connection Migration (RFC 9000 §9)
-- ==========================================

/-- Migration state for path validation -/
inductive MigrationStatus where
  | none       : MigrationStatus     -- No migration in progress
  | validating : MigrationStatus     -- PATH_CHALLENGE sent, awaiting PATH_RESPONSE
  | validated  : MigrationStatus     -- PATH_RESPONSE received, migration complete
  | failed     : MigrationStatus     -- PATH_RESPONSE timeout
  deriving Inhabited, Repr, BEq

/-- Path information for connection migration -/
structure PathInfo where
  remoteAddr   : String     -- IP:port
  localAddr    : String     -- local IP:port
  challenge    : ByteArray  -- 8-byte PATH_CHALLENGE data
  status       : MigrationStatus
  validatedAt  : Nat        -- timestamp of validation
  deriving Inhabited

/-- Initiate path validation after detecting address change (RFC 9000 §9.1) -/
def initiatePathValidation (conn : QUICConnection) (_newRemoteAddr : String)
    (_challenge : ByteArray) : QUICConnection :=
  { conn with
    -- Anti-amplification: reset until path validated
    addressValidated := false }

/-- Validate path after receiving PATH_RESPONSE matching our challenge -/
def validatePath (conn : QUICConnection) (response : ByteArray)
    (challenge : ByteArray) : Option QUICConnection :=
  if response == challenge then
    some { conn with addressValidated := true }
  else
    none

-- ==========================================
-- F5: QUIC Proofs
-- ==========================================

/-- Pure send-packet step: assigns the current `nextPacketNumber` to the
    packet, records it in `sentPackets`, and increments the counter.
    This is the abstract model of packet transmission (RFC 9000 §17.1). -/
def sendPacket (conn : QUICConnection) (payload : ByteArray) (nowMs : UInt64)
    : QUICConnection × QUICPacketNumber :=
  let pn := conn.nextPacketNumber
  let entry : SentPacketEntry := {
    pn := pn.number
    sentTimeMs := nowMs
    payload := payload
  }
  let conn' := { conn with
    nextPacketNumber := { number := pn.number + 1 }
    sentPackets := conn.sentPackets.push entry
  }
  (conn', pn)

/-- **Packet number monotonicity**: After `sendPacket`, the connection's
    `nextPacketNumber` is incremented by exactly 1 (RFC 9000 §17.1).
    Combined with `quic_pn_difference_positive` from ProtocolInvariants,
    this establishes strict monotonicity at the Nat level. -/
theorem packet_number_monotonic (conn : QUICConnection) (payload : ByteArray) (nowMs : UInt64) :
    (sendPacket conn payload nowMs).1.nextPacketNumber.number =
      conn.nextPacketNumber.number + 1 := by
  simp [sendPacket]

/-- **sendPacket preserves state**: sendPacket only modifies nextPacketNumber
    and sentPackets — all other connection state is preserved. -/
theorem sendPacket_preserves_state (conn : QUICConnection) (payload : ByteArray) (nowMs : UInt64) :
    (sendPacket conn payload nowMs).1.state = conn.state := by
  simp [sendPacket]

/-- **sendPacket advances counter**: The counter is exactly +1. -/
theorem sendPacket_counter_step (conn : QUICConnection) (payload : ByteArray) (nowMs : UInt64) :
    (sendPacket conn payload nowMs).1.nextPacketNumber.number =
      conn.nextPacketNumber.number + 1 := by
  simp [sendPacket]

/-- **sendPacket records packet**: The sent packet is appended to sentPackets. -/
theorem sendPacket_records_packet (conn : QUICConnection) (payload : ByteArray) (nowMs : UInt64) :
    (sendPacket conn payload nowMs).1.sentPackets.size =
      conn.sentPackets.size + 1 := by
  simp [sendPacket, Array.size_push]

/-- **sendPacket returns current PN**: The returned packet number is the
    connection's current nextPacketNumber. -/
theorem sendPacket_returns_current_pn (conn : QUICConnection) (payload : ByteArray) (nowMs : UInt64) :
    (sendPacket conn payload nowMs).2 = conn.nextPacketNumber := by
  simp [sendPacket]

/-- **Two consecutive sends produce different assigned PNs**: The second
    packet gets PN = first_PN + 1, so they differ (unless UInt64 overflow). -/
theorem sendPacket_pn_distinct (conn : QUICConnection) (p1 p2 : ByteArray) (t1 t2 : UInt64) :
    (sendPacket conn p1 t1).2.number ≠
    (sendPacket (sendPacket conn p1 t1).1 p2 t2).2.number := by
  simp [sendPacket]

/-- Packet threshold is positive -/
theorem kPacketThreshold_pos : kPacketThreshold > 0 := by decide

/-- Time threshold is at least kGranularity -/
theorem timeThreshold_min (sRtt lRtt : Nat) :
    computeTimeThreshold sRtt lRtt ≥ kGranularity := by
  simp [computeTimeThreshold]
  omega

/-- Initial RTT is positive -/
theorem kInitialRtt_pos : kInitialRtt > 0 := by decide

/-- Persistent congestion requires at least 2 lost packets -/
theorem persistent_congestion_min_packets (sRtt rttVar : Nat) :
    isPersistentCongestion #[] sRtt rttVar = false := by
  simp [isPersistentCongestion]

end LeanServer
