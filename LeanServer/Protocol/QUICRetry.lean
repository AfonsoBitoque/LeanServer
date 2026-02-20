import LeanServer.Protocol.QUIC
import LeanServer.Crypto.Crypto

/-!
# QUIC Retry Token Validation (R16)

Implements QUIC Retry packet generation and token validation per RFC 9000 §8.1.

## Address Validation via Retry
When a server receives an Initial packet from an unvalidated address, it MAY
send a Retry packet containing a token. The client must re-send its Initial
with that token, proving it controls the source address.

## Token Format (opaque to the client)
```
[4 bytes: timestamp (seconds since epoch)]
[16 bytes: client IP hash (HMAC-SHA256 truncated)]
[8 bytes: original DCID length + data]
[32 bytes: HMAC-SHA256 integrity tag over the above]
```

## Retry Integrity Tag
RFC 9001 §5.8: The Retry packet uses a fixed key and nonce for AEAD
to compute the Retry Integrity Tag (16 bytes appended to the packet).
-/

namespace LeanServer

-- ==========================================
-- Retry Token Generation & Validation
-- ==========================================

/-- Secret key for token generation. In production, this should be rotated. -/
private def retryTokenKey : ByteArray :=
  -- 32-byte key derived from a fixed seed (in production, use IO.getRandomBytes at startup)
  sha256 (ByteArray.mk #[0x4C, 0x65, 0x61, 0x6E, 0x53, 0x65, 0x72, 0x76,
                          0x65, 0x72, 0x52, 0x65, 0x74, 0x72, 0x79, 0x4B])

/-- Token validity window in seconds -/
def retryTokenLifetimeSec : Nat := 60

/-- Encode a 32-bit timestamp as 4 big-endian bytes -/
private def encodeTimestamp (ts : UInt32) : ByteArray :=
  ByteArray.mk #[
    (ts >>> 24).toUInt8,
    (ts >>> 16).toUInt8,
    (ts >>> 8).toUInt8,
    ts.toUInt8
  ]

/-- Decode a 32-bit timestamp from 4 big-endian bytes -/
private def decodeTimestamp (data : ByteArray) (offset : Nat) : Option UInt32 :=
  if offset + 4 > data.size then none
  else
    let b0 := data.get! offset
    let b1 := data.get! (offset + 1)
    let b2 := data.get! (offset + 2)
    let b3 := data.get! (offset + 3)
    some ((b0.toUInt32 <<< 24) ||| (b1.toUInt32 <<< 16) |||
          (b2.toUInt32 <<< 8) ||| b3.toUInt32)

/-- Hash a client IP address to a fixed 16-byte value using HMAC-SHA256 truncation -/
private def hashClientIP (clientIP : String) : ByteArray :=
  let full := hmac_sha256 retryTokenKey clientIP.toUTF8
  full.extract 0 16  -- truncate to 16 bytes

/-- Encode the original Destination CID (length-prefixed, up to 20 bytes) -/
private def encodeOriginalDCID (dcid : QUICConnectionID) : ByteArray :=
  let cidData := dcid.data
  let lenByte := ByteArray.mk #[cidData.size.toUInt8]
  lenByte ++ cidData

/-- Generate a Retry token for a given client IP and original DCID.
    The token binds the client's address to the connection attempt. -/
def generateRetryToken (clientIP : String) (originalDCID : QUICConnectionID)
    (nowSec : UInt32) : ByteArray :=
  let tsBytes := encodeTimestamp nowSec
  let ipHash := hashClientIP clientIP
  let dcidEncoded := encodeOriginalDCID originalDCID
  -- Data to authenticate
  let tokenData := tsBytes ++ ipHash ++ dcidEncoded
  -- HMAC integrity tag
  let tag := hmac_sha256 retryTokenKey tokenData
  tokenData ++ tag

/-- Result of validating a Retry token -/
inductive RetryTokenResult where
  | valid (originalDCID : QUICConnectionID)
  | expired
  | invalidIP
  | malformed
  | invalidMAC

instance : ToString RetryTokenResult where
  toString
    | .valid dcid  => s!"valid(dcid={dcid.data.size}B)"
    | .expired     => "expired"
    | .invalidIP   => "invalid_ip"
    | .malformed   => "malformed"
    | .invalidMAC  => "invalid_mac"

/-- Validate a Retry token received from a client.
    Returns the original DCID if valid, or an error reason. -/
def validateRetryToken (token : ByteArray) (clientIP : String)
    (nowSec : UInt32) : RetryTokenResult :=
  -- Minimum token size: 4 (ts) + 16 (ip) + 1 (dcid len) + 32 (hmac) = 53
  if token.size < 53 then .malformed
  else
    -- Extract parts
    let tagStart := token.size - 32
    let tokenData := token.extract 0 tagStart
    let providedTag := token.extract tagStart token.size
    -- Verify integrity
    let expectedTag := hmac_sha256 retryTokenKey tokenData
    if expectedTag != providedTag then .invalidMAC
    else
      -- Verify timestamp
      match decodeTimestamp tokenData 0 with
      | none => .malformed
      | some ts =>
        if nowSec.toNat > ts.toNat + retryTokenLifetimeSec then .expired
        else
          -- Verify client IP
          let expectedIPHash := hashClientIP clientIP
          let storedIPHash := tokenData.extract 4 20
          if expectedIPHash != storedIPHash then .invalidIP
          else
            -- Extract original DCID
            if tokenData.size < 21 then .malformed
            else
              let dcidLen := tokenData.get! 20
              let dcidStart : Nat := 21
              let dcidEnd := dcidStart + dcidLen.toNat
              if dcidEnd > tagStart then .malformed
              else
                let dcidData := tokenData.extract dcidStart dcidEnd
                .valid (QUICConnectionID.mk dcidData)

-- ==========================================
-- Retry Packet Construction (RFC 9000 §17.2.5)
-- ==========================================

/-- Fixed key for Retry Integrity Tag (RFC 9001 §5.8, QUIC v1) -/
private def retryIntegrityKey : ByteArray :=
  ByteArray.mk #[0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
                  0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e]

/-- Fixed nonce for Retry Integrity Tag (RFC 9001 §5.8, QUIC v1) -/
private def retryIntegrityNonce : ByteArray :=
  ByteArray.mk #[0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
                  0x23, 0x98, 0x25, 0xbb]

/-- Build the Retry Pseudo-Packet for integrity tag computation.
    RFC 9001 §5.8: The pseudo-packet includes the original DCID. -/
def buildRetryPseudoPacket (originalDCID : QUICConnectionID)
    (retryHeader : ByteArray) : ByteArray :=
  let dcidLen := ByteArray.mk #[originalDCID.data.size.toUInt8]
  dcidLen ++ originalDCID.data ++ retryHeader

/-- Create a QUIC Retry packet (RFC 9000 §17.2.5).
    The server generates a new SCID and includes a token for address validation. -/
def createRetryPacket (originalDCID : QUICConnectionID)
    (serverCID : QUICConnectionID)
    (clientDCID : QUICConnectionID)
    (token : ByteArray) : ByteArray :=
  -- Retry packet format:
  -- [1 byte: 0xF0 | (Retry type)] = 0xFF for Retry
  -- [4 bytes: version]
  -- [1 byte: DCID length][DCID]
  -- [1 byte: SCID length][SCID]
  -- [token bytes]
  -- [16 bytes: Retry Integrity Tag]
  let firstByte : UInt8 := 0xFF  -- Long header, Retry type
  let version := ByteArray.mk #[0x00, 0x00, 0x00, 0x01]  -- QUIC v1
  let dcidLen := ByteArray.mk #[clientDCID.data.size.toUInt8]
  let scidLen := ByteArray.mk #[serverCID.data.size.toUInt8]

  let retryHeader := ByteArray.mk #[firstByte] ++ version ++
    dcidLen ++ clientDCID.data ++
    scidLen ++ serverCID.data ++
    token

  -- Compute integrity tag using AES-128-GCM with fixed key/nonce
  -- For simplicity, use HMAC-SHA256 truncated to 16 bytes as the integrity tag
  -- (Full AEAD requires the AES-GCM module integration)
  let pseudoPacket := buildRetryPseudoPacket originalDCID retryHeader
  let fullTag := hmac_sha256 retryIntegrityKey pseudoPacket
  let integrityTag := fullTag.extract 0 16

  retryHeader ++ integrityTag

/-- Check whether an Initial packet carries a valid Retry token.
    If no token is present, the server should consider sending a Retry. -/
def shouldSendRetry (packet : QUICPacket) (clientIP : String) (nowSec : UInt32) :
    Bool × Option QUICConnectionID :=
  match packet.header.token with
  | none => (true, none)  -- No token → send Retry
  | some token =>
    if token.isEmpty then (true, none)
    else
      match validateRetryToken token clientIP nowSec with
      | .valid originalDCID => (false, some originalDCID)
      | _ => (true, none)  -- Invalid token → send Retry again

end LeanServer
