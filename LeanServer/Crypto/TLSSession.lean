import LeanServer.Crypto.Crypto

/-!
  # TLS Session Management — Re-export Module
  Focused import path for TLS session lifecycle: tickets, PSK cache,
  anti-replay, record encryption/decryption.

  ## Key Types
  - `TLSSessionTLS` — Full TLS session state
  - `PSKCache` / `PSKEntry` — Pre-Shared Key cache
  - `AntiReplayWindow` — 0-RTT anti-replay protection
  - `SessionTicket` — NewSessionTicket message
  - `TicketKeyManager` — Ticket key rotation

  ## Key Functions
  - `encryptTLS13Record` / `decryptTLS13Record` — Record-layer encryption
  - `encryptAppData` — Application data encryption
  - `transitionToAppData` — Transition session from handshake to data state
  - `buildNewSessionTicket` — Build NewSessionTicket message
  - `encryptSessionTicket` / `decryptSessionTicket` — Ticket encryption

  ## Usage
  ```lean
  import LeanServer.Crypto.TLSSession
  let encrypted := LeanServer.encryptTLS13Record key nonce content contentType
  ```
-/

namespace LeanServer.TLSSessionMgr

/-- Encrypt a TLS 1.3 record -/
@[inline] def encryptRecord (key nonce innerContent : ByteArray) (innerType : UInt8) : ByteArray :=
  LeanServer.encryptTLS13Record key nonce innerContent innerType

/-- Decrypt a TLS 1.3 record -/
@[inline] def decryptRecord (key nonce ciphertextWithTag : ByteArray) : Option (ByteArray × UInt8) :=
  LeanServer.decryptTLS13Record key nonce ciphertextWithTag

/-- Insert a PSK entry into the cache -/
@[inline] def pskInsert (cache : LeanServer.PSKCache) (entry : LeanServer.PSKEntry) : LeanServer.PSKCache :=
  cache.insert entry

/-- Look up a PSK entry -/
@[inline] def pskLookup (cache : LeanServer.PSKCache) (identity : ByteArray) (nowMs : UInt64) : Option LeanServer.PSKEntry :=
  cache.lookup identity nowMs

/-- Rotate ticket encryption key if needed -/
@[inline] def rotateKey (mgr : LeanServer.TicketKeyManager) (nowMs : UInt64) (newKey : ByteArray) : LeanServer.TicketKeyManager × Bool :=
  LeanServer.rotateTicketKeyIfNeeded mgr nowMs newKey

/-- Build NewSessionTicket message -/
@[inline] def buildTicket (resumptionSecret : ByteArray) (ticketAgeAdd : UInt32)
    (ticketNonce : ByteArray) (maxEarlyData : UInt32 := 16384) : ByteArray :=
  LeanServer.buildNewSessionTicket resumptionSecret ticketAgeAdd ticketNonce maxEarlyData

end LeanServer.TLSSessionMgr
