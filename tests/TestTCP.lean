import Init.System.IO

-- FFI Declarations (Match Network.c)
@[extern "lean_socket_create"]
opaque socketCreate (proto : UInt32) : IO UInt64

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

@[extern "lean_closesocket"]
opaque socketClose (sock : UInt64) : IO Unit

def main : IO Unit := do
  IO.println "TestTCP: Starting..."
  
  -- 1. Create Socket (TCP = 0)
  IO.println "TestTCP: Creating socket..."
  let sock ← socketCreate 0
  IO.println s!"TestTCP: Socket created: {sock}"
  
  -- 2. Bind (Port 4433)
  IO.println "TestTCP: Binding to port 4433..."
  try
    socketBind sock 4433
    IO.println "TestTCP: Bound successfully."
  catch e =>
    IO.println s!"TestTCP: Bind failed: {e}"
    return

  -- 3. Listen
  IO.println "TestTCP: Listening..."
  try
    socketListen sock 5
    IO.println "TestTCP: Listening successfully. Waiting for connection..."
  catch e =>
    IO.println s!"TestTCP: Listen failed: {e}"
    return

  -- 4. Accept
  try
    let clientSock ← socketAccept sock
    IO.println s!"TestTCP: Accepted connection! Socket: {clientSock}"
    
    -- 5. Recv
    let bufSize : UInt32 := 1024
    let buf := ByteArray.mk (List.replicate bufSize.toNat 0).toArray
    let recvBytes ← socketRecv clientSock buf bufSize 0
    IO.println s!"TestTCP: Received {recvBytes} bytes."
    
    if recvBytes > 0 then
      let msg := match String.fromUTF8? (buf.extract 0 recvBytes.toNat) with
        | some s => s
        | none => "<Invalid UTF-8>"
      IO.println s!"TestTCP: Message: {msg}"
      
      -- 6. Send
      let response := "Hello from TestTCP!\n"
      let respBytes := response.toUTF8
      let _ ← socketSend clientSock respBytes respBytes.size.toUInt32 0
      IO.println "TestTCP: Sent response."
    
    -- 7. Close Client
    socketClose clientSock
    IO.println "TestTCP: Closed client socket."
    
  catch e =>
    IO.println s!"TestTCP: Accept/Handle failed: {e}"

  -- 8. Close Server
  socketClose sock
  IO.println "TestTCP: Closed server socket. Done."
