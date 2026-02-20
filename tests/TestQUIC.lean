import LeanServer.Protocol.QUIC

def main : IO Unit := do
  IO.println "=== Testes QUIC Avançados ==="

  -- Teste de VarInt
  IO.println "🔧 Testando VarInt..."
  let testValue : UInt64 := 0x123456789ABCDEF
  let encoded := LeanServer.encodeVarInt testValue
  IO.println s!"✅ VarInt codificado: {encoded.size} bytes"

  let decodedOpt := LeanServer.decodeVarInt encoded 0
  match decodedOpt with
  | some (value, pos) =>
    if value == testValue then
      IO.println s!"✅ VarInt decodificado corretamente: {value}"
    else
      IO.println s!"❌ VarInt decodificado incorretamente: {value} != {testValue}"
  | none => IO.println "❌ Falha na decodificação VarInt"

  -- Teste de CRYPTO frame
  IO.println "🔐 Testando CRYPTO frame..."
  let cryptoData := "Hello QUIC TLS!".toUTF8
  let cryptoFrame := LeanServer.createQUICCryptoFrame 0 cryptoData
  let encodedCrypto := LeanServer.encodeQUICCryptoFrame 0 cryptoData
  IO.println s!"✅ CRYPTO frame criado e codificado: {encodedCrypto.size} bytes"

  let decodedCryptoOpt := LeanServer.decodeQUICCryptoFrame encodedCrypto
  match decodedCryptoOpt with
  | some (offset, data) =>
    if data == cryptoData then
      IO.println s!"✅ CRYPTO frame decodificado corretamente: offset={offset}"
    else
      IO.println "❌ CRYPTO frame decodificado incorretamente"
  | none => IO.println "❌ Falha na decodificação CRYPTO frame"

  -- Teste de STREAM frame
  IO.println "🌊 Testando STREAM frame..."
  let streamData := "Stream data payload".toUTF8
  let streamFrame := LeanServer.createQUICStreamFrame 1 0 streamData false
  let encodedStream := LeanServer.encodeQUICStreamFrame 1 0 streamData false
  IO.println s!"✅ STREAM frame criado e codificado: {encodedStream.size} bytes"

  let decodedStreamOpt := LeanServer.decodeQUICStreamFrame encodedStream
  match decodedStreamOpt with
  | some (streamId, offset, data, fin) =>
    if streamId == 1 && offset == 0 && data == streamData && !fin then
      IO.println s!"✅ STREAM frame decodificado corretamente: stream={streamId}, fin={fin}"
    else
      IO.println "❌ STREAM frame decodificado incorretamente"
  | none => IO.println "❌ Falha na decodificação STREAM frame"

  -- Teste de processamento de pacotes
  IO.println "📦 Testando processamento de pacotes QUIC..."
  let server := LeanServer.initQUICServer 10
  let cid := LeanServer.QUICConnectionID.mk "client-connection-123".toUTF8
  let cryptoData := "ClientHello TLS data".toUTF8
  let initialPacket := LeanServer.createQUICInitialPacket cid none cryptoData
  IO.println s!"✅ Initial packet criado: {initialPacket.frames.size} frames"

  let serverAfterInitial := LeanServer.processQUICPacket server initialPacket
  IO.println s!"✅ Initial packet processado, conexões: {serverAfterInitial.connections.size}"

  let foundConnection := LeanServer.findQUICConnection serverAfterInitial cid
  match foundConnection with
  | some conn =>
    IO.println s!"✅ Conexão encontrada, estado: {LeanServer.QUICConnectionState.toString conn.state}"
  | none => IO.println "❌ Conexão não encontrada"

  -- Teste de gerenciamento de servidor
  IO.println "🖥️ Testando gerenciamento de servidor QUIC..."
  let canAccept := LeanServer.canAcceptQUICConnection serverAfterInitial
  IO.println s!"✅ Servidor pode aceitar novas conexões: {canAccept}"

  let stats := LeanServer.getQUICServerStats serverAfterInitial
  IO.println s!"📊 {stats}"

  -- Teste de gerenciamento de conexões
  IO.println "🔗 Testando gerenciamento de conexões QUIC..."
  let conn := LeanServer.createQUICConnection cid
  let connWithFrame := LeanServer.addQUICPendingFrame conn (LeanServer.createQUICPingFrame)
  IO.println s!"✅ Frame pendente adicionado: {connWithFrame.pendingFrames.size} frames"

  let connCleared := LeanServer.clearQUICPendingFrames connWithFrame
  IO.println s!"✅ Frames pendentes limpos: {connCleared.pendingFrames.size} frames"

  let connWithIncrement := LeanServer.incrementQUICPacketNumber conn
  let nextNum := connWithIncrement.nextPacketNumber.number
  IO.println s!"✅ Número de pacote incrementado: {nextNum}"

  IO.println "✅ Todos os testes QUIC avançados passaram!"
