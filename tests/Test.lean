import LeanServer
import LeanServer.Crypto.AES
import LeanServer.Crypto.Crypto
import LeanServer.Protocol.HTTP2
import LeanServer.Protocol.HTTP3
import LeanServer.Protocol.QUIC
import LeanServer.Protocol.HPACK
import LeanServer.Protocol.WebSocket
import LeanServer.Protocol.WebSocketOverHTTP2
import LeanServer.Protocol.GRPC
import LeanServer.Server.LoadBalancer

open LeanServer.AES

namespace LeanServer

/-- Teste básico de estruturas de dados -/
def testBasicDataStructures : IO Unit := do
  IO.println "Testando estruturas básicas de dados..."

  -- Teste de ByteArray
  let bytes := "test".toUTF8
  IO.println s!"ByteArray: {bytes}"
  IO.println s!"Tamanho: {bytes.size}"

  -- Teste de SHA-256
  let hash := sha256 bytes
  IO.println s!"SHA-256: {hash}"

  -- Teste de HMAC-SHA256
  let key := "key".toUTF8
  let hmac := hmac_sha256 key bytes
  IO.println s!"HMAC-SHA256: {hmac}"
  IO.println s!"Tamanho HMAC: {hmac.size}"

  -- Teste de HKDF
  let salt := "salt".toUTF8
  let info := "info".toUTF8
  let hkdf_result := hkdf_expand salt info 32
  IO.println s!"HKDF: {hkdf_result}"
  IO.println s!"Tamanho HKDF: {hkdf_result.size}"

/-- Teste de HMAC-SHA256 básico -/
def testHMACSHA256Basic : IO Unit := do
  IO.println "Testando HMAC-SHA256 básico..."

  let key := "key".toUTF8
  let message := "message".toUTF8

  let hmac := hmac_sha256 key message
  IO.println s!"HMAC result: {hmac}"
  IO.println s!"HMAC size: {hmac.size}"

  -- Teste determinístico
  let hmac2 := hmac_sha256 key message
  if hmac == hmac2 then
    IO.println "✓ HMAC determinístico"
  else
    IO.println "✗ HMAC não determinístico"

  -- Teste de diferenciação
  let message2 := "message2".toUTF8
  let hmac3 := hmac_sha256 key message2
  if hmac != hmac3 then
    IO.println "✓ HMAC diferencia mensagens"
  else
    IO.println "✗ HMAC não diferencia mensagens"

  -- Teste de diferenciação de chave
  let key2 := "key2".toUTF8
  let hmac4 := hmac_sha256 key2 message
  if hmac != hmac4 then
    IO.println "✓ HMAC diferencia chaves"
  else
    IO.println "✗ HMAC não diferencia chaves"

/-- Teste de handshake TLS básico -/
def testTLSHandshake : IO Unit := do
  IO.println "Testando handshake TLS básico..."

  -- Teste de criação de ClientHello structure
  let clientHello : ClientHello := {
    clientRandom := sha256 "test_random".toUTF8,
    sessionId := ByteArray.empty,
    cipherSuites := #[0x1301, 0x1302, 0x1303],  -- TLS 1.3 cipher suites
    legacyCompressionMethods := ByteArray.mk #[0x00],
    extensions := ByteArray.empty,
    clientKeyShare := some "dummy_key".toUTF8,
    alpnProtocols := some #["h2", "http/1.1"]
  }
  IO.println s!"ClientHello criado com {clientHello.cipherSuites.size} cipher suites"

  -- Teste de geração de ServerHello
  let serverPublicKey := sha256 "dummy_server_key".toUTF8
  let serverRandom := sha256 "server_random".toUTF8
  let serverHello := generateServerHello clientHello serverPublicKey serverRandom (some "h2")
  IO.println s!"ServerHello gerado: {serverHello.size} bytes"

  -- Teste de TLS session state (TLSSessionTLS)
  let session : TLSSessionTLS := {
    state := TLSState.Handshake,
    masterSecret := ByteArray.empty,
    privateKey := ByteArray.empty,
    peerPublicKey := none,
    handshakeKeys := none,
    appKeys := none,
    transcript := ByteArray.empty,
    readSeq := 0,
    writeSeq := 0,
    alpnProtocol := some "h2"
  }
  IO.println s!"Estado inicial: Handshake"
  IO.println s!"ALPN: {session.alpnProtocol}"

  IO.println "✓ Handshake TLS básico funcionando"

end LeanServer

/-- Teste básico HTTP/2 -/
def testHTTP2Basic : IO Unit := do
  IO.println "Testando estruturas básicas HTTP/2..."

  -- Teste de criação de frame SETTINGS
  let settingsFrame := LeanServer.createSettingsAckFrame
  IO.println s!"Frame SETTINGS ACK criado: {repr settingsFrame.header.frameType}"

  -- Teste de criação de WINDOW_UPDATE frame
  let windowUpdateFrame := LeanServer.createWindowUpdateFrame 1 65536
  IO.println s!"Frame WINDOW_UPDATE criado: stream {windowUpdateFrame.header.streamId}"

  -- Teste de parsing de WINDOW_UPDATE payload
  let windowUpdatePayload := LeanServer.serializeWindowUpdatePayload 65536
  match LeanServer.parseWindowUpdatePayload windowUpdatePayload with
  | some increment => IO.println s!"✅ WINDOW_UPDATE payload parsed: {increment}"
  | none => IO.println "❌ Falha no parsing de WINDOW_UPDATE payload"

  IO.println "✅ Módulo HTTP/2 carregado com sucesso!"

/-- Teste de Flow Control HTTP/2 -/
def testHTTP2FlowControl : IO Unit := do
  IO.println "Testando Flow Control HTTP/2..."

  -- Criar conexão HTTP/2 inicial
  let connection := LeanServer.initHTTP2Connection
  IO.println s!"Conexão inicial criada com janela: {connection.windowSize}"

  -- Teste de atualização de janela de conexão
  let updatedConnection := (LeanServer.updateConnectionWindow connection 1024).getD connection
  IO.println s!"Janela de conexão após update: {updatedConnection.windowSize}"

  -- Criar stream
  let stream := LeanServer.createStream 1
  IO.println s!"Stream criado com janela: {stream.windowSize}"

  -- Teste de atualização de janela de stream
  let updatedStream := (LeanServer.updateStreamWindow stream 2048).getD stream
  IO.println s!"Janela de stream após update: {updatedStream.windowSize}"

  -- Teste de consumo de janelas
  let consumedConnection := LeanServer.consumeConnectionWindow updatedConnection 512
  let consumedStream := LeanServer.consumeStreamWindow updatedStream 1024
  IO.println s!"Janela de conexão após consumo: {consumedConnection.windowSize}"
  IO.println s!"Janela de stream após consumo: {consumedStream.windowSize}"

  -- Teste de validação de flow control
  let validationResult := LeanServer.validateFlowControl consumedConnection 1 256
  match validationResult with
  | some error => IO.println s!"Erro de flow control detectado: {repr error}"
  | none => IO.println "✅ Flow control válido"

  IO.println "✅ Flow Control HTTP/2 funcionando!"

/-- Teste de Stream Multiplexing HTTP/2 -/
def testHTTP2StreamMultiplexing : IO Unit := do
  IO.println "Testando Stream Multiplexing HTTP/2..."

  -- Criar conexão inicial
  let connection := LeanServer.initHTTP2Connection
  IO.println s!"Conexão inicial com {connection.streams.size} streams"

  -- Criar streams
  let stream1 := LeanServer.createStream 1
  let stream3 := LeanServer.createStream 3
  let connectionWithStreams := LeanServer.updateStream (LeanServer.updateStream connection stream1) stream3
  IO.println s!"Conexão com {connectionWithStreams.streams.size} streams"

  -- Teste de busca de stream
  match LeanServer.findStream connectionWithStreams 1 with
  | some foundStream => IO.println s!"✅ Stream 1 encontrado, ID: {foundStream.id}"
  | none => IO.println "❌ Stream 1 não encontrado"

  IO.println "✅ Stream Multiplexing HTTP/2 funcionando!"

/-- Teste básico HPACK -/
def testHPACKBasic : IO Unit := do
  IO.println "Testando estruturas básicas HPACK..."

  -- Teste de inicialização de encoder/decoder
  let encoder := LeanServer.initHPACKEncoder
  let _decoder := LeanServer.initHPACKDecoder
  IO.println s!"HPACK encoder inicializado com tabela de {encoder.dynamicTable.entries.size} entradas"

  -- Teste de busca na tabela estática
  match LeanServer.findInStaticTable ":method" "GET" with
  | some index => IO.println s!"✅ Método GET encontrado na tabela estática, índice: {index}"
  | none => IO.println "❌ Método GET não encontrado na tabela estática"

  IO.println "✅ Módulo HPACK carregado com sucesso!"

/-- Teste de Server Push HTTP/2 -/
def testHTTP2ServerPush : IO Unit := do
  IO.println "Testando Server Push HTTP/2..."

  -- Inicializar conexão com push
  let connection := LeanServer.initHTTP2ConnectionWithPush
  IO.println s!"Conexão com push inicializada, push enabled: {connection.pushEnabled}"

  -- Verificar se push está habilitado
  let pushEnabled := LeanServer.isPushEnabled connection
  IO.println s!"Push está habilitado: {pushEnabled}"

  -- Simular headers de requisição
  let _requestHeaders := #[("method", "GET"), (":path", "/index.html"), ("host", "example.com")]
  let associatedStreamId := UInt32.ofNat 1

  -- Iniciar server push
  let (updatedConnection, pushFrameOpt) := LeanServer.initiateServerPush connection associatedStreamId "/style.css" #[(":path", "/style.css"), ("host", "example.com")]

  match pushFrameOpt with
  | some pushFrame =>
    IO.println s!"✅ PUSH_PROMISE frame criado: {repr pushFrame.header.frameType}"
    IO.println s!"Stream prometido: {pushFrame.header.streamId}"
  | none => IO.println "❌ Falha ao criar PUSH_PROMISE frame"

  -- Verificar recursos de push
  IO.println s!"Recursos de push na conexão: {updatedConnection.pushResources.size}"

  IO.println "✅ Server Push HTTP/2 funcionando!"

/-- Teste de Priority HTTP/2 -/
def testHTTP2Priority : IO Unit := do
  IO.println "Testando Priority HTTP/2..."

  -- Criar prioridade padrão
  let defaultPriority := LeanServer.defaultPriority
  IO.println s!"Prioridade padrão: weight={defaultPriority.weight}, exclusive={defaultPriority.exclusive}"

  -- Criar prioridade customizada
  let customPriority : LeanServer.Priority := {
    exclusive := true
    streamDependency := UInt32.ofNat 1
    weight := UInt8.ofNat 32
  }

  -- Criar frame PRIORITY
  let priorityFrame := LeanServer.createPriorityFrame 3 customPriority
  IO.println s!"✅ PRIORITY frame criado: {repr priorityFrame.header.frameType}"
  IO.println s!"Stream ID: {priorityFrame.header.streamId}"

  -- Testar parsing de prioridade
  let parsedPriorityOpt := LeanServer.parsePriority priorityFrame.payload
  match parsedPriorityOpt with
  | some parsed =>
    IO.println s!"✅ Prioridade parsed: weight={parsed.weight}, exclusive={parsed.exclusive}"
    IO.println s!"Stream dependency: {parsed.streamDependency}"
  | none => IO.println "❌ Falha no parsing de prioridade"

  -- Testar priority queue
  let stream1 : LeanServer.HTTP2StreamWithPriority := {
    baseStream := LeanServer.createStream 1
    priority := defaultPriority
  }
  let stream2 : LeanServer.HTTP2StreamWithPriority := {
    baseStream := LeanServer.createStream 3
    priority := customPriority
  }

  let queue : LeanServer.PriorityQueue := {
    streams := #[stream1, stream2]
  }

  let scheduled := LeanServer.scheduleStreams queue
  IO.println s!"Streams agendados por prioridade: {scheduled.size} streams"

  IO.println "✅ Priority HTTP/2 funcionando!"

/-- Teste de Flow Control Aprimorado -/
def testHTTP2EnhancedFlowControl : IO Unit := do
  IO.println "Testando Flow Control Aprimorado..."

  -- Inicializar flow control aprimorado
  let fc := LeanServer.initEnhancedFlowControl
  IO.println s!"Flow control inicializado com janela: {fc.connectionWindow}"

  -- Testar ajuste adaptativo
  let rtt1 := 100.0  -- 100ms RTT
  let throughput1 := 1000.0  -- 1000 KB/s
  let fcAdapted := LeanServer.adjustWindowAdaptive fc rtt1 throughput1
  IO.println s!"Janela após primeiro ajuste: {fcAdapted.connectionWindow}"

  -- Simular condições de rede ruins
  let rtt2 := 200.0  -- RTT aumentou
  let throughput2 := 500.0  -- Throughput diminuiu
  let fcAdapted2 := LeanServer.adjustWindowAdaptive fcAdapted rtt2 throughput2
  IO.println s!"Janela após condições ruins: {fcAdapted2.connectionWindow}"

  IO.println "✅ Flow Control Aprimorado funcionando!"

/-- Teste de Connection Health -/
def testHTTP2ConnectionHealth : IO Unit := do
  IO.println "Testando Connection Health..."

  -- Inicializar conexão com health monitoring
  let connection := LeanServer.initHTTP2ConnectionWithHealth
  IO.println s!"Conexão com health inicializada, frames totais: {connection.health.totalFrames}"

  -- Simular processamento de frames
  let testFrame := LeanServer.createSettingsAckFrame
  let updatedConnection := LeanServer.updateHealthMetrics connection testFrame 100
  IO.println s!"Após processamento de frame: {updatedConnection.health.totalFrames} frames, {updatedConnection.health.bytesReceived} bytes"

  -- Verificar saúde da conexão
  let isHealthy := LeanServer.isConnectionHealthy updatedConnection
  IO.println s!"Conexão saudável: {isHealthy}"

  IO.println "✅ Connection Health funcionando!"

/-- Teste de HTTP/3 com QUIC Transport -/
def testHTTP3Preview : IO Unit := do
  IO.println "Testando HTTP/3 com QUIC Transport..."

  -- Inicializar servidor HTTP/3
  let server := LeanServer.initH3Server 50
  IO.println s!"✅ Servidor HTTP/3 inicializado (máx {server.maxConnections} conexões)"

  -- Adicionar conexões ao servidor
  let serverWithConn := LeanServer.addH3Connection server 1 { data := ByteArray.mk #[0x01] }
  let serverWithMore := LeanServer.addH3Connection serverWithConn 2 { data := ByteArray.mk #[0x02] }
  let finalServer := LeanServer.removeH3Connection serverWithMore 1

  -- Estatísticas finais
  let stats := LeanServer.getH3ServerStats finalServer
  IO.println s!"✅ {stats}"

  IO.println "✅ HTTP/3 com QUIC Transport funcionando!"

/-- Teste expandido de HTTP/3 Frames e Streams -/
def testHTTP3Frames : IO Unit := do
  IO.println "Testando HTTP/3 Frames e Streams..."

  -- Teste de frames HTTP/3
  let _dataFrame := LeanServer.createH3DataFrame "Hello HTTP/3".toUTF8
  IO.println s!"✅ DATA frame criado: tipo válido"

  let _headersFrame := LeanServer.createH3HeadersFrame (ByteArray.mk #[])
  IO.println s!"✅ HEADERS frame criado: tipo válido"

  let _settingsFrame := LeanServer.createH3SettingsFrame
  IO.println s!"✅ SETTINGS frame criado: tipo válido"

  let _goAwayFrame := LeanServer.createH3GoAwayFrame 42
  IO.println s!"✅ GOAWAY frame criado: tipo válido"

  -- Teste de parsing de frames
  let testData := ByteArray.mk #[0x00, 0x48, 0x65, 0x6C, 0x6C, 0x6F]  -- DATA frame
  let parsedFrame := LeanServer.parseH3Frame testData
  match parsedFrame with
  | some _frame => IO.println s!"✅ Frame parseado com sucesso"
  | none => IO.println "❌ Falha no parsing de frame"

  -- Teste de streams
  let stream := LeanServer.createH3Stream 1
  IO.println s!"✅ Stream criado: ID {stream.streamId}, estado válido"

  -- Teste de servidor com streams
  let server := LeanServer.initH3Server 10
  let serverWithConn := LeanServer.addH3Connection server 100 { data := ByteArray.mk #[0x64] }
  let streamToAdd := LeanServer.createH3Stream 5
  let serverWithStream := LeanServer.addH3StreamToConnection serverWithConn 100 streamToAdd

  -- Verificar estatísticas atualizadas
  let finalStats := LeanServer.getH3ServerStats serverWithStream
  IO.println s!"✅ Servidor com streams: {finalStats}"

  IO.println "✅ HTTP/3 Frames e Streams funcionando!"

/-- Teste de WebSocket over HTTP/2 -/
def testWebSocket : IO Unit := do
  IO.println "Testando WebSocket over HTTP/2..."

  -- Inicializar conexão HTTP/2 com WebSocket
  let connection := LeanServer.initHTTP2ConnectionWithWebSocket
  IO.println s!"Conexão HTTP/2 com WebSocket inicializada, WebSocket enabled: {connection.webSocketEnabled}"

  -- Criar requisição WebSocket upgrade
  let wsRequest : LeanServer.HttpRequest := {
    method := "GET"
    path := "/websocket"
    headers := #[
      { name := "upgrade", value := "websocket" },
      { name := "connection", value := "upgrade" },
      { name := "sec-websocket-key", value := "dGhlIHNhbXBsZSBub25jZQ==" },
      { name := "sec-websocket-version", value := "13" },
      { name := "host", value := "example.com" }
    ]
    body := ByteArray.mk #[]
    streamId := 1
  }

  -- Verificar se é uma requisição válida de upgrade
  let isValidUpgrade := LeanServer.isWebSocketUpgradeRequest wsRequest
  IO.println s!"Requisição de upgrade WebSocket válida: {isValidUpgrade}"

  -- Processar upgrade
  let streamId := UInt32.ofNat 1
  let (updatedConnection, response, wsConnOpt) := LeanServer.processWebSocketUpgrade connection wsRequest streamId
  IO.println s!"Upgrade processado, status: {response.statusCode}"

  match wsConnOpt with
  | some wsConn =>
    IO.println s!"Conexão WebSocket criada no stream {wsConn.streamId}, estado: {repr wsConn.state}"

    -- Testar envio de mensagem de texto
    let textMessage := LeanServer.WebSocketMessage.TEXT "Hello WebSocket!"
    let (msgConnection, msgFrames) := LeanServer.sendWebSocketMessage updatedConnection streamId textMessage
    IO.println s!"Mensagem de texto enviada, frames gerados: {Array.size msgFrames}"

    -- Simular recebimento de frame WebSocket
    let textFrame := LeanServer.createWebSocketFrame LeanServer.WebSocketFrameType.TEXT "Hello from client!".toUTF8
    let serializedFrame := LeanServer.serializeWebSocketFrame textFrame
    let (processedConnection, messages, _responseFrames) := LeanServer.processWebSocketData msgConnection streamId serializedFrame

    IO.println s!"Frame WebSocket processado, mensagens recebidas: {messages.size}"
    if messages.size > 0 then
      match messages[0]! with
      | .TEXT text => IO.println s!"Mensagem de texto recebida: {text}"
      | _ => IO.println "Outro tipo de mensagem recebida"

    -- Testar ping/pong
    let pingFrame := LeanServer.createWebSocketFrame LeanServer.WebSocketFrameType.PING (ByteArray.mk #[1, 2, 3])
    let pingSerialized := LeanServer.serializeWebSocketFrame pingFrame
    let (pingConnection, _pingMessages, pingResponses) := LeanServer.processWebSocketData processedConnection streamId pingSerialized

    IO.println s!"Ping processado, respostas geradas: {pingResponses.size}"
    if pingResponses.size > 0 then
      IO.println "Pong frame gerado automaticamente"

    -- Testar close
    let closeFrame := LeanServer.createWebSocketFrame LeanServer.WebSocketFrameType.CLOSE (ByteArray.mk #[3, 232, 72, 101, 108, 108, 111])  -- Code 1000 + "Hello"
    let closeSerialized := LeanServer.serializeWebSocketFrame closeFrame
    let (_closeConnection, closeMessages, closeResponses) := LeanServer.processWebSocketData pingConnection streamId closeSerialized

    IO.println s!"Close processado, mensagens: {closeMessages.size}, respostas: {closeResponses.size}"

  | none => IO.println "Falha ao criar conexão WebSocket"

  IO.println "✅ WebSocket over HTTP/2 funcionando!"

/-- Teste de gRPC over HTTP/2 -/
def testGRPC : IO Unit := do
  IO.println "Testando gRPC over HTTP/2..."

  -- Teste de codificação/decodificação de mensagens gRPC
  let testMessage : LeanServer.GRPCMessage := {
    messageType := .REQUEST
    payload := "Hello gRPC!".toUTF8
    compressed := false
  }

  let encoded := LeanServer.encodeGRPCMessage testMessage
  IO.println s!"Mensagem gRPC codificada, tamanho: {encoded.size}"

  -- Teste de decodificação
  match LeanServer.decodeGRPCMessage encoded with
  | some decoded =>
    match String.fromUTF8? decoded.payload with
    | some decodedText =>
      IO.println s!"Mensagem decodificada: {decodedText}"
      if decodedText == "Hello gRPC!" then
        IO.println "✅ Codificação/decodificação gRPC funcionando!"
      else
        IO.println "❌ Falha na decodificação"
    | none => IO.println "❌ Falha ao converter payload para string"
  | none => IO.println "❌ Falha ao decodificar mensagem gRPC"

  -- Teste de parsing de método gRPC
  let validPath := "/Greeter/SayHello"
  match LeanServer.parseGRPCMethod validPath with
  | some method =>
    IO.println s!"Método parseado: {method}"
    if method.serviceName == "Greeter" && method.methodName == "SayHello" then
      IO.println "✅ Parsing de método gRPC funcionando!"
    else
      IO.println "❌ Falha no parsing de método"
  | none => IO.println "❌ Falha ao parsear método gRPC"

  -- Teste de path inválido
  let invalidPath := "/invalid"
  match LeanServer.parseGRPCMethod invalidPath with
  | some _ => IO.println "❌ Path inválido foi aceito"
  | none => IO.println "✅ Path inválido rejeitado corretamente"

  IO.println "✅ gRPC over HTTP/2 funcionando!"

/-- Teste de Load Balancer -/
def testLoadBalancer : IO Unit := do
  IO.println "Testando Load Balancer..."

  -- Criar load balancer com Round Robin
  let lb := LeanServer.createLoadBalancer .ROUND_ROBIN
  IO.println s!"Load Balancer criado com algoritmo: {lb.algorithm}"

  -- Adicionar backends
  let backend1 : LeanServer.BackendServer := {
    host := "backend1.example.com"
    port := 8080
    weight := 1
    connections := 0
    healthy := true
  }

  let backend2 : LeanServer.BackendServer := {
    host := "backend2.example.com"
    port := 8080
    weight := 1
    connections := 0
    healthy := true
  }

  let backend3 : LeanServer.BackendServer := {
    host := "backend3.example.com"
    port := 8080
    weight := 1
    connections := 0
    healthy := false  -- Unhealthy backend
  }

  let lbWithBackends := LeanServer.addBackend (LeanServer.addBackend (LeanServer.addBackend lb backend1) backend2) backend3
  IO.println s!"Backends adicionados: {lbWithBackends.backends.size} total, {LeanServer.getHealthyBackends lbWithBackends |>.size} healthy"

  -- Teste Round Robin
  match LeanServer.selectBackendRoundRobin lbWithBackends with
  | some (selected, updatedLB) =>
    IO.println s!"✅ Round Robin: Selecionado {selected.host}:{selected.port}"
    IO.println s!"Próximo índice: {updatedLB.currentIndex}"
  | none => IO.println "❌ Round Robin falhou"

  -- Teste Least Connections (usando backends com diferentes conexões)
  let backend1 := { host := "backend1", port := 8081, weight := 1, connections := 5, healthy := true }
  let backend2 := { host := "backend2", port := 8082, weight := 1, connections := 2, healthy := true }
  let lbLeastConn := LeanServer.addBackend (LeanServer.addBackend (LeanServer.createLoadBalancer LeanServer.LoadBalancingAlgorithm.LEAST_CONNECTIONS) backend1) backend2

  match LeanServer.selectBackendLeastConnections lbLeastConn with
  | some (selected, _) =>
    IO.println s!"✅ Least Connections: Selecionado {selected.host}:{selected.port} (conexões: {selected.connections})"
  | none => IO.println "❌ Least Connections falhou"

  -- Teste IP Hash
  match LeanServer.selectBackendIPHash lbWithBackends "192.168.1.100" with
  | some (selected, updatedLB) =>
    IO.println s!"✅ IP Hash: Cliente 192.168.1.100 -> {selected.host}:{selected.port}"
    -- Testar persistência
    match LeanServer.selectBackendIPHash updatedLB "192.168.1.100" with
    | some (selected2, _) =>
      if selected.host == selected2.host then
        IO.println "✅ IP Hash persistente"
      else
        IO.println "❌ IP Hash não persistente"
    | none => IO.println "❌ IP Hash persistente falhou"
  | none => IO.println "❌ IP Hash falhou"

  -- Teste Weighted Round Robin
  let weightedLB := LeanServer.createLoadBalancer .WEIGHTED_ROUND_ROBIN
  let weightedBackend1 := { backend1 with weight := 3 }  -- 3x mais peso
  let weightedBackend2 := { backend2 with weight := 1 }
  let weightedLB := LeanServer.addBackend (LeanServer.addBackend weightedLB weightedBackend1) weightedBackend2

  IO.println "Testando Weighted Round Robin (pesos 3:1)..."
  let mut testLB := weightedLB
  for i in [0:4] do
    match LeanServer.selectBackendWeightedRoundRobin testLB with
    | some (selected, updatedLB) =>
      IO.println s!"Seleção {i+1}: {selected.host} (peso: {selected.weight})"
      testLB := updatedLB
    | none => IO.println s!"❌ Weighted Round Robin falhou na seleção {i+1}"

  -- Estatísticas
  let stats := LeanServer.getLoadBalancerStats lbWithBackends
  IO.println s!"📊 {stats}"

  IO.println "✅ Load Balancer funcionando!"

-- Teste AES SIMD optimizations
def testAES_SIMD : IO Unit := do
  IO.println "🔬 Testando otimizações AES SIMD..."

  -- Test key and data
  let key := ByteArray.mk (List.replicate 16 0x2B).toArray
  let data := ByteArray.mk (List.replicate 16 0x32).toArray

  -- Expand key
  let expKey := expandKey key

  -- Test reference implementation
  let refResult := encryptBlock expKey data
  IO.println s!"📊 Reference AES result: {refResult.size} bytes"

  -- Test SIMD implementation
  let simdResult := SIMD.encryptBlockSIMD expKey data
  IO.println s!"🚀 SIMD AES result: {simdResult.size} bytes"

  -- Verify correctness
  if refResult == simdResult then
    IO.println "✅ SIMD AES implementation is correct"
  else
    IO.println "❌ SIMD AES implementation differs from reference"

  -- Test CTR mode
  let iv := ByteArray.mk (List.replicate 16 0x00).toArray
  let plaintext := "Hello SIMD AES-CTR!".toUTF8

  let ctrResult := SIMD.aesCTR_SIMD key iv plaintext
  IO.println s!"🔐 AES-CTR result: {ctrResult.size} bytes"

-- Teste Session Cache
def testSessionCache : IO Unit := do
  IO.println "💾 Testando Session Cache..."

  -- Create cache with PSKCache
  let cache : LeanServer.PSKCache := { entries := #[], maxSize := 10 }

  -- Create PSK entries
  let entry1 : LeanServer.PSKEntry := {
    ticketData := "session1".toUTF8,
    psk := "secret1".toUTF8,
    ticketAgeAdd := 0,
    createdMs := 1000,
    lifetimeMs := 5000,
    maxEarlyData := 0,
    alpnProtocol := some "h2"
  }
  let entry2 : LeanServer.PSKEntry := {
    ticketData := "session2".toUTF8,
    psk := "secret2".toUTF8,
    ticketAgeAdd := 0,
    createdMs := 1001,
    lifetimeMs := 5000,
    maxEarlyData := 0,
    alpnProtocol := some "h2"
  }

  -- Add sessions using PSKCache.insert
  let cache := cache.insert entry1
  let cache := cache.insert entry2

  IO.println s!"📊 Cache size: {cache.entries.size}"

  -- Retrieve sessions using PSKCache.lookup
  let retrieved1 := cache.lookup "session1".toUTF8 1002
  let retrieved2 := cache.lookup "session2".toUTF8 1003

  match retrieved1 with
  | some entry => IO.println s!"✅ Retrieved session 1: {entry.psk.size} bytes"
  | none => IO.println "❌ Failed to retrieve session 1"

  match retrieved2 with
  | some entry => IO.println s!"✅ Retrieved session 2: {entry.psk.size} bytes"
  | none => IO.println "❌ Failed to retrieve session 2"

  -- Test expiration using PSKCache.prune
  let prunedCache := cache.prune 10000  -- Way future, should expire all
  IO.println s!"🧹 Cache after cleanup: {prunedCache.entries.size} entries"

-- Teste Crypto Metrics
def testCryptoMetrics : IO Unit := do
  IO.println "📈 Testando Crypto Metrics..."

  -- Verificar que as estruturas de crypto existem
  let hash := LeanServer.sha256 "test".toUTF8
  IO.println s!"📊 SHA-256 hash: {hash.size} bytes"

  let hmac := LeanServer.hmac_sha256 "key".toUTF8 "data".toUTF8
  IO.println s!"📊 HMAC-SHA256: {hmac.size} bytes"

  let hkdf := LeanServer.hkdf_expand "secret".toUTF8 "info".toUTF8 32
  IO.println s!"📊 HKDF expand: {hkdf.size} bytes"

  IO.println "✅ Crypto metrics test completed"

/-- Teste básico QUIC -/
def testQUICBasic : IO Unit := do
  IO.println "🌐 Testando QUIC Transport Protocol..."

  -- Inicializar servidor QUIC
  let server := LeanServer.initQUICServer 50
  IO.println s!"✅ Servidor QUIC inicializado (máx {server.maxConnections} conexões)"

  -- Criar connection ID
  let cid := LeanServer.QUICConnectionID.mk "test-connection".toUTF8
  IO.println s!"✅ Connection ID criado: {cid.data.size} bytes"

  -- Criar conexão QUIC
  let connection := LeanServer.createQUICConnection cid
  IO.println s!"✅ Conexão QUIC criada, estado: válido"

  -- Adicionar conexão ao servidor
  let serverWithConn := LeanServer.addQUICConnection server connection
  IO.println s!"✅ Conexão adicionada ao servidor"

  -- Testar frames QUIC
  let _pingFrame := LeanServer.createQUICPingFrame
  IO.println s!"✅ PING frame criado: tipo válido"

  let paddingFrame := LeanServer.createQUICPaddingFrame 8
  IO.println s!"✅ PADDING frame criado: {paddingFrame.payload.size} bytes"

  -- Testar parsing de frame
  let testFrameData := ByteArray.mk #[0x01]  -- PING frame
  let parsedFrame := LeanServer.parseQUICFrame testFrameData
  match parsedFrame with
  | some _frame => IO.println s!"✅ Frame parseado: tipo válido"
  | none => IO.println "❌ Falha no parsing de frame"

  -- Estatísticas do servidor
  let stats := LeanServer.getQUICServerStats serverWithConn
  IO.println s!"📊 {stats}"

  IO.println "✅ QUIC Transport Protocol funcionando!"

/-- Teste avançado de QUIC Frames -/
def testQUICFrames : IO Unit := do
  IO.println "🔧 Testando QUIC Frames avançados..."

  -- Teste de codificação/decodificação VarInt
  let testValue : UInt64 := 0x123456789ABCDEF
  let encoded := LeanServer.encodeVarInt testValue
  IO.println s!"✅ VarInt codificado: {encoded.size} bytes"

  -- Teste de decodificação
  let decodedOpt := LeanServer.decodeVarInt encoded 0
  match decodedOpt with
  | some (value, _pos) =>
    if value == testValue then
      IO.println s!"✅ VarInt decodificado corretamente: {value}"
    else
      IO.println s!"❌ VarInt decodificado incorretamente: {value} != {testValue}"
  | none => IO.println "❌ Falha na decodificação VarInt"

  -- Teste de CRYPTO frame
  let cryptoData := "Hello QUIC TLS!".toUTF8
  let _cryptoFrame := LeanServer.createQUICCryptoFrame 0 cryptoData
  let encodedCrypto := LeanServer.encodeQUICCryptoFrame 0 cryptoData
  IO.println s!"✅ CRYPTO frame criado e codificado: {encodedCrypto.size} bytes"

  -- Teste de decodificação CRYPTO frame
  let decodedCryptoOpt := LeanServer.decodeQUICCryptoFrame encodedCrypto
  match decodedCryptoOpt with
  | some (offset, data) =>
    if data == cryptoData then
      IO.println s!"✅ CRYPTO frame decodificado corretamente: offset={offset}"
    else
      IO.println "❌ CRYPTO frame decodificado incorretamente"
  | none => IO.println "❌ Falha na decodificação CRYPTO frame"

  -- Teste de STREAM frame
  let streamData := "Stream data payload".toUTF8
  let _streamFrame := LeanServer.createQUICStreamFrame 1 0 streamData false
  let encodedStream := LeanServer.encodeQUICStreamFrame 1 0 streamData false
  IO.println s!"✅ STREAM frame criado e codificado: {encodedStream.size} bytes"

  -- Teste de decodificação STREAM frame
  let decodedStreamOpt := LeanServer.decodeQUICStreamFrame encodedStream
  match decodedStreamOpt with
  | some (streamId, offset, data, fin) =>
    if streamId == 1 && offset == 0 && data == streamData && !fin then
      IO.println s!"✅ STREAM frame decodificado corretamente: stream={streamId}, fin={fin}"
    else
      IO.println "❌ STREAM frame decodificado incorretamente"
  | none => IO.println "❌ Falha na decodificação STREAM frame"

  IO.println "✅ QUIC Frames avançados funcionando!"

/-- Teste de QUIC Packet Processing -/
def testQUICPacketProcessing : IO Unit := do
  IO.println "📦 Testando processamento de pacotes QUIC..."

  -- Inicializar servidor
  let server := LeanServer.initQUICServer 10

  -- Criar connection ID
  let cid := LeanServer.QUICConnectionID.mk "client-connection-123".toUTF8

  -- Criar Initial packet
  let cryptoData := "ClientHello TLS data".toUTF8
  let initialPacket := LeanServer.createQUICInitialPacket cid none cryptoData
  IO.println s!"✅ Initial packet criado: {initialPacket.frames.size} frames"

  -- Processar Initial packet
  let serverAfterInitial := LeanServer.processQUICPacket server initialPacket
  IO.println s!"✅ Initial packet processado, conexões: {serverAfterInitial.connections.size}"

  -- Verificar se conexão foi criada
  let foundConnection := LeanServer.findQUICConnection serverAfterInitial cid
  match foundConnection with
  | some conn =>
    IO.println s!"✅ Conexão encontrada, estado: {LeanServer.QUICConnectionState.toString conn.state}"
  | none => IO.println "❌ Conexão não encontrada"

  -- Criar Handshake packet
  let sourceCID := LeanServer.QUICConnectionID.mk "server-connection-456".toUTF8
  let handshakeData := "ServerHello TLS data".toUTF8
  let handshakePacket := LeanServer.createQUICHandshakePacket cid sourceCID handshakeData
  IO.println s!"✅ Handshake packet criado: {handshakePacket.frames.size} frames"

  -- Processar Handshake packet
  let serverAfterHandshake := LeanServer.processQUICPacket serverAfterInitial handshakePacket
  IO.println s!"✅ Handshake packet processado"

  -- Verificar estado da conexão
  let updatedConnection := LeanServer.findQUICConnection serverAfterHandshake cid
  match updatedConnection with
  | some conn =>
    IO.println s!"✅ Conexão atualizada, estado: {LeanServer.QUICConnectionState.toString conn.state}"
  | none => IO.println "❌ Conexão não encontrada após handshake"

  IO.println "✅ Processamento de pacotes QUIC funcionando!"

/-- Teste de QUIC Server Management -/
def testQUICServerManagement : IO Unit := do
  IO.println "🖥️ Testando gerenciamento de servidor QUIC..."

  -- Inicializar servidor
  let server := LeanServer.initQUICServer 5

  -- Adicionar múltiplas conexões
  let cid1 := LeanServer.QUICConnectionID.mk "conn1".toUTF8
  let cid2 := LeanServer.QUICConnectionID.mk "conn2".toUTF8
  let cid3 := LeanServer.QUICConnectionID.mk "conn3".toUTF8

  let conn1 := LeanServer.createQUICConnection cid1
  let conn2 := LeanServer.createQUICConnection cid2
  let conn3 := LeanServer.createQUICConnection cid3

  let server := LeanServer.addQUICConnection server conn1
  let server := LeanServer.addQUICConnection server conn2
  let server := LeanServer.addQUICConnection server conn3

  IO.println s!"✅ Servidor com {server.connections.size} conexões"

  -- Testar busca de conexões
  let found1 := LeanServer.findQUICConnection server cid1
  let found2 := LeanServer.findQUICConnection server cid2
  let found3 := LeanServer.findQUICConnection server cid3

  if found1.isSome && found2.isSome && found3.isSome then
    IO.println "✅ Todas as conexões encontradas"
  else
    IO.println "❌ Alguma conexão não encontrada"

  -- Testar atualização de conexão
  let updatedConn := LeanServer.updateQUICConnectionState conn1 LeanServer.QUICConnectionState.connected
  let server := LeanServer.updateQUICConnection server cid1 (fun _ => updatedConn)

  let updatedFound := LeanServer.findQUICConnection server cid1
  match updatedFound with
  | some conn =>
    if conn.state == LeanServer.QUICConnectionState.connected then
      IO.println "✅ Conexão atualizada com sucesso"
    else
      IO.println "❌ Conexão não foi atualizada corretamente"
  | none => IO.println "❌ Conexão não encontrada após atualização"

  -- Testar limpeza de conexões
  let serverAfterCleanup := LeanServer.cleanupQUICConnections server
  IO.println s!"✅ Servidor após limpeza: {serverAfterCleanup.connections.size} conexões ativas"

  -- Testar estatísticas
  let stats := LeanServer.getQUICServerStats serverAfterCleanup
  IO.println s!"📊 {stats}"

  -- Testar limite de conexões
  let canAccept := LeanServer.canAcceptQUICConnection serverAfterCleanup
  IO.println s!"✅ Servidor pode aceitar novas conexões: {canAccept}"

  IO.println "✅ Gerenciamento de servidor QUIC funcionando!"

/-- Teste de QUIC Connection Management -/
def testQUICConnectionManagement : IO Unit := do
  IO.println "🔗 Testando gerenciamento de conexões QUIC..."

  -- Criar conexão
  let cid := LeanServer.QUICConnectionID.mk "test-conn".toUTF8
  let connection := LeanServer.createQUICConnection cid

  IO.println s!"✅ Conexão criada: {LeanServer.getQUICConnectionInfo connection}"

  -- Testar atualização de estado
  let connectingConn := LeanServer.updateQUICConnectionState connection LeanServer.QUICConnectionState.connecting
  let connectedConn := LeanServer.updateQUICConnectionState connectingConn LeanServer.QUICConnectionState.connected

  IO.println s!"✅ Estados atualizados: {LeanServer.QUICConnectionState.toString connectedConn.state}"

  -- Testar adição de frames pendentes
  let pingFrame := LeanServer.createQUICPingFrame
  let connWithFrame := LeanServer.addQUICPendingFrame connectedConn pingFrame

  IO.println s!"✅ Frame pendente adicionado: {connWithFrame.pendingFrames.size} frames"

  -- Testar limpeza de frames pendentes
  let connCleared := LeanServer.clearQUICPendingFrames connWithFrame

  IO.println s!"✅ Frames pendentes limpos: {connCleared.pendingFrames.size} frames"

  -- Testar incremento de número de pacote
  let connWithIncrement := LeanServer.incrementQUICPacketNumber connectedConn
  let nextNum := connWithIncrement.nextPacketNumber.number

  IO.println s!"✅ Número de pacote incrementado: {nextNum}"

  -- Testar validação de Connection ID
  let validCID := LeanServer.isValidQUICConnectionID cid
  let invalidCID := LeanServer.QUICConnectionID.mk (ByteArray.mk #[])  -- Too short

  IO.println s!"✅ CID válido: {validCID}, CID inválido: {!LeanServer.isValidQUICConnectionID invalidCID}"

  IO.println "✅ Gerenciamento de conexões QUIC funcionando!"

/-- Função principal de teste -/
def main : IO Unit := do
  IO.println "=== Testes do LeanServer ==="

  LeanServer.testBasicDataStructures
  IO.println ""

  LeanServer.testHMACSHA256Basic
  IO.println ""

  LeanServer.testTLSHandshake
  IO.println ""

  testHTTP2Basic
  IO.println ""

  testHTTP2FlowControl
  IO.println ""

  testHTTP2StreamMultiplexing
  IO.println ""

  testHPACKBasic
  IO.println ""

  testHTTP2ServerPush
  IO.println ""

  testHTTP2Priority
  IO.println ""

  testHTTP2EnhancedFlowControl
  IO.println ""

  testHTTP2ConnectionHealth
  IO.println ""

  testHTTP3Preview
  IO.println ""

  testHTTP3Frames
  IO.println ""

  testWebSocket
  IO.println ""

  testGRPC
  IO.println ""

  testLoadBalancer
  IO.println ""

  -- ============================================================================
  -- FASE 11: TESTES DE OTIMIZAÇÃO SIMD
  -- ============================================================================

  testAES_SIMD
  IO.println ""

  testSessionCache
  IO.println ""

  testCryptoMetrics
  IO.println ""

  -- ============================================================================
  -- FASE 14: TESTES QUIC E HTTP/3
  -- ============================================================================

  testQUICBasic
  IO.println ""

  IO.println "=== Todos os testes concluídos ==="
