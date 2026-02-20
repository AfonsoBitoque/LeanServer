# 📚 API Reference - LeanServer

Esta é a documentação da API do LeanServer, incluindo os módulos principais, tipos, funções e estruturas de dados disponíveis.

> Para a referência completa auto-gerada com todas as funções, veja [API_GENERATED.md](API_GENERATED.md).

## 📁 Estrutura dos Módulos

```
LeanServer/
├── Proofs.lean                    # Provas formais (169 teoremas)
├── Core/
│   ├── Base64.lean                # Codificação Base64
│   ├── Basic.lean                 # Tipos básicos e utilitários HTTP
│   ├── BufferPool.lean            # Pool de buffers reutilizáveis
│   ├── ByteSlice.lean             # Operações de slicing de bytes
│   ├── Logger.lean                # Sistema de logging estruturado
│   ├── ParserCombinators.lean     # Framework de parser combinators
│   ├── SafeAccess.lean            # Acesso seguro a byte arrays
│   └── ServerError.lean           # Tipos de erro unificados
├── Crypto/
│   ├── AES.lean                   # AES-128/256-GCM
│   ├── CertificateManager.lean    # Gestão de certificados X.509
│   ├── Crypto.lean                # TLS 1.3 completo, chaves, sessões
│   ├── FFI.lean                   # Bindings FFI para OpenSSL
│   ├── MTLSAuth.lean              # Autenticação mutual TLS
│   ├── NonceManager.lean          # Gestão de nonces criptográficos
│   ├── RSA.lean                   # Criptografia RSA
│   ├── SHA256.lean                # Hash SHA-256
│   ├── SideChannel.lean           # Proteções side-channel
│   ├── TLSHandshake.lean          # Máquina de estados TLS
│   ├── TLSKeySchedule.lean        # Key schedule TLS 1.3
│   ├── TLSSession.lean            # Gestão de sessões TLS
│   ├── X25519.lean                # Curvas elípticas X25519
│   └── X509Validation.lean        # Validação de certificados X.509
├── Protocol/
│   ├── GRPC.lean                  # Suporte gRPC
│   ├── HPACK.lean                 # Compressão HPACK (HTTP/2)
│   ├── HTTP2.lean                 # Protocolo HTTP/2
│   ├── HTTP3.lean                 # Protocolo HTTP/3
│   ├── QUIC.lean                  # Protocolo QUIC
│   ├── QUICRetry.lean             # QUIC retry e proteção anti-amplificação
│   ├── WebSocket.lean             # Protocolo WebSocket
│   ├── WebSocketOverHTTP2.lean    # WebSocket sobre HTTP/2
│   └── WSCompression.lean         # Compressão per-message WebSocket
├── Server/
│   ├── HTTPServer.lean            # Servidor HTTPS principal (~5,650 LOC)
│   ├── HTTPServer/
│   │   ├── ConnectionPool.lean    # Pool de conexões
│   │   ├── DistributedRateLimiter.lean  # Rate limiting distribuído
│   │   ├── H2Handler.lean         # Handler HTTP/2
│   │   ├── QPACK.lean             # Compressão QPACK (HTTP/3)
│   │   ├── QUICHandler.lean       # Handler QUIC
│   │   ├── RateLimiter.lean       # Rate limiting
│   │   ├── Router.lean            # Roteamento de requests
│   │   ├── ServerConfig.lean      # Configuração do servidor
│   │   ├── TLSHandler.lean        # Handler TLS
│   │   └── Tracing.lean           # Tracing distribuído
│   ├── Benchmark.lean             # Framework de benchmark
│   ├── BlueGreenDeployment.lean   # Deploy blue-green
│   ├── CanaryDeployment.lean      # Deploy canary
│   ├── CircuitBreaker.lean        # Circuit breaker pattern
│   ├── Concurrency.lean           # Primitivas de concorrência
│   ├── ConfigReload.lean          # Hot reload de configuração
│   ├── ContentNegotiation.lean    # Negociação de conteúdo
│   ├── GracefulShutdown.lean      # Shutdown gracioso
│   ├── LoadBalancer.lean          # Balanceamento de carga
│   ├── Metrics.lean               # Métricas Prometheus
│   ├── Production.lean            # Funcionalidades de produção
│   ├── Timeout.lean               # Gestão de timeouts
│   └── ...                        # Outros módulos de servidor
├── Db/
│   ├── Database.lean              # Interface de banco de dados
│   ├── MySQL.lean                 # Driver MySQL
│   ├── PostgreSQL.lean            # Driver PostgreSQL
│   └── SQLite.lean                # Driver SQLite
├── Web/
│   ├── Framework.lean             # Framework web
│   ├── SampleWebApp.lean          # App de exemplo
│   ├── WebAppTests.lean           # Testes da web app
│   ├── WebApplication.lean        # App web principal
│   └── WebApplicationSimple.lean  # App web simplificada
└── Spec/
    ├── TLSSpec.lean               # Especificação abstrata TLS
    ├── TLSModel.lean              # Modelo executável TLS
    ├── TLSRefinement.lean         # Provas de refinamento
    ├── TLSStateMachineProofs.lean # Provas da máquina de estados
    ├── ProtocolInvariants.lean    # Invariantes de protocolo
    ├── CompositionProofs.lean     # Provas de composição
    ├── UniversalCodecProofs.lean  # Provas de codec
    ├── AdvancedProofs.lean        # Provas avançadas
    ├── AdvancedProofs2.lean       # Provas avançadas (cont.)
    ├── AdvancedProofs3.lean       # Provas avançadas (cont.)
    └── RFCCompliance.lean         # Conformidade RFC
```

## 🔧 Módulo Core

### `ServerConfig` (Server/HTTPServer.lean)
```lean
structure ServerConfig where
  host : String := "0.0.0.0"
  port : UInt16 := 4433
  certPath : String := "cert.pem"
  keyPath : String := "key.pem"
  maxConnections : Nat := 1000
  logLevel : String := "DEBUG"
  enableWebSocket : Bool := true
  enableServerPush : Bool := true
  healthCheckPath : String := "/health"
  metricsPath : String := "/metrics"
```

Configuração do servidor carregada de `server.config`. Chaves suportadas:
- `host`, `port`, `certificate_path`, `private_key_path`
- `max_connections`, `log_level`
- `enable_websocket`, `enable_server_push`
- `health_check_path`, `metrics_path`

### `LogLevel` (Core/Logger.lean)
```lean
inductive LogLevel where
  | FATAL | ERROR | WARN | INFO | DEBUG | TRACE
```

6 níveis de log com prioridade decrescente.

### Tipos Básicos (Core/Basic.lean)

#### `HTTPRequest`
```lean
structure HTTPRequest where
  method : String
  path : String
  headers : List (String × String)
  body : ByteArray
```

#### `HTTPResponse`
```lean
structure HTTPResponse where
  status : Nat
  headers : List (String × String)
  body : String
```

### Erros (Core/ServerError.lean)
```lean
inductive ServerError where
  | network (kind : NetworkErrorKind) (msg : String)
  | tls (kind : TLSErrorKind) (msg : String)
  | protocol (kind : ProtocolErrorKind) (msg : String)
  | quic (kind : QUICErrorKind) (msg : String)
  | config (kind : ConfigErrorKind) (msg : String)
  | internal (msg : String)
  | timeout (msg : String)
```

## 🔐 Módulo Crypto

### Funções Criptográficas

#### SHA-256
```lean
def sha256 (input : ByteArray) : ByteArray
def hmac_sha256 (key msg : ByteArray) : ByteArray
def hkdf_expand (ikm salt info : ByteArray) (len : Nat) : ByteArray
```

#### AES-128/256-GCM
```lean
def aesGCMEncrypt (key iv plaintext aad : ByteArray) : ByteArray × ByteArray
def aesGCMDecrypt (key iv ciphertext aad tag : ByteArray) : Option ByteArray
def aes256GCMEncrypt (key iv plaintext aad : ByteArray) : ByteArray × ByteArray
def aes256GCMDecrypt (key iv ciphertext aad tag : ByteArray) : Option ByteArray
```

#### X25519
```lean
def x25519 (privateKey publicKey : ByteArray) : ByteArray
```

#### RSA
```lean
def rsaEncrypt (key : RSAPublicKey) (plaintext : ByteArray) : ByteArray
def rsaDecrypt (key : RSAPrivateKey) (ciphertext : ByteArray) : Option ByteArray
```

### TLS 1.3

#### `TLSState`
```lean
inductive TLSState where
  | Initial | ClientHelloSent | ServerHelloReceived
  | HandshakeKeysDerived | Connected | Closed
```

#### Estado de Sessão
```lean
structure TLSSession (state : TLSState) where
  clientRandom : ByteArray
  serverRandom : ByteArray
  handshakeKeys : Option HandshakeKeys
  applicationKeys : Option ApplicationKeys
```

## 🌐 Módulo Protocol

### HTTP/2 (Protocol/HTTP2.lean)

Implementação completa do HTTP/2 com multiplexação de streams, controle de fluxo,
priorização, e suporte a CONTINUATION frames.

### HPACK (Protocol/HPACK.lean)

Compressão de headers HTTP/2 com tabela estática, tabela dinâmica, e codificação Huffman.

### WebSocket (Protocol/WebSocket.lean)

Protocolo WebSocket com masking, fragmentação, e extensões de compressão.

### QUIC (Protocol/QUIC.lean)

Protocolo QUIC com migração de conexão, 0-RTT, e proteção anti-amplificação.

### gRPC (Protocol/GRPC.lean)

Suporte gRPC sobre HTTP/2 com unary, server-streaming, client-streaming, e bidirectional streaming.

## 🏭 Módulo Server

### `loadServerConfig` (Server/HTTPServer.lean)
```lean
def loadServerConfig (quiet : Bool := true) : IO ServerConfig
```

Carrega configuração de `server.config`. O parâmetro `quiet` suprime output
durante compilação (default: `true`).

### Funcionalidades de Produção

- **Métricas**: Endpoint Prometheus em `/metrics`
- **Health Check**: Endpoint em `/health`
- **Graceful Shutdown**: Drena conexões antes de parar
- **Hot Reload**: Recarrega configuração sem restart
- **Rate Limiting**: Limitação de taxa por IP
- **Circuit Breaker**: Proteção contra cascata de falhas
- **Load Balancer**: Round-robin, least-connections, weighted
- **Blue-Green / Canary Deployment**: Estratégias de deploy

## 🛡️ Provas Formais

### Estatísticas
- **914 teoremas**, 0 axiomas, 0 sorry
- **4 definições parciais** (`partial`)
- **392 usos de `native_decide`** (verificações concretas)
- **Proofs.lean**: 169 teoremas (test vectors criptográficos)
- **Spec/**: 654 teoremas (especificações formais, refinamento, invariantes)

### Teoremas Principais

#### Criptografia
- `sha256_deterministic`: Determinismo do SHA-256
- `sha256_length_32`: Output sempre 32 bytes
- `aes_encrypt_decrypt_inverse`: AES é invertível
- `x25519_deterministic`: Determinismo do X25519

#### TLS
- `tls_state_machine_theorem`: Transições válidas da máquina de estados
- `tls_key_uniqueness`: Chaves únicas de randoms únicos
- `handshake_integrity_theorem`: Integridade do transcript hash
- `mtls_mutual_auth_theorem`: Autenticação mútua

#### Protocolos
- `http2_stream_id_odd`: Streams client-initiated são ímpares
- `hpack_integer_encode_decode_inverse`: Codec HPACK é invertível
- `websocket_frame_mask_involution`: XOR masking é involutivo
- `quic_pn_monotonic`: Packet numbers QUIC são monotónicos

## 📖 Uso

### Composição de Módulos

```lean
import LeanServer.Core.Basic
import LeanServer.Core.Logger
import LeanServer.Crypto.Crypto
import LeanServer.Protocol.HTTP2
import LeanServer.Server.HTTPServer
```

### Configuração

Crie um ficheiro `server.config`:
```ini
host = "0.0.0.0"
port = "8443"
certificate_path = "cert.pem"
private_key_path = "key.pem"
max_connections = "1000"
log_level = "INFO"
enable_websocket = "true"
enable_server_push = "true"
health_check_path = "/health"
metrics_path = "/metrics"
```

### Build e Execução
```bash
lake build
.lake/build/bin/leanserver
```

## 🔗 Referências Cruzadas

- **Core/**: Tipos fundamentais usados por todos os módulos
- **Crypto/**: Base criptográfica para TLS e HTTPServer
- **Protocol/**: HTTP/2, QUIC, WebSocket, gRPC
- **Server/**: Servidor HTTPS e funcionalidades de produção
- **Db/**: Interfaces de banco de dados (SQLite, MySQL, PostgreSQL)
- **Web/**: Framework web e aplicações de exemplo
- **Spec/**: Especificações formais e provas de refinamento
- **Proofs.lean**: Test vectors e provas concretas

Para a referência completa auto-gerada, consulte [API_GENERATED.md](API_GENERATED.md).
Para exemplos práticos de uso, consulte a pasta `examples/`.
