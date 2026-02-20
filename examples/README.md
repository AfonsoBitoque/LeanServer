# 🌟 Exemplos Práticos - LeanServer

Esta pasta contém exemplos práticos de uso do LeanServer para diferentes cenários de produção.

## 📁 Exemplos Disponíveis

- `basic-server/` - Servidor HTTPS básico
- `websocket-chat/` - Aplicação de chat com WebSocket
- `grpc-service/` - Serviço gRPC
- `load-balancer/` - Configuração com load balancer
- `metrics-monitoring/` - Monitoramento avançado
- `tls-config/` - Configurações TLS avançadas

## 🚀 Exemplo 1: Servidor HTTPS Básico

### Estrutura
```
basic-server/
├── server.config
├── cert.pem
├── key.pem
├── Main.lean
└── README.md
```

### server.config
```toml
# Configuração básica do servidor HTTPS
host = "0.0.0.0"
port = "8443"
tls_enabled = "true"
max_connections = "100"
log_level = "INFO"

# Funcionalidades básicas
enable_websocket = "false"
enable_http2 = "true"
enable_metrics = "true"

# Certificados
cert_file = "cert.pem"
key_file = "key.pem"

# Endpoints padrão
health_check_path = "/health"
metrics_path = "/metrics"
```

### Main.lean
```lean
import LeanServer.Production
import LeanServer.HTTPServer

def main : IO Unit := do
  -- Carregar configuração
  let config ← loadConfig "server.config"

  -- Inicializar componentes
  let crypto ← initCrypto config.certFile config.keyFile
  let http2 ← initHTTP2
  let production ← initProduction config

  -- Criar servidor
  let server ← createHTTPSServer config crypto http2 production

  -- Adicionar handler personalizado
  let server ← server.addHandler "/hello" (fun req => do
    return {
      status = 200,
      headers = [
        ("Content-Type", "text/plain"),
        ("X-Powered-By", "LeanServer")
      ],
      body = "Olá do LeanServer! 🚀"
    })

  -- Iniciar servidor
  IO.println "🚀 Servidor HTTPS iniciado na porta 8443"
  server.run
```

### Executar
```bash
# Compilar
lake build

# Executar
./build/bin/basic-server

# Testar
curl -k https://localhost:8443/hello
# Resposta: Olá do LeanServer! 🚀

curl -k https://localhost:8443/health
# Resposta: {"status":"healthy","uptime":123,"connections":1}
```

## 💬 Exemplo 2: Chat com WebSocket

### Main.lean
```lean
import LeanServer.WebSocketOverHTTP2
import LeanServer.Production

def main : IO Unit := do
  let config ← loadConfig "server.config"
  let server ← createHTTPSServer config

  -- Mapa de conexões ativas
  let connections ← IO.mkRef (HashMap.empty : HashMap String WebSocketConnection)

  -- Handler para upgrade WebSocket
  let server ← server.addWebSocketHandler "/chat" (fun wsConn clientId => do
    -- Registrar conexão
    connections.modify (fun map => map.insert clientId wsConn)

    -- Loop de mensagens
    repeat do
      let msg ← wsConn.receiveMessage
      match msg with
      | some (text, data) =>
        -- Broadcast para todos os clientes conectados
        connections.get >>= (fun conns =>
          conns.forM (fun ⟨_, conn⟩ =>
            conn.sendMessage s!"[{clientId}]: {data}"))
      | none => break

    -- Remover conexão ao desconectar
    connections.modify (fun map => map.erase clientId))

  server.run
```

### Cliente JavaScript (chat.html)
```html
<!DOCTYPE html>
<html>
<head>
    <title>LeanServer WebSocket Chat</title>
</head>
<body>
    <div id="messages"></div>
    <input id="messageInput" type="text" placeholder="Digite sua mensagem...">
    <button onclick="sendMessage()">Enviar</button>

    <script>
        const ws = new WebSocket('wss://localhost:8443/chat');
        const messages = document.getElementById('messages');
        const input = document.getElementById('messageInput');

        ws.onmessage = function(event) {
            const msg = document.createElement('div');
            msg.textContent = event.data;
            messages.appendChild(msg);
        };

        function sendMessage() {
            if (input.value.trim()) {
                ws.send(input.value);
                input.value = '';
            }
        }

        input.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    </script>
</body>
</html>
```

## 📊 Exemplo 3: Serviço gRPC

### protobuf/service.proto
```protobuf
syntax = "proto3";

service Calculator {
  rpc Add (AddRequest) returns (AddResponse);
  rpc Multiply (MultiplyRequest) returns (MultiplyResponse);
}

message AddRequest {
  int32 a = 1;
  int32 b = 2;
}

message AddResponse {
  int32 result = 1;
}

message MultiplyRequest {
  int32 a = 1;
  int32 b = 2;
}

message MultiplyResponse {
  int32 result = 1;
}
```

### Main.lean
```lean
import LeanServer.GRPC

def main : IO Unit := do
  let config ← loadConfig "server.config"
  let server ← createGRPCServer config

  -- Registrar serviços gRPC
  let server ← server.addGRPCService "Calculator" [
    ("Add", fun req => do
      let request ← parseGRPCMessage req.payload
      let a ← getField request "a"
      let b ← getField request "b"
      let result := a + b
      createGRPCResponse (createMessage [("result", result)]) GRPCStatus.OK),

    ("Multiply", fun req => do
      let request ← parseGRPCMessage req.payload
      let a ← getField request "a"
      let b ← getField request "b"
      let result := a * b
      createGRPCResponse (createMessage [("result", result)]) GRPCStatus.OK)
  ]

  server.run
```

### Cliente Python
```python
import grpc
import calculator_pb2
import calculator_pb2_grpc

def run():
    with grpc.insecure_channel('localhost:8443') as channel:
        stub = calculator_pb2_grpc.CalculatorStub(channel)

        # Teste de soma
        response = stub.Add(calculator_pb2.AddRequest(a=5, b=3))
        print(f"5 + 3 = {response.result}")

        # Teste de multiplicação
        response = stub.Multiply(calculator_pb2.MultiplyRequest(a=4, b=7))
        print(f"4 * 7 = {response.result}")

if __name__ == '__main__':
    run()
```

## ⚖️ Exemplo 4: Load Balancer

### lb-config.config
```toml
# Configuração do load balancer
host = "0.0.0.0"
port = "8443"
tls_enabled = "true"

# Backends
backends = [
  "https://server1.example.com:8443",
  "https://server2.example.com:8443",
  "https://server3.example.com:8443"
]

# Algoritmo de balanceamento
lb_algorithm = "least_connections"

# Health checks
health_check_interval = "30"
health_check_timeout = "5"
health_check_path = "/health"

# Sessão sticky (opcional)
sticky_sessions = "true"
sticky_cookie_name = "LEANSESSION"
```

### Main.lean
```lean
import LeanServer.LoadBalancer

def main : IO Unit := do
  let config ← loadLBConfig "lb-config.config"

  -- Criar load balancer
  let lb ← createLoadBalancer config.backends config.algorithm

  -- Configurar health checks
  let lb ← lb.withHealthChecks config.healthCheckInterval

  -- Configurar sticky sessions (opcional)
  let lb ← if config.stickySessions then
    lb.withStickySessions config.stickyCookieName
  else lb

  -- Iniciar servidor LB
  let server ← createLBSerer config.host config.port lb
  server.run
```

## 📈 Exemplo 5: Monitoramento Avançado

### monitoring.config
```toml
# Configuração de monitoramento
host = "0.0.0.0"
port = "8443"
enable_metrics = "true"
metrics_path = "/metrics"

# Prometheus
prometheus_enabled = "true"
prometheus_path = "/prometheus"

# Alertas customizados
alert_rules = [
  "request_rate > 1000 for 5m",
  "error_rate > 0.05 for 1m",
  "memory_usage > 80% for 10m"
]

# Logs estruturados
log_format = "json"
log_fields = ["timestamp", "level", "message", "request_id", "user_id", "duration"]

# Tracing
tracing_enabled = "true"
tracing_sample_rate = "0.1"
```

### Main.lean
```lean
import LeanServer.Production
import LeanServer.Monitoring

def main : IO Unit := do
  let config ← loadConfig "monitoring.config"
  let server ← createHTTPSServer config

  -- Configurar métricas customizadas
  let server ← server.addMetricsCollector "custom_metrics" (fun state => [
    ("custom_requests_total", state.customRequests),
    ("custom_errors_total", state.customErrors),
    ("custom_latency_avg", state.avgLatency)
  ])

  -- Middleware de tracing
  let server ← server.addMiddleware (fun req next => do
    let start ← IO.monoMsNow
    let traceId ← generateTraceId

    -- Adicionar headers de tracing
    let req ← req.addHeader "X-Trace-Id" traceId

    let resp ← next req

    let duration ← IO.monoMsNow >>= (fun end => pure (end - start))

    -- Registrar métrica
    recordLatency req.path duration

    -- Log estruturado
    logStructured "request" #[
      ("trace_id", traceId),
      ("method", req.method),
      ("path", req.path),
      ("status", resp.status),
      ("duration_ms", duration)
    ]

    pure resp)

  -- Health check customizado
  let server ← server.addHealthCheck "database" checkDatabaseHealth
  let server ← server.addHealthCheck "cache" checkCacheHealth

  server.run
```

### Dashboard Grafana (JSON)
```json
{
  "dashboard": {
    "title": "LeanServer Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [{
          "expr": "rate(leanserver_requests_total[5m])",
          "legendFormat": "Requests/sec"
        }]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [{
          "expr": "rate(leanserver_errors_total[5m]) / rate(leanserver_requests_total[5m])",
          "legendFormat": "Error Rate"
        }]
      },
      {
        "title": "Active Connections",
        "type": "singlestat",
        "targets": [{
          "expr": "leanserver_active_connections",
          "legendFormat": "Active Connections"
        }]
      }
    ]
  }
}
```

## 🔐 Exemplo 6: Configurações TLS Avançadas

### tls-advanced.config
```toml
# Configurações TLS avançadas
host = "0.0.0.0"
port = "8443"
tls_enabled = "true"

# Versão TLS mínima
tls_min_version = "1.3"

# Cipher suites prioritárias
cipher_suites = [
  "TLS_AES_256_GCM_SHA384",
  "TLS_AES_128_GCM_SHA256",
  "TLS_CHACHA20_POLY1305_SHA256"
]

# Certificados
cert_file = "fullchain.pem"
key_file = "privkey.pem"
chain_file = "chain.pem"

# OCSP Stapling
ocsp_enabled = "true"
ocsp_url = "http://ocsp.example.com"
ocsp_cache_size = "1000"
ocsp_cache_ttl = "3600"

# HSTS
hsts_enabled = "true"
hsts_max_age = "31536000"
hsts_include_subdomains = "true"
hsts_preload = "false"

# HPKP (HTTP Public Key Pinning) - DEPRECATED
# hpkp_enabled = "false"

# Session tickets
session_tickets_enabled = "true"
session_ticket_key_rotation = "86400"

# Client certificates (mTLS)
client_certs_required = "false"
client_cert_ca_file = "client-ca.pem"

# Perfect Forward Secrecy
force_pfs = "true"
dh_param_file = "dhparam.pem"
```

### Main.lean
```lean
import LeanServer.Crypto
import LeanServer.TLS

def main : IO Unit := do
  let config ← loadTLSConfig "tls-advanced.config"

  -- Configurar contexto TLS avançado
  let tlsConfig : TLSConfig := {
    minVersion := config.tlsMinVersion,
    cipherSuites := config.cipherSuites,
    certificates := loadCertificates config.certFile config.keyFile config.chainFile,
    enableOCSP := config.ocspEnabled,
    ocspResponder := config.ocspUrl,
    enableHSTS := config.hstsEnabled,
    hstsMaxAge := config.hstsMaxAge,
    sessionTicketsEnabled := config.sessionTicketsEnabled,
    clientCertsRequired := config.clientCertsRequired,
    clientCertCA := loadCA config.clientCertCaFile
  }

  -- Criar servidor com configuração TLS avançada
  let server ← createHTTPSServerWithTLS config.host config.port tlsConfig

  -- Middleware de segurança adicional
  let server ← server.addSecurityMiddleware [
    ("Content-Security-Policy", "default-src 'self'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin")
  ]

  server.run
```

### Teste de Segurança
```bash
# Testar configuração TLS
openssl s_client -connect localhost:8443 -tls1_3 -servername localhost

# Verificar cipher suites
openssl ciphers -v | grep TLS

# Teste de vulnerabilidades
sslscan --tls-all localhost:8443

# Teste SSL Labs
# https://www.ssllabs.com/ssltest/analyze.html?d=localhost
```

## 🏃‍♂️ Executando os Exemplos

### Pré-requisitos Gerais
```bash
# Instalar Lean 4
elan install leanprover/lean4:4.27.0

# Clonar repositório
git clone https://github.com/seu-usuario/leanserver.git
cd leanserver

# Compilar base
lake build
```

### Para Cada Exemplo
```bash
# Entrar no diretório do exemplo
cd examples/basic-server

# Gerar certificados (se necessário)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"

# Compilar
lake build

# Executar
./build/bin/example

# Testar em outro terminal
curl -k https://localhost:8443/health
```

## 📖 Próximos Passos

- Explore os códigos fonte em cada exemplo
- Modifique os handlers para suas necessidades
- Adicione autenticação e autorização
- Implemente cache e otimização
- Configure CI/CD para deployment

Para documentação completa da API, consulte `docs/API.md`.