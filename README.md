# LeanServer — Servidor HTTPS Verificado em Lean 4

Um servidor HTTPS completo implementado em **Lean 4**, com TLS 1.3, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC, e **935 teoremas formais** verificados pelo compilador — zero `sorry`. A especificação formal É o código executável: sem extracção, sem spec-impl gap.

## Números do Projeto

| Métrica | Valor |
|---|---|
| Linhas de Lean | ~32 000 |
| Módulos Lean | 81 |
| Linhas de C (FFI) | ~1 000 |
| **Teoremas formais** | **935** |
| **`sorry` (provas incompletas)** | **0** |
| `partial def` | 4 (apenas event loops genuínos) |
| Testes executáveis | 137 (41 diff + 51 H2 + 45 TLS e2e) |
| Lean 4 | v4.27.0 |

## Diferenciadores

1. **Spec = Implementação** — Em Lean 4 a especificação formal é directamente executável. Sem KaRaMeL, sem extracção, sem spec-impl mismatch.
2. **3-layer refinement chain** — TLSSpec → TLSModel → ServerStep com provas mecânicas de simulação.
3. **`native_decide`** — Verificação por força bruta de propriedades finitas (S-Box bijectivity, RFC test vectors).
4. **Uma linguagem para tudo** — Servidor, testes, fuzzers, provas — tudo Lean 4.
5. **Primeiro QUIC funcional puro com provas** — Não existe outro QUIC verificado em linguagem funcional pura.

## Funcionalidades

### Protocolos

- **TLS 1.3** — Handshake completo, X25519 key exchange, AES-128-GCM, SHA-256, HKDF, session tickets, 0-RTT, KeyUpdate
- **HTTP/2** — Multiplexação de streams, HPACK (com Huffman RFC 7541), Server Push, flow control adaptativo
- **HTTP/3** — Frames SETTINGS/HEADERS/DATA/GOAWAY, codificação QUIC VarInt, integração com QUIC
- **QUIC** — Initial/Handshake/1-RTT packets, ACK frames, congestion control (NewReno), connection migration
- **WebSocket** — Upgrade over HTTP/2 (RFC 8441), frames de texto/binário/ping/pong/close
- **gRPC** — Service registry, request/response sobre HTTP/2, serialização protobuf simplificada

### Criptografia (Lean puro)

| Algoritmo | Módulo | Notas |
|---|---|---|
| SHA-256 | `Crypto/Crypto.lean` | Implementação completa RFC 6234 |
| HMAC-SHA256 | `Crypto/Crypto.lean` | RFC 2104 |
| HKDF | `Crypto/Crypto.lean` | Extract + Expand (RFC 5869) |
| AES-128-GCM | `Crypto/AES.lean` | Encrypt/decrypt com GHASH |
| X25519 | `Crypto/X25519.lean` | Diffie-Hellman sobre Curve25519 |
| RSA-PSS | `Crypto/RSA.lean` | Assinatura com MGF1-SHA256 |
| Base64 | `Core/Base64.lean` | Encode/decode RFC 4648 |
| HPACK Huffman | `Protocol/HPACK.lean` | Encode/decode RFC 7541 Appendix B |

### Provas Formais (935 teoremas, 0 sorry)

Os teoremas são verificados pelo compilador Lean — se compila, está correcto:

| Categoria | Teoremas | Exemplos |
|---|---|---|
| **Protocolo** | ~166 | TLS FSM, HTTP/2 stream SM, QUIC state, anti-downgrade, cert validation |
| **Codec roundtrip** | ~120 | HPACK integer, VarInt, frame headers, serialização, universal codec |
| **Safety** | ~110 | Bounds checking, overflow prevention, index safety, size preservation |
| **Criptografia** | ~100 | S-Box bijectivity, SHA-256 test vectors, nonce uniqueness, HMAC, constant-time |
| **Refinement** | ~50 | Spec↔impl linkage, simulation relations, serverStep chain |
| **Structural** | ~200 | Data structure shapes, definitional equalities, compositional properties |
| **Sanity** | ~189 | Constants validation, size checks, RFC test vectors via native_decide |

### Infraestrutura

- **Zero-copy parsing** — ByteSlice com provas de bounds safety
- **Configuração** — Ficheiro `server.config` estilo TOML, hot-reload
- **Logging estruturado** — Níveis ERROR, WARN, INFO, DEBUG com timestamps
- **Health checks** — Endpoint `/health` com uptime, conexões, requests
- **Métricas Prometheus** — Endpoint `/metrics` com contadores e gauges
- **Graceful shutdown** — Handlers de sinais POSIX, draining de conexões
- **Load balancer** — Round-robin ponderado, health checks de backends
- **Database** — Camada de abstração PostgreSQL/MySQL/SQLite com connection pooling
- **Web framework** — Routing, middleware, request context, response builders
- **Tracing distribuído** — W3C Trace Context, propagação de contexto

## Arquitetura

```
┌──────────────────────────────────────────────────────────┐
│                 VERIFICATION BOUNDARY                    │
│                                                          │
│  TLSSpec ──► TLSModel ──► TLSRefinement                  │
│  (130 thms)  (bidirectional)  (trace safety)             │
│         │                          │                     │
│         └──── serverStep ◄─────────┘                     │
│                   │                                      │
│  AES (S-Box bij.)  SHA-256 (structural)  HKDF (sizes)   │
│  HPACK (roundtrip) VarInt (universal RT) Nonce (unique)  │
│  CertValidation    ByteSlice (zero-copy) QUIC PN (mono) │
│                                                          │
├──────────────────── IO BOUNDARY ─────────────────────────┤
│                                                          │
│  HTTPServer.lean (17 theorems + try/finally safety)      │
│  Socket/Epoll/Signal @[extern] (syscalls)                │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### Camadas

| Camada | Módulos | LOC | Descrição |
|---|---|---|---|
| **Spec** | 11 | ~5 450 | TLS FSM formal, refinement, invariantes de protocolo, provas de composição |
| **Server** | 29 | ~11 800 | HTTPServer, middleware, load balancer, tracing, deployment |
| **Crypto** | 14 | ~5 100 | TLS 1.3, AES-GCM, X25519, SHA-256, HKDF, nonce management, cert validation |
| **Protocol** | 9 | ~5 000 | HTTP/2, HTTP/3, QUIC, HPACK, WebSocket, gRPC |
| **Core** | 8 | ~1 400 | ByteSlice, parsers, logging, error handling, buffer pool |
| **Web** | 5 | ~1 350 | Web framework, routing, templates |
| **Db** | 4 | ~1 150 | PostgreSQL, MySQL, SQLite abstraction |
| **Proofs** | 1 | ~1 650 | Provas consolidadas |

### FFI em C (4 ficheiros — ~1 000 linhas)

| Ficheiro | Linhas | Funções |
|---|---|---|
| `src/Network.c` | 430 | Socket POSIX: socket, bind, listen, accept, recv, send, epoll, signals |
| `src/crypto_ffi.c` | 365 | OpenSSL wrappers: certificados, hash, random + `secure_zero` (volatile loop) |
| `src/sqlite_ffi.c` | 162 | SQLite3 wrappers: open, exec, prepare, step, finalize |
| `src/db_stubs.c` | 50 | Stubs para PostgreSQL/MySQL (placeholder) |

Tudo o resto — TLS handshake, HTTP/2 framing, HPACK, QUIC, criptografia, parsing — é **Lean puro**.

## Quick Start

### 1. Instalar Lean 4

```bash
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh
elan install leanprover/lean4:v4.27.0
```

### 2. Compilar

```bash
git clone https://github.com/lean-server/LeanServer6.git
cd LeanServer6
lake build
```

### 3. Gerar Certificados

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

### 4. Executar

```bash
.lake/build/bin/leanserver
```

### 5. Testar

```bash
# Servidor
curl -k https://localhost:8443/
curl -k https://localhost:8443/health
curl -k https://localhost:8443/metrics

# Test suites
lake build test && .lake/build/bin/test
lake build differential_crypto && .lake/build/bin/differential_crypto
lake build http2_conformance && .lake/build/bin/http2_conformance
lake build tls_handshake_e2e && .lake/build/bin/tls_handshake_e2e
```

### 6. Reproduzir Artefactos

```bash
./reproduce.sh   # Build + all verification checks
```

## Usar como Biblioteca

O LeanServer expõe uma **biblioteca pura** (`LeanServerPure`) sem dependências C,
importável por qualquer projecto Lean 4 via Lake:

### 1. Adicionar dependência ao seu `lakefile.toml`

```toml
[[require]]
name = "LeanServer"
git = "https://github.com/<user>/LeanServer6"
rev = "main"
```

### 2. Importar módulos

```lean
-- Importar tudo (crypto + protocolos + provas)
import LeanServerPure

-- Ou importar módulos individuais
import LeanServer.Crypto.AES          -- AES-128/256-GCM
import LeanServer.Crypto.SHA256       -- SHA-256, HMAC, HKDF
import LeanServer.Crypto.X25519       -- Curve25519 key exchange
import LeanServer.Protocol.HTTP2      -- HTTP/2 framing
import LeanServer.Protocol.HPACK      -- HPACK compression
import LeanServer.Protocol.QUIC       -- QUIC protocol
import LeanServer.Proofs              -- 914 verified theorems
```

### Duas bibliotecas disponíveis

| Biblioteca | Descrição | C/FFI |
|---|---|---|
| `LeanServerPure` | Crypto, protocolos, provas (43 módulos) | **Zero** |
| `LeanServer` | Tudo incluindo servidor HTTP, DB, FFI (81 módulos) | Sim |

## Configuração

Editar `server.config`:

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

## Documentação

- [Instalação](docs/INSTALL.md)
- [Arquitectura](docs/ARCHITECTURE.md)
- [API Reference](docs/API.md)
- [API Completa (auto-gerada)](docs/API_GENERATED.md)
- [Guia de Provas](docs/PROOF_GUIDE.md)
- [Extracção de Pacotes](docs/PACKAGE_EXTRACTION.md)
- [Deployment](docs/DEPLOYMENT.md) — Docker, systemd
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Exemplos](examples/README.md)
- [Outline de Paper](docs/PAPER_OUTLINE.md)

## Aviso de Segurança

Este projeto é uma **demonstração técnica e de investigação**. A criptografia implementada em Lean puro não foi auditada por especialistas de segurança. Para produção:

- Use bibliotecas criptográficas auditadas (OpenSSL, BoringSSL, libsodium)
- Não confie na validação de certificados X.509 deste servidor
- Considere integração FFI com stacks TLS maduras

Ver [THREAT_MODEL.md](THREAT_MODEL.md) e [SECURITY.md](SECURITY.md) para detalhes.

## Licença

[Apache License 2.0](LICENSE)
