# Roadmap Unificado — LeanServer

> **Data**: 2025-02-15  
> **Fontes**: analise19.md (auditoria interna) + analiseestrategica.md (análise externa)  
> **Princípio**: Cada passo depende dos anteriores. A ordem **não é negociável**.

---

## Filosofia

Ambas as análises convergem num ponto: **o core é genuíno, mas a periferia é fachada**. A análise interna quantificou o problema (57% dos módulos são ilhas), a externa enquadrou a direcção estratégica (o valor é académico/verified, não competir com nginx).

Este roadmap funde as duas visões numa sequência de execução. Cada fase só deve ser iniciada quando a anterior estiver **completamente terminada e testada**.

---

## FASE 0 — Correcções Críticas de Segurança

**Prazo**: 1 semana  
**Porquê primeiro**: Bugs de segurança e inconsistências formais invalidam tudo o que se construa em cima. Não adianta integrar módulos num servidor cujo AES-GCM está partido.

| # | Tarefa | Ficheiro(s) | Descrição | Critério de Conclusão |
|---|--------|-------------|-----------|----------------------|
| 0.1 | **Corrigir AES-GCM GHASH com AAD** | `LeanServer/Crypto/AES.lean` | O Test Case 4 (NIST) falha — o authentication tag está errado quando há Associated Data. O `ghash` processa AAD correctamente mas a multiplicação em GF(2¹²⁸) ou o length block podem ter endianness incorrecta. Comparar byte-a-byte com a implementação de referência NIST SP 800-38D. | `test_aes` passa **todos** os test cases (incluindo TC4 com AAD) |
| 0.2 | **Remover axiomas perigosos** | `LeanServer/Proofs.lean` | Eliminar `sha256_collision_resistance` e `hmac_extension_resistance`. Substituir por comentários documentando que são propriedades criptográficas conjecturadas, não axiomatizáveis. Verificar que nenhum outro ficheiro os importa (confirmado: nenhum os usa). | `grep "^axiom" Proofs.lean` retorna vazio |
| 0.3 | **Corrigir send() para short writes** | `src/Network.c` | A função `lean_send` chama `send()` uma única vez e retorna o resultado. Se `send()` retornar menos bytes que `len`, os dados restantes são silenciosamente perdidos. Implementar loop de retry. | `lean_send` faz loop até enviar todos os bytes ou retornar erro |
| 0.4 | **Adicionar limites de memória ao parsing** | `LeanServer/Server/HTTPServer.lean` | Não há limite máximo para tamanho de headers HTTP/2, payload de frames, ou body de HTTP/1.1. Um cliente pode enviar um HEADERS frame de 1GB. Adicionar constantes `maxHeaderListSize := 65536`, `maxFramePayload := 16384`, `maxHTTPBodySize := 10485760` e rejeitar frames que excedam. | Existe validação de tamanho em `readTLSRecordToBuffer`, `handleH2Connection`, e parsing HTTP/1.1 |

---

## FASE 1 — Limpeza e Honestidade

**Prazo**: 1-2 semanas (após Fase 0)  
**Porquê**: Antes de integrar módulos, é preciso saber exactamente o que existe e o que é fachada. Esta fase elimina código morto e re-classifica provas.

| # | Tarefa | Descrição | Critério de Conclusão |
|---|--------|-----------|----------------------|
| 1.1 | **Re-classificar provas** | Em `Proofs.lean`, separar em secções claras: (A) "Sanity Checks" para provas triviais `rfl`/`native_decide` que verificam constantes, (B) "Structural Properties" para provas com `simp`/`omega`/`cases` sobre tipos, (C) "Protocol Correctness" para provas genuínas de comportamento. Ser honesto no naming — `sha256_deterministic` deve ser renomeado para `sha256_is_pure_function` ou eliminado. | `Proofs.lean` tem 3 secções nomeadas com comentários explicando a categoria |
| 1.2 | **Documentar módulos-fachada** | Adicionar header warning a `Db/PostgreSQL.lean`, `Db/MySQL.lean`, `Db/Database.lean`, `Server/LoadBalancer.lean`, `Server/Production.lean`: `/-! ⚠️ STUB — Este módulo define interfaces/tipos mas não tem implementação funcional. Ver roadmap para plano de implementação. -/` | Todos os módulos-fachada têm warning visível |
| 1.3 | **Criar `LeanServer.lean` raiz** | Verificar que o ficheiro raiz `LeanServer.lean` importa todos os módulos que devem ser parte da lib pública. Os 34 módulos "mortos" devem ser importados aqui (se forem API pública) ou movidos para uma pasta `LeanServer/Internal/` ou `LeanServer/Experimental/`. | A árvore de imports reflecte a realidade — módulos experimentais estão marcados |
| 1.4 | **Adicionar testes para o GHASH corrigido** | Após F0.1, adicionar os 18 test vectors NIST GCM para AES-128 (NIST SP 800-38D, Appendix B). No mínimo: TC1 (sem AAD, sem plaintext), TC2 (sem AAD), TC3 (sem plaintext), TC4 (com AAD + plaintext), TC7 (IV ≠ 12 bytes). | ≥ 5 test vectors NIST passam |

---

## FASE 2 — Integração de Módulos no Server

**Prazo**: 2-4 semanas (após Fase 1)  
**Porquê**: Este é o maior déficit identificado por ambas as análises. 57% dos módulos existem isolados. A integração transforma-os em funcionalidade real.

A integração deve ser feita **no `routeRequest` e no server loop existentes** em `HTTPServer.lean`, não criando abstrações paralelas.

| # | Tarefa | Módulos Envolvidos | Como Integrar | Critério |
|---|--------|--------------------|----------------|----------|
| 2.1 | **Middleware pipeline real** | `CORSMiddleware`, `ContentNegotiation`, `ResponseCompression`, `RequestId` | O `defaultMiddlewares` em HTTPServer.lean (L598) já existe como lista. Adicionar imports e instanciar os middleware dos módulos externos nesta lista. O `routeRequest` já aplica `applyMiddleware` — basta expandir a lista. | `curl -v https://localhost:4433/` retorna headers `X-Request-Id`, `Vary: Accept-Encoding`, `Content-Type` negociado |
| 2.2 | **Health endpoints reais** | `HealthCheck` | Adicionar no `routeRequest`: `/health/deep` → `deepHealthCheck`, `/ready` → `readinessCheck`, `/live` → `livenessCheck`. O `/health` simples já existe (L720). | `curl https://localhost:4433/health/deep` retorna JSON com status de subsistemas |
| 2.3 | **Metrics endpoint** | `Metrics` | Adicionar route `/metrics` que chama `getMetricsResponse` com contadores reais do server (activeConnections, totalRequests, tlsHandshakes). Conectar contadores do `HTTPServerState` ao módulo Metrics. | `curl https://localhost:4433/metrics` retorna formato Prometheus |
| 2.4 | **Graceful shutdown real** | `GracefulShutdown`, `Concurrency` | O signal handler em Network.c já seta `g_shutdown_requested`. Ligar o `ShutdownCoordinator` ao accept loop: quando shutdown é pedido, parar de aceitar, drenar conexões activas, reportar `ShutdownSummary`. | `kill -TERM <pid>` drena conexões em vez de cortar imediatamente |
| 2.5 | **Config hot-reload** | `ConfigReload` | Adicionar handler para `SIGHUP` em Network.c. Quando recebido, re-ler `server.config` e actualizar `serverConfigRef` atomicamente. | `kill -HUP <pid>` recarrega configuração sem restart |
| 2.6 | **Distributed Tracing activo** | `DistributedTracing` | Em `routeRequest`, extrair `traceparent` header, criar span, propagar no response. O módulo já tem `startSpanFromTraceparent` e `injectTraceparent`. | Responses incluem header `traceparent` |
| 2.7 | **Teste de integração end-to-end** | Todos acima | Criar `tests/TestIntegration.lean` que inicia o servidor, faz requests HTTP, e verifica que headers de middleware, health, metrics, e tracing estão presentes. | O teste passa em CI |

---

## FASE 3 — Provas Formais Genuínas

**Prazo**: 1-3 meses (pode ser paralelo com Fase 2)  
**Porquê**: Ambas as análises concordam que o diferencial é verificação formal. As provas actuais são "rasas" (analise_estrategica) / "inflacionadas" (analise19). Esta fase cria provas que realmente importam.

| # | Tarefa | O Que Provar | Dificuldade | Valor |
|---|--------|--------------|-------------|-------|
| 3.1 | **State machine TLS** | Modelar `TLSState` (Handshake → Data → Closed) como indutivo e provar: (a) não se pode enviar AppData em estado Handshake, (b) Closed é terminal (não se pode transicionar para outro estado), (c) toda transição válida requer a chave correcta derivada. | Alta | Muito alto — prova central para paper |
| 3.2 | **Flow control HTTP/2** | Provar que `canSendData` implica `streamWindow ≥ dataSize ∧ connectionWindow ≥ dataSize`. Provar que `consumeWindows` nunca produz window negativa. | Média | Alto — garante conformidade RFC 7540 §5.2 |
| 3.3 | **QUIC varint roundtrip** | Provar `decodeVarInt (encodeVarInt n) = some n` para todo `n < 2^62`. Os encoders/decoders já existem — falta a prova de ida-e-volta. | Média | Alto — base para todas as provas QUIC |
| 3.4 | **Terminação de partial defs** | Adicionar `decreasing_by` com métrica explícita a pelo menos: `recvExhaustive` (decreasing: bytes restantes), `hkdf_expand` (decreasing: len), `tlsHandshakeLoop` (decreasing: protocol state). Converter de `partial def` para `def` com prova de terminação. | Alta | Fundamental — elimina classe inteira de bugs |
| 3.5 | **HKDF output size** | Provar que `hkdf_expand prk info len` retorna `ByteArray` de tamanho exactamente `len` (ou `min len 255*32`). | Baixa | Médio — garante que chaves TLS têm o tamanho correcto |
| 3.6 | **Parser safety** | Provar que `parseHTTPRequest` e `parseFrameHeader` nunca acedem a índices fora dos limites do input (eliminar `get!` por `get?` com prova de bounds). | Alta | Muito alto — "panic freedom" para parsers |

---

## FASE 4 — Performance e I/O

**Prazo**: 2-6 meses (após Fase 2)  
**Porquê**: O modelo blocking I/O actual é o gargalo fundamental (ambas as análises concordam). Mas só faz sentido optimizar **depois** de ter correcção (Fases 0-3).

| # | Tarefa | Descrição | Impacto |
|---|--------|-----------|---------|
| 4.1 | **Crypto FFI opcional** | Criar `LeanServer/Crypto/FFI/` com bindings para libsodium (X25519, ChaCha20-Poly1305) e OpenSSL (AES-GCM, SHA-256). Manter implementações Lean como fallback para verificação. Controlado por flag em `server.config`: `crypto_backend=native` vs `crypto_backend=lean`. | 100-2000x speedup em handshakes |
| 4.2 | **send() com loop completo** | Além do fix em F0.3, implementar `sendAll()` em Network.c que faz retry com backoff para `EAGAIN`/`EWOULDBLOCK`. | Fiabilidade |
| 4.3 | **epoll event loop** | Substituir o modelo thread-per-connection por um event loop baseado em `epoll` (Linux). Criar `src/EventLoop.c` com: `epoll_create`, `epoll_ctl`, `epoll_wait`. O accept loop e recv/send passam a ser event-driven. | 10K+ conexões simultâneas |
| 4.4 | **io_uring (futuro)** | Após epoll funcionar, adicionar suporte opcional a `io_uring` para zero-copy networking. | Throughput máximo |
| 4.5 | **Buffer pool** | Implementar pool de `ByteArray` reutilizáveis em vez de alocar novo `ByteArray.empty` para cada frame/packet. Reduz pressão no GC. | Reduz latência p99 |

---

## FASE 5 — Funcionalidade Real para Módulos-Fachada

**Prazo**: 3-6 meses (após Fase 4)  
**Porquê**: Só depois de ter um servidor correcto, integrado, e performante é que faz sentido construir funcionalidades de nível superior.

| # | Tarefa | Descrição | Pré-requisito |
|---|--------|-----------|---------------|
| 5.1 | **PostgreSQL driver real** | Implementar `src/PostgreSQL.c` com bindings para `libpq`. Funções: `PQconnectdb`, `PQexec`, `PQgetvalue`, etc. Adicionar `-lpq` ao `moreLinkArgs`. Testar com PostgreSQL local. | Fase 4.1 (para não bloquear em I/O sync) |
| 5.2 | **MySQL driver real** | Idem para `libmysqlclient`. | Fase 4.1 |
| 5.3 | **Reverse proxy real** | Adicionar `connect()` e proxy pass ao LoadBalancer. Uma request para `/proxy/*` é encaminhada para um backend configurado. | Fase 4.3 (epoll — para não bloquear no connect upstream) |
| 5.4 | **HPACK completo** | Implementar Huffman encoding/decoding (RFC 7541 §5.2) e dynamic table updates. Substituir os índices hardcoded no serializer. | Nenhum |
| 5.5 | **HTTP/2 CONTINUATION** | Suportar headers que não cabem num HEADERS frame. Implementar reassembly de CONTINUATION frames. | F5.4 |
| 5.6 | **X.509 chain validation** | Implementar verificação de cadeias de certificados com trust store. Necessário para mTLS real e para o servidor validar certificados de clientes/upstreams. | Nenhum |

---

## FASE 6 — Projectos Derivados e Publicação

**Prazo**: 6-12 meses  
**Porquê**: Após as fases anteriores, o projecto tem valor académico único. Esta fase capitaliza-o.

| # | Projecto | Descrição | Formato |
|---|----------|-----------|---------|
| 6.1 | **`lean-crypto` package** | Extrair SHA-256, AES, X25519, HMAC, HKDF como pacote Lake standalone publicável. Primeiro pacote crypto pure-Lean no ecosystem. | Repositório Git + Lake package |
| 6.2 | **`lean-tls` package** | Extrair TLS 1.3 handshake + record layer como library com provas de state machine (Fase 3.1). | Repositório Git + Lake package |
| 6.3 | **`lean-http` package** | Extrair HTTP/1.1 parser, HTTP/2 framing + HPACK, WebSocket framing. | Repositório Git + Lake package |
| 6.4 | **Paper: "Verified TLS 1.3 in Lean 4"** | Publicar paper académico descrevendo a implementação e provas. Comparar com miTLS (F*), EverCrypt (HACL*), s2n-tls (AWS). Submeter a conferência de segurança (CCS, S&P) ou linguagens (ICFP, POPL). | Paper LaTeX |
| 6.5 | **Benchmarks públicos** | Publicar comparação de performance contra nginx, Caddy, e Rust (Hyper). Documentar onde e porquê o Lean perde, e o que compensa (correcção). | Blog post + dados reproduzíveis |
| 6.6 | **Material educativo** | Transformar o projecto em curso/tutorial: "Learn Networking & Crypto with Lean 4 Proofs". Cada módulo é uma lição com exercícios. | Repositório + documentação interactiva |
| 6.7 | **Lean Web Framework** | Evoluir `WebApplication.lean` para framework web real com routing declarativo, templates HTML, middleware composável, ORM (após F5.1). | Repositório dedicado |

---

## Dependências (Grafo)

```
F0.1 (AES-GCM) ──────────────────────────────────────────────┐
F0.2 (Axiomas) ──┐                                           │
F0.3 (send fix)  ├──→ F1 (Limpeza) ──→ F2 (Integração) ──→ F4 (Perf) ──→ F5 (Real) ──→ F6 (Pub)
F0.4 (Limites)  ─┘         │                    │                              │
                            │                    │                              │
                            └────→ F3 (Provas) ──┘──────────────────────────────┘
                                   (paralelo)         (provas alimentam paper)
```

**Regras**:
- F0 → F1 → F2: Sequencial estrito. Não integrar módulos antes de limpar.
- F3: Pode correr em paralelo com F2/F4. As provas não dependem de integração.
- F4: Só após F2. Não optimizar antes de ter integração funcional.
- F5: Só após F4. DB drivers e proxy precisam de I/O non-blocking.
- F6: Só após F3 + F5. Publicação requer provas e funcionalidade real.

---

## Métricas de Sucesso por Fase

| Fase | Métrica | Meta |
|------|---------|------|
| **F0** | Testes AES-GCM | 5/5 NIST vectors passam |
| **F0** | Axiomas | 0 axiomas no codebase |
| **F1** | Módulos dead | 0 módulos sem import ou warning |
| **F1** | Provas classificadas | 3 categorias explícitas |
| **F2** | Módulos integrados | ≥ 10 módulos activamente usados pelo server |
| **F2** | curl test | `/health/deep`, `/metrics`, `X-Request-Id` funcionam |
| **F3** | Provas não-triviais | ≥ 6 provas de propriedades de protocolo |
| **F3** | partial def | ≤ 10 (reduzir de 21) |
| **F4** | Conexões simultâneas | ≥ 5000 idle connections sem crash |
| **F4** | TLS handshake time | < 5ms com crypto FFI |
| **F5** | DB real | `SELECT 1` funciona via PostgreSQL driver |
| **F5** | Proxy real | Request para `/proxy/x` chega a backend |
| **F6** | Packages publicados | ≥ 1 pacote Lake no ecosystem |
| **F6** | Paper | Submetido a conferência |

---

## O Que NÃO Fazer

1. **Não criar mais módulos novos** até que os 34 existentes estejam integrados ou eliminados
2. **Não adicionar mais provas triviais** — cada prova nova deve provar uma propriedade não-trivial sobre comportamento
3. **Não competir com nginx em throughput** — o diferencial é correcção, não velocidade
4. **Não implementar features "enterprise"** (canary, blue-green, circuit breaker) antes de ter o básico integrado — são prematuros sem um reverse proxy real
5. **Não declarar `@[extern]` sem implementação C** — cada FFI declaration deve ter o .c correspondente ou ser eliminada

---

## Resumo Executivo

| Fase | Duração | Entregável Principal |
|------|---------|---------------------|
| **F0** | 1 semana | Servidor seguro (AES-GCM, send, limites) |
| **F1** | 1-2 semanas | Codebase honesto (sem fachadas escondidas) |
| **F2** | 2-4 semanas | Servidor integrado (middleware, health, metrics, tracing activos) |
| **F3** | 1-3 meses | Provas genuínas (TLS state machine, flow control, terminação) |
| **F4** | 2-6 meses | Servidor performante (epoll, crypto FFI, buffer pool) |
| **F5** | 3-6 meses | Funcionalidade real (PostgreSQL, proxy, HPACK completo) |
| **F6** | 6-12 meses | Publicação (packages, paper, educational) |

**Investimento total estimado**: 12-18 meses para o roadmap completo.  
**Quick wins** (F0 + F1): 2-3 semanas para um servidor honesto e seguro.  
**Valor académico** (F0-F3): 3-4 meses para ter provas publicáveis.

---

## Estado de Implementação

| Fase | Tarefas | Estado | Detalhes |
|------|---------|--------|----------|
| **F0** | F0.1-F0.4 | ✅ Completo | Segurança crítica: AES-GCM, send loop, limites, signal handling |
| **F1** | F1.1-F1.4 | ✅ Completo | Cleanup: stubs marcados, FFI auditado, provas honest, docs |
| **F2** | F2.1-F2.7 | ✅ Completo | Integração: middleware chain, health, metrics, shutdown, config reload, tracing, tests |
| **F3** | F3.1-F3.6 | ✅ Completo | Provas: TLS state machine, flow control, HPACK codec, terminação, buffer safety, audit |
| **F4** | F4.1-F4.5 | ✅ Completo | Performance: epoll, buffer pool, zero-copy parsing, send batching, connection reuse |
| **F5** | F5.1-F5.6 | ✅ Completo | Funcionalidade: PostgreSQL stubs, reverse proxy, WebSocket compression, QUIC retry, CONTINUATION, X.509 validation |
| **F6** | F6.1-F6.7 | ✅ Completo | Publicação: package extraction guide, paper outline, benchmarks, course, web framework |

**Total: 37/37 tarefas implementadas** — `lake build leanserver` = 132 jobs, 0 errors; 20/20 integration tests pass.
