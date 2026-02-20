# Fuzzing de Parsers — LeanServer

Harnesses de fuzzing para testar os parsers de protocolos com input aleatório/malformado.

## Objectivo

Encontrar crashes, panics, ou comportamento indefinido nos parsers de:
- **TLS 1.3** — `parseTLSRecord`, `parseServerHello`, `parseClientHello`
- **HTTP/2** — `parseFrameHeader`, `parseHPACK`
- **QUIC** — `decodeVarInt`, `parseQUICLongHeader`, `parseQUICShortHeader`
- **WebSocket** — `parseWebSocketFrame`

## Arquitectura

Cada harness gera N iterações de input aleatório (ByteArray com bytes aleatórios)
e alimenta os parsers. Nenhum crash deve ocorrer — os parsers devem retornar
`none` ou um resultado válido para qualquer input.

## Ficheiros

| Ficheiro | Parser testado |
|----------|---------------|
| `FuzzTLS.lean` | TLS record parsing, ClientHello, ServerHello |
| `FuzzHTTP2.lean` | HTTP/2 frame header, HPACK decoding |
| `FuzzQUIC.lean` | QUIC variable-length integer, packet headers |
| `FuzzWebSocket.lean` | WebSocket frame parsing |

## Como executar

```bash
# A partir da raiz do projecto
lake env lean fuzz/FuzzTLS.lean
lake env lean fuzz/FuzzHTTP2.lean
lake env lean fuzz/FuzzQUIC.lean
lake env lean fuzz/FuzzWebSocket.lean

# Ou todos de uma vez
bash fuzz/run_all.sh
```

## Integração com libFuzzer / AFL

Para fuzzing mais profundo via FFI, pode-se compilar os parsers como bibliotecas C
e usar libFuzzer:

```bash
# Compilar parser como shared lib
lake build LeanServer:shared

# Usar o .so com libFuzzer (requer clang)
# clang -fsanitize=fuzzer fuzz/fuzz_tls_harness.c -L.lake/build/lib -lLeanServer
```
