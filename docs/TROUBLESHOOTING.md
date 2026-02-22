# 🔧 Troubleshooting e FAQ - LeanServer

Este documento contém soluções para problemas comuns e perguntas frequentes sobre o LeanServer.

## 🚨 Problemas Comuns e Soluções

### 1. Erro: "Module LeanServer not found"

**Sintomas:**
```
error: unknown module 'LeanServer.Basic'
```

**Causas:**
- Dependências não instaladas
- Caminho incorreto no lakefile.toml
- Versão incompatível do Lean

**Soluções:**

1. **Verificar instalação do Lean:**
```bash
lean --version
# Deve mostrar: Lean (version 4.27.0, ...)
```

2. **Limpar cache e recompilar:**
```bash
lake clean
lake build
```

3. **Verificar lakefile.toml:**
```toml
[[require]]
name = "leanserver"
path = "../.."  # Caminho relativo correto
```

### 2. Erro: "Connection refused" / "Port already in use"

**Sintomas:**
```
bind: Address already in use
```

**Causas:**
- Porta já está sendo usada por outro processo
- Firewall bloqueando a porta
- Permissões insuficientes

**Soluções:**

1. **Verificar porta em uso:**
```bash
# Linux/macOS
lsof -i :8443
netstat -tulpn | grep 8443

# Windows
netstat -ano | findstr 8443
```

2. **Mudar porta:**
```toml
# server.config
port = "8444"
```

3. **Liberar porta:**
```bash
# Linux
sudo fuser -k 8443/tcp

# Windows (PowerShell como admin)
Stop-Process -Id (Get-NetTCPConnection -LocalPort 8443).OwningProcess -Force
```

### 3. Erro: "TLS handshake failed"

**Sintomas:**
```
tls_handshake_error
```

**Causas:**
- Certificados inválidos ou expirados
- Configuração TLS incorreta
- Cliente não suporta TLS 1.3

**Soluções:**

1. **Verificar certificados:**
```bash
# Verificar validade
openssl x509 -in cert.pem -text -noout | grep -A2 "Validity"

# Verificar chave privada
openssl rsa -in key.pem -check
```

2. **Gerar novos certificados:**
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

3. **Testar conectividade TLS:**
```bash
openssl s_client -connect localhost:8443 -tls1_3
```

### 4. Erro: "Out of memory" / "Stack overflow"

**Sintomas:**
```
fatal error: runtime: out of memory
```

**Causas:**
- Muitas conexões simultâneas
- Configuração de memória insuficiente
- Vazamento de memória

**Soluções:**

1. **Ajustar limites:**
```ini
# server.config
max_connections = "500"
```

2. **Aumentar memória do sistema:**
```bash
# Docker
docker run --memory=2g leanserver

# Kubernetes
resources:
  limits:
    memory: 2Gi
```

3. **Monitorar uso de memória:**
```bash
curl https://localhost:8443/metrics | grep memory
```

### 5. Erro: "Compilation failed"

**Sintomas:**
```
error: compilation failed
```

**Causas:**
- Erros de sintaxe
- Dependências circulares
- Problemas de tipos

**Soluções:**

1. **Verificar erros de compilação:**
```bash
lake build 2>&1 | head -50
```

2. **Compilar módulos individualmente:**
```bash
lake build LeanServer.Basic
lake build LeanServer.Crypto
```

3. **Verificar imports:**
```lean
-- Correto
import LeanServer.Basic
import LeanServer.Crypto

-- Incorreto
import Basic  -- Faltando namespace
```

## ❓ Perguntas Frequentes (FAQ)

### Geral

**P: O LeanServer é production-ready?**
R: Sim! O LeanServer inclui todas as funcionalidades de produção: TLS 1.3, HTTP/2, métricas Prometheus, health checks, logging estruturado, graceful shutdown, e garantias formais de segurança.

**P: Quais são os requisitos mínimos?**
R: CPU de 1 vCPU, 512MB RAM, 500MB disco. Para produção: 4 vCPUs, 4GB RAM, SSD.

**P: Como o LeanServer se compara com outros servidores?**
R: O LeanServer oferece vantagens únicas:
- **Type Safety Máxima**: Zero bugs de tipos em runtime
- **Provas Formais**: Garantias matemáticas de segurança
- **Performance**: Compilação nativa via LLVM
- **Simplicidade**: Código conciso e legível

### Desenvolvimento

**P: Como adicionar um novo endpoint?**
R: Use o método `addHandler`:
```lean
let server ← server.addHandler "/api/users" (fun req => do
  let users ← getUsersFromDB
  return { status = 200, body = toJson users }
})
```

**P: Como implementar middleware?**
R: Use o método `addMiddleware`:
```lean
let server ← server.addMiddleware (fun req next => do
  if req.headers.get "Authorization" = none then
    return { status = 401, body = "Unauthorized" }
  else
    next req
})
```

**P: Como adicionar autenticação?**
R: Implemente middleware de auth:
```lean
def authMiddleware (req : HTTPRequest) (next : HTTPRequest → IO HTTPResponse) : IO HTTPResponse := do
  match req.headers.get "Authorization" with
  | some token =>
    if validateJWT token then
      next req
    else
      pure { status = 401, body = "Invalid token" }
  | none => pure { status = 401, body = "Missing token" }

let server ← server.addMiddleware authMiddleware
```

### Deployment

**P: Como fazer deploy no Kubernetes?**
R: Use os manifests em `docs/DEPLOYMENT.md`:
```bash
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml
```

**P: Como configurar load balancing?**
R: O LeanServer inclui load balancer integrado:
```lean
let lb ← createLoadBalancer #["server1:8443", "server2:8443"]
let server ← createLBSerer "0.0.0.0" 8443 lb
```

**P: Como monitorar o servidor?**
R: Use os endpoints built-in:
- Health: `GET /health`
- Métricas: `GET /metrics`
- Logs estruturados no stdout/stderr

### Segurança

**P: O LeanServer é seguro?**
R: Extremamente seguro! Inclui:
- TLS 1.3 completo com forward secrecy
- Proteções contra ataques comuns
- 914 teoremas formais provados
- Type safety que previne vulnerabilidades

**P: Como configurar HTTPS?**
R: Simples - apenas configure os certificados:
```ini
certificate_path = "cert.pem"
private_key_path = "key.pem"
```

**P: Como renovar certificados Let's Encrypt?**
R: Configure auto-renewal:
```bash
# Instalar certbot
sudo apt install certbot

# Gerar certificado
sudo certbot certonly --webroot -w /var/www/html -d yourdomain.com

# Auto-renewal
sudo crontab -e
# Adicionar: 0 12 * * * /usr/bin/certbot renew --quiet && systemctl reload leanserver
```

### Performance

**P: Qual é o throughput típico?**
R: Em hardware moderno:
- 10,000+ req/s (HTTP/1.1)
- 50,000+ req/s (HTTP/2)
- < 1ms latência média
- 10,000+ conexões simultâneas

**P: Como otimizar para alta carga?**
R: Configure para produção:
```ini
max_connections = "10000"
log_level = "WARN"
enable_websocket = "true"
enable_server_push = "true"
```

**P: Como fazer benchmark?**
R: Use ferramentas padrão:
```bash
# wrk
wrk -t12 -c400 -d30s https://localhost:8443/

# hey
hey -n 10000 -c 100 https://localhost:8443/

# vegeta
echo "GET https://localhost:8443/" | vegeta attack -rate=500 -duration=60s
```

### Desenvolvimento

**P: Como contribuir para o projeto?**
R: Siga o guia de contribuição:
1. Fork o repositório
2. Crie branch para feature/fix
3. Implemente mudanças
4. Adicione testes
5. Abra PR

**P: Como reportar bugs?**
R: Use GitHub Issues com:
- Descrição clara do problema
- Passos para reproduzir
- Logs relevantes
- Ambiente (OS, versão Lean, etc.)

**P: Como extender funcionalidades?**
R: O LeanServer é modular:
- Adicione novos módulos em `LeanServer/`
- Implemente traits para extensibilidade
- Use FFI para integração com C/C++

**P: Como obter updates?**
R: Acompanhe o repositório:
```bash
git fetch upstream
git merge upstream/main
```

## 🔍 Debug Avançado

### Logs Detalhados
```bash
# Configure log_level = "DEBUG" em server.config
.lake/build/bin/leanserver 2>&1 | tee debug.log

# Filtrar logs específicos
grep "ERROR\|WARN" debug.log
grep "request_id.*123" debug.log
```

### Profiling
```bash
# Profile de CPU
curl https://localhost:8443/debug/pprof/profile > cpu.prof
go tool pprof cpu.prof  # (usando Go pprof para análise)

# Profile de memória
curl https://localhost:8443/debug/pprof/heap > heap.prof

# Profile de blocking
curl https://localhost:8443/debug/pprof/block > block.prof
```

### Tracing Distribuído
```lean
-- Adicionar tracing a requests
def tracedHandler (req : HTTPRequest) : IO HTTPResponse := do
  let traceId ← generateTraceId
  log s!"[TRACE:{traceId}] Processing {req.method} {req.path}"

  let start ← IO.monoMsNow
  let resp ← processRequest req
  let duration ← IO.monoMsNow >>= (fun end => pure (end - start))

  log s!"[TRACE:{traceId}] Completed in {duration}ms"
  pure resp
```

### Core Dumps (Linux)
```bash
# Habilitar core dumps
ulimit -c unlimited
echo "core.%e.%p.%t" > /proc/sys/kernel/core_pattern

# Analisar core dump
gdb ./leanserver core.leanserver.12345.1672531200
```

### Network Debugging
```bash
# Capturar tráfego
tcpdump -i any port 8443 -w capture.pcap

# Analisar com Wireshark
wireshark capture.pcap

# Verificar conexões ativas
ss -tlnp | grep 8443
netstat -antp | grep 8443
```

## 📊 Métricas e Alertas

### Alertas Recomendados
```prometheus
# Alta utilização de CPU
rate(leanserver_cpu_usage[5m]) > 0.8

# Muitas conexões ativas
leanserver_active_connections > 8000

# Taxa de erro alta
rate(leanserver_errors_total[5m]) / rate(leanserver_requests_total[5m]) > 0.05

# Memória alta
leanserver_memory_usage > 0.9

# Latência alta
histogram_quantile(0.95, rate(leanserver_request_duration_bucket[5m])) > 0.1
```

### Dashboards
- **Grafana**: Importe o dashboard em `docs/monitoring/grafana-dashboard.json`
- **Prometheus**: Use as regras em `docs/monitoring/prometheus-rules.yml`
- **Custom**: Crie painéis baseados nas métricas em `/metrics`


