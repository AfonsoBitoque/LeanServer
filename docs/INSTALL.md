# 🚀 Guia de Instalação e Configuração - LeanServer

Este guia fornece instruções completas para instalar, configurar e executar o LeanServer em diferentes ambientes.

## 📋 Pré-requisitos

### Sistema Operacional
- **Windows 10/11** (recomendado para desenvolvimento)
- **Linux** (Ubuntu 20.04+, CentOS 8+)
- **macOS** (10.15+)

### Dependências
- **Lean 4** (versão 4.27.0 ou superior)
- **Lake** (build system do Lean)
- **OpenSSL** (para geração de certificados)
- **Git** (para controle de versão)

### Recursos de Sistema
- **RAM**: Mínimo 4GB, recomendado 8GB+
- **Disco**: 2GB de espaço livre
- **CPU**: Qualquer processador moderno (x86_64)

## 🛠️ Instalação

### 1. Instalar Lean 4

#### Windows (Recomendado)
```powershell
# Usando elan (recomendado)
curl -sSfL https://github.com/leanprover/elan/releases/latest/download/elan-x86_64-pc-windows-msvc.exe -o elan.exe
.\elan.exe --default-toolchain leanprover/lean4:4.27.0 --yes
```

#### Linux/macOS
```bash
# Instalar elan
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh

# Configurar toolchain
elan default leanprover/lean4:4.27.0
```

### 2. Clonar o Repositório
```bash
git clone https://github.com/seu-usuario/leanserver.git
cd leanserver
```

### 3. Verificar Instalação
```bash
# Verificar versão do Lean
lean --version
# Deve mostrar: Lean (version 4.27.0, ...)

# Verificar lake
lake --version
# Deve mostrar versão do lake
```

## ⚙️ Configuração

### Arquivo de Configuração Básico

Crie o arquivo `server.config`:

```ini
# Configuração básica do servidor
host = "0.0.0.0"
port = "8443"
max_connections = "1000"
log_level = "INFO"

# TLS
certificate_path = "cert.pem"
private_key_path = "key.pem"

# Funcionalidades
enable_websocket = "true"
enable_server_push = "true"

# Endpoints
health_check_path = "/health"
metrics_path = "/metrics"
```

### Geração de Certificados TLS

#### Usando OpenSSL (Recomendado)
```bash
# Gerar chave privada
openssl genrsa -out key.pem 2048

# Gerar certificado auto-assinado
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/C=BR/ST=SP/L=SaoPaulo/O=LeanServer/CN=localhost"
```

#### Usando o Próprio LeanServer (Futuro)
```bash
# Comando futuro para geração automática
lake run certgen --domain localhost --days 365
```

## 🏗️ Compilação

### Build Completo
```bash
# Compilar tudo
lake build

# Build específico do servidor
lake build LeanServer

# Build com testes
lake build test
```

### Build Otimizado para Produção
```bash
# Build completo (o Lake já aplica otimizações)
lake build

# O binário é gerado em .lake/build/bin/
ls .lake/build/bin/leanserver
```

## 🚀 Execução

### Servidor Básico
```bash
# Executar servidor HTTPS
.lake/build/bin/leanserver
```

### Modos de Execução

#### Modo Desenvolvimento
```bash
# Configure log_level = "DEBUG" em server.config
# e execute:
.lake/build/bin/leanserver
```

#### Modo Produção
```bash
# Configure server.config para produção e execute:
.lake/build/bin/leanserver
```

#### Modo Teste
```bash
# Compilar e executar testes
lake build test_integration
.lake/build/bin/test_integration

# Testes específicos
lake build testcrypto && .lake/build/bin/testcrypto
lake build testx25519 && .lake/build/bin/testx25519
lake build testaes && .lake/build/bin/testaes
```

## 🔧 Configuração Avançada

### Configuração de Performance

```ini
# server.config - Configuração de alta performance
max_connections = "10000"
log_level = "WARN"
enable_websocket = "true"
enable_server_push = "true"
```

### Configuração de Segurança

```ini
# server.config - Configuração segura
# O LeanServer usa TLS 1.3 por padrão com AES-128-GCM e AES-256-GCM
certificate_path = "/etc/leanserver/ssl/cert.pem"
private_key_path = "/etc/leanserver/ssl/key.pem"
max_connections = "1000"
```

### Configuração de Logging

```ini
# server.config - Logging detalhado
# Níveis disponíveis: FATAL, ERROR, WARN, INFO, DEBUG, TRACE
log_level = "DEBUG"
```

## 🌐 Configuração de Rede

### Firewall (Windows)
```powershell
# Abrir porta 8443
New-NetFirewallRule -DisplayName "LeanServer HTTPS" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
```

### Firewall (Linux)
```bash
# Ubuntu/Debian
sudo ufw allow 8443

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

### Load Balancer (nginx)
```nginx
upstream leanserver_backend {
    server 127.0.0.1:8443;
    server 127.0.0.1:8444 backup;
}

server {
    listen 443 ssl;
    server_name yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass https://leanserver_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 🔍 Verificação da Instalação

### Teste Básico
```bash
# Verificar se o servidor está rodando
curl -k https://localhost:8443/health

# Deve retornar:
# {"status":"healthy","uptime":123,"connections":0}
```

### Teste de Performance
```bash
# Usando wrk para teste de carga
wrk -t4 -c100 -d30s https://localhost:8443/

# Usando ab (Apache Benchmark)
ab -n 1000 -c 10 https://localhost:8443/
```

### Teste de Segurança
```bash
# Verificar certificado
openssl s_client -connect localhost:8443 -servername localhost

# Teste SSL Labs
# Acesse: https://www.ssllabs.com/ssltest/
```

## 🐛 Troubleshooting

### Problemas Comuns

#### Erro de Compilação
```bash
# Limpar cache e recompilar
lake clean
lake build

# Verificar versão do Lean
lean --version
```

#### Erro de Rede
```bash
# Verificar se porta está livre
netstat -an | grep 8443

# Windows: Verificar firewall
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*8443*" }
```

#### Erro de TLS
```bash
# Verificar certificados
openssl x509 -in cert.pem -text -noout

# Testar conectividade TLS
openssl s_client -connect localhost:8443
```

### Logs de Debug
```bash
# Configure log_level = "DEBUG" em server.config
# e execute com redirecionamento:
.lake/build/bin/leanserver 2>&1 | tee debug.log
```

## 📞 Suporte

- **Documentação**: [docs/README.md](README.md)
- **Issues**: [GitHub Issues](https://github.com/seu-usuario/leanserver/issues)
- **Discussões**: [GitHub Discussions](https://github.com/seu-usuario/leanserver/discussions)

## 🔄 Atualização

```bash
# Atualizar código
git pull origin main

# Recompilar
lake clean
lake build

# Reiniciar serviço
systemctl restart leanserver  # ou equivalente
```