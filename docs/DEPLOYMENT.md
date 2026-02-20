# 🚀 Guia de Deployment - LeanServer

Este guia fornece instruções completas para fazer deployment do LeanServer em diferentes ambientes de produção.

## 📋 Pré-requisitos de Produção

### Sistema Operacional
- **Linux**: Ubuntu 20.04+, CentOS 8+, RHEL 8+
- **Container**: Docker/Podman
- **Orquestração**: Kubernetes, Docker Compose, systemd

### Recursos Mínimos
- **CPU**: 1 vCPU
- **RAM**: 512MB (mínimo), 2GB (recomendado)
- **Disco**: 500MB para binários + logs
- **Rede**: Conectividade estável

### Recursos para Alta Performance
- **CPU**: 4+ vCPUs
- **RAM**: 4GB+
- **Disco**: SSD com 50GB+
- **Rede**: 1Gbps+

## 🐳 Deployment com Docker

### Dockerfile Otimizado
```dockerfile
# Multi-stage build para imagem otimizada
FROM leanprover/lean4:4.27.0 AS builder

# Instalar dependências de build
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copiar código fonte
WORKDIR /app
COPY . .

# Compilar
RUN lake build

# Imagem final minimalista
FROM ubuntu:20.04

# Instalar apenas runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Criar usuário não-root
RUN useradd -r -s /bin/false leanserver

# Copiar binário compilado
COPY --from=builder /app/.lake/build/bin/leanserver /usr/local/bin/leanserver

# Copiar arquivos de configuração e certificados
COPY server.config /etc/leanserver/
COPY cert.pem key.pem /etc/leanserver/ssl/

# Criar diretórios necessários
RUN mkdir -p /var/log/leanserver /var/lib/leanserver && \
    chown -R leanserver:leanserver /var/log/leanserver /var/lib/leanserver

# Configurar usuário
USER leanserver

# Expor porta
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f https://localhost:8443/health || exit 1

# Comando de execução
CMD ["/usr/local/bin/leanserver", "--config", "/etc/leanserver/server.config"]
```

### Docker Compose para Produção
```yaml
version: '3.8'

services:
  leanserver:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8443:8443"
    volumes:
      - ./config/server.config:/etc/leanserver/server.config:ro
      - ./ssl:/etc/leanserver/ssl:ro
      - ./logs:/var/log/leanserver
    environment:
      - LEANSERVER_ENV=production
      - LEANSERVER_LOG_LEVEL=INFO
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "https://localhost:8443/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - web

  # Load balancer opcional
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/ssl/certs:ro
    depends_on:
      - leanserver
    networks:
      - web

networks:
  web:
    driver: bridge
```

### Build e Execução
```bash
# Build da imagem
docker build -t leanserver:latest .

# Executar localmente
docker run -p 8443:8443 leanserver:latest

# Com docker-compose
docker-compose up -d

# Verificar logs
docker-compose logs -f leanserver
```

## ☸️ Deployment no Kubernetes

### Deployment Manifest
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: leanserver
  labels:
    app: leanserver
spec:
  replicas: 3
  selector:
    matchLabels:
      app: leanserver
  template:
    metadata:
      labels:
        app: leanserver
    spec:
      containers:
      - name: leanserver
        image: your-registry/leanserver:latest
        ports:
        - containerPort: 8443
          name: https
        env:
        - name: LEANSERVER_MAX_CONNECTIONS
          value: "1000"
        - name: LEANSERVER_LOG_LEVEL
          value: "INFO"
        volumeMounts:
        - name: config
          mountPath: /etc/leanserver
        - name: ssl-certs
          mountPath: /etc/leanserver/ssl
          readOnly: true
        - name: logs
          mountPath: /var/log/leanserver
        livenessProbe:
          httpGet:
            path: /health
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: leanserver-config
      - name: ssl-certs
        secret:
          secretName: leanserver-tls
      - name: logs
        emptyDir: {}
```

### Service Manifest
```yaml
apiVersion: v1
kind: Service
metadata:
  name: leanserver-service
spec:
  selector:
    app: leanserver
  ports:
  - port: 8443
    targetPort: 8443
    protocol: TCP
  type: ClusterIP
```

### Ingress com TLS
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: leanserver-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - your-domain.com
    secretName: leanserver-tls
  rules:
  - host: your-domain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: leanserver-service
            port:
              number: 8443
```

### ConfigMap para Configuração
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: leanserver-config
data:
  server.config: |
    host = "0.0.0.0"
    port = "8443"
    max_connections = "1000"
    log_level = "INFO"
    enable_websocket = "true"
    enable_server_push = "true"
    health_check_path = "/health"
    metrics_path = "/metrics"
    certificate_path = "/etc/leanserver/ssl/cert.pem"
    private_key_path = "/etc/leanserver/ssl/key.pem"
```

### Aplicar no Cluster
```bash
# Aplicar manifests
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml
kubectl apply -f configmap.yaml

# Verificar deployment
kubectl get pods -l app=leanserver
kubectl get services
kubectl get ingress

# Verificar logs
kubectl logs -f deployment/leanserver
```

## 🖥️ Deployment com systemd

### Arquivo de Serviço
```ini
[Unit]
Description=LeanServer HTTPS Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=leanserver
Group=leanserver
ExecStart=/usr/local/bin/leanserver --config /etc/leanserver/server.config
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
LimitNOFILE=65536

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/log/leanserver /var/lib/leanserver
ProtectHome=yes

# Resource limits
MemoryLimit=1G
CPUQuota=50%

[Install]
WantedBy=multi-user.target
```

### Instalação Manual
```bash
# Criar usuário
sudo useradd -r -s /bin/false leanserver

# Criar diretórios
sudo mkdir -p /etc/leanserver/ssl
sudo mkdir -p /var/log/leanserver
sudo mkdir -p /var/lib/leanserver

# Copiar arquivos
sudo cp .lake/build/bin/leanserver /usr/local/bin/
sudo cp server.config /etc/leanserver/
sudo cp cert.pem key.pem /etc/leanserver/ssl/

# Ajustar permissões
sudo chown -R leanserver:leanserver /var/log/leanserver
sudo chown -R leanserver:leanserver /var/lib/leanserver
sudo chmod 600 /etc/leanserver/ssl/key.pem

# Instalar serviço
sudo cp leanserver.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable leanserver
sudo systemctl start leanserver

# Verificar status
sudo systemctl status leanserver
sudo journalctl -u leanserver -f
```

## 🔒 Configuração de Segurança

### Certificado Let's Encrypt
```bash
# Instalar certbot
sudo apt install certbot

# Gerar certificado
sudo certbot certonly --standalone -d your-domain.com

# Configurar auto-renewal
sudo crontab -e
# Adicionar: 0 12 * * * /usr/bin/certbot renew --quiet
```

### Firewall
```bash
# UFW (Ubuntu)
sudo ufw allow 8443
sudo ufw --force enable

# firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

### SELinux (RHEL/CentOS)
```bash
# Permitir porta customizada
sudo semanage port -a -t http_port_t -p tcp 8443

# Políticas para LeanServer
sudo setsebool -P httpd_can_network_connect 1
```

## 📊 Monitoramento e Observabilidade

### Prometheus + Grafana
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'leanserver'
    static_configs:
      - targets: ['localhost:8443']
    metrics_path: '/metrics'
    scheme: 'https'
    tls_config:
      insecure_skip_verify: true
```

### Dashboard Grafana
```json
{
  "dashboard": {
    "title": "LeanServer Production",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [{
          "expr": "rate(leanserver_requests_total[5m])",
          "legendFormat": "{{instance}} req/s"
        }]
      },
      {
        "title": "Active Connections",
        "type": "singlestat",
        "targets": [{
          "expr": "leanserver_active_connections",
          "legendFormat": "Active Connections"
        }]
      },
      {
        "title": "Memory Usage",
        "type": "graph",
        "targets": [{
          "expr": "process_resident_memory_bytes / 1024 / 1024",
          "legendFormat": "Memory (MB)"
        }]
      }
    ]
  }
}
```

### Log Aggregation (ELK Stack)
```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  paths:
    - /var/log/leanserver/*.log
  json.keys_under_root: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
```

## 🔄 Estratégias de Deployment

### Blue-Green Deployment
```bash
# Criar nova versão
docker tag leanserver:latest leanserver:v2

# Deploy blue (versão atual)
kubectl set image deployment/leanserver leanserver=leanserver:v1

# Testar blue
curl -f https://your-domain.com/health

# Deploy green (nova versão)
kubectl set image deployment/leanserver leanserver=leanserver:v2

# Verificar health checks
kubectl rollout status deployment/leanserver

# Remover versão antiga se tudo OK
docker rmi leanserver:v1
```

### Canary Deployment
```yaml
# Deployment canary (10% do tráfego)
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: leanserver-canary
spec:
  http:
  - route:
    - destination:
        host: leanserver
        subset: v1
      weight: 90
    - destination:
        host: leanserver
        subset: v2
      weight: 10
```

### Rolling Updates
```bash
# Update gradual
kubectl set image deployment/leanserver leanserver=leanserver:v2
kubectl rollout status deployment/leanserver

# Rollback se necessário
kubectl rollout undo deployment/leanserver
```

## 🚨 Troubleshooting de Produção

### Problemas Comuns

#### High Memory Usage
```bash
# Verificar métricas
curl https://localhost:8443/metrics | grep memory

# Ajustar configuração
max_connections = "500"  # Reduzir conexões
```

#### Slow Requests
```bash
# Verificar logs
tail -f /var/log/leanserver/server.log

# Profile de performance
curl https://localhost:8443/debug/pprof/profile > profile.out
go tool pprof profile.out
```

#### TLS Handshake Failures
```bash
# Verificar certificados
openssl x509 -in cert.pem -text -noout

# Testar conectividade
openssl s_client -connect localhost:8443 -servername your-domain.com
```

### Health Checks
```bash
# Endpoint health
curl -f https://localhost:8443/health

# Com timeout
curl --max-time 5 -f https://localhost:8443/health

# Verificar JSON response
curl https://localhost:8443/health | jq .status
```

### Log Analysis
```bash
# Buscar erros
grep "ERROR" /var/log/leanserver/server.log

# Contar requests por endpoint
grep "GET\|POST" /var/log/leanserver/server.log | cut -d' ' -f7 | sort | uniq -c | sort -nr

# Monitorar em tempo real
tail -f /var/log/leanserver/server.log | grep --line-buffered "WARN\|ERROR"
```

## 📈 Otimização de Performance

### Configurações para Alta Carga
```ini
# server.config - Produção high-load
max_connections = "10000"
log_level = "WARN"
enable_websocket = "true"
enable_server_push = "true"
certificate_path = "/etc/leanserver/ssl/cert.pem"
private_key_path = "/etc/leanserver/ssl/key.pem"
health_check_path = "/health"
metrics_path = "/metrics"
```

### Benchmarking
```bash
# Usando wrk
wrk -t12 -c400 -d30s https://your-domain.com/

# Usando hey
hey -n 10000 -c 100 https://your-domain.com/

# Usando vegeta
echo "GET https://your-domain.com/" | vegeta attack -rate=500 -duration=60s | vegeta report
```

### Horizontal Scaling
```yaml
# HPA (Horizontal Pod Autoscaler)
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: leanserver-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: leanserver
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## 🔧 Manutenção

### Backup
```bash
# Backup de configuração
tar -czf backup-config-$(date +%Y%m%d).tar.gz /etc/leanserver/

# Backup de logs
tar -czf backup-logs-$(date +%Y%m%d).tar.gz /var/log/leanserver/
```

### Atualização
```bash
# Rolling update
kubectl set image deployment/leanserver leanserver=leanserver:v2.1.0
kubectl rollout status deployment/leanserver

# Verificar após update
curl https://your-domain.com/health
curl https://your-domain.com/metrics
```

### Disaster Recovery
```bash
# Backup completo
kubectl exec -it leanserver-pod -- tar -czf /tmp/backup.tar.gz /etc/leanserver /var/lib/leanserver

# Copiar backup
kubectl cp leanserver-pod:/tmp/backup.tar.gz ./backup.tar.gz

# Restore
kubectl cp ./backup.tar.gz leanserver-pod:/tmp/
kubectl exec -it leanserver-pod -- tar -xzf /tmp/backup.tar.gz -C /
```

## 📞 Suporte

Para issues de produção:
- Verifique logs em `/var/log/leanserver/`
- Use health checks: `GET /health`
- Monitore métricas: `GET /metrics`
- Documentação: [docs/README.md](README.md)

Para questões críticas, crie issue no repositório com:
- Logs relevantes
- Configuração atual
- Métricas do sistema
- Passos para reproduzir