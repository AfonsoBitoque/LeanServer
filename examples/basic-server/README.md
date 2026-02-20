# Exemplo Básico de Servidor HTTPS

Este exemplo demonstra como definir rotas usando a DSL monádica do LeanServer (`WebApplication.lean`).

## Arquivos

- `server.config` - Configuração do servidor
- `Main.lean` - Definição de rotas com a DSL monádica

## Rotas definidas

| Método | Path | Descrição |
|--------|------|-----------|
| GET | `/` | Página HTML principal |
| GET | `/health` | Health check (JSON) |
| GET | `/api/info` | Informações do servidor |
| GET | `/metrics` | Métricas simples |
| POST | `/api/users` | Criação de recurso com echo do body |

## Como executar

```bash
# Compilar (a partir da raiz do projecto)
cd ../..
lake build

# Ou compilar apenas o exemplo
cd examples/basic-server
lake build

# Executar
./build/bin/basic-server
```

## API DSL

```lean
def myApp := webApp defaultWebAppConfig do
  get "/" fun _ => htmlResponse "<h1>Olá!</h1>"
  get "/health" fun _ => jsonResponse "{\"ok\":true}"
  post "/api/users" fun ctx => do
    let body := String.fromUTF8! ctx.request.body
    let resp ← jsonResponse s!"\{\"echo\":\"{body}\"}"
    pure (resp.withStatus 201)
```