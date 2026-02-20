import LeanServer.Web.WebApplication

/-!
# Exemplo Básico de Servidor — LeanServer

Demonstra a utilização real da DSL monádica de routing (#18)
e do framework WebApplication para definir endpoints.
-/

open LeanServer

/-- Definição da aplicação usando a DSL monádica de routes -/
def myApp : WebAppState := webApp defaultWebAppConfig do
  -- Página principal
  get "/" fun _ => WebApp.htmlResponse "<h1>Olá do LeanServer! 🚀</h1><p>Servidor HTTPS em Lean 4</p>"

  -- Health check endpoint
  get "/health" fun _ => WebApp.jsonResponse "{\"status\":\"ok\"}"

  -- Informações do servidor
  get "/api/info" fun _ => WebApp.jsonResponse (
    "{\"server\":\"LeanServer\",\"version\":\"1.0.0\"," ++
    "\"protocol\":\"HTTP/2 + TLS 1.3\"," ++
    "\"features\":[\"HTTP/1.1\",\"HTTP/2\",\"HTTP/3\",\"WebSocket\",\"gRPC\"]}"
  )

  -- Métricas simples
  get "/metrics" fun _ => do
    let resp ← WebApp.jsonResponse "{\"requests_total\":0,\"uptime_seconds\":0}"
    pure (resp.withStatus 200)

  -- Criação de recurso (POST)
  post "/api/users" fun ctx => do
    let body := String.fromUTF8! ctx.request.body
    let resp ← WebApp.jsonResponse s!"\{\"created\":true,\"echo\":\"{body.take 100}\"}"
    pure (resp.withStatus 201)

def main : IO Unit := do
  IO.println "🚀 LeanServer — Exemplo Básico"
  IO.println "📍 Rotas definidas:"
  for (key, _) in myApp.routes do
    IO.println s!"   {key}"
  IO.println ""
  IO.println "Este exemplo demonstra a DSL de routing."
  IO.println "Para executar o servidor completo, use o Main.lean raiz."
  IO.println ""
  -- Demonstrar que as rotas estão registadas
  IO.println s!"Total de rotas: {myApp.routes.length}"
  IO.println s!"Total de middlewares: {myApp.middleware.size}"
