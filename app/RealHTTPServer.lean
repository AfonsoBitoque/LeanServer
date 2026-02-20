-- Real HTTPS Server Main
import LeanServer.Server.HTTPServer
import LeanServer

def main : IO Unit := do
  let server ← LeanServer.initHTTPServer 4433
  LeanServer.runHTTPServer server
