import LeanServer.Server.HTTPServer

/-!
  # Server Configuration — Re-export Module
  Clean import path for server configuration, constants, and runtime state.

  ## Key Types
  - `ServerConfig` — Parsed server configuration
  - `ServerLogLevel` — Log level enum
  - `HTTPServerState` — Server runtime state

  ## Key Functions
  - `loadServerConfig` — Load config from file
  - `parseConfigFile` — Parse config content
  - `serverLog` — Log with level filtering
  - `getServerConfig` — Get current config
  - `getServerSecret` — Get runtime server secret
-/

namespace LeanServer.Config

/-- Load server configuration from file -/
@[inline] def load (path : String := "server.config") : IO LeanServer.ServerConfig :=
  LeanServer.loadServerConfig path

/-- Parse configuration from string content -/
@[inline] def parse (content : String) : LeanServer.ServerConfig :=
  LeanServer.parseConfigFile content

/-- Get the current server configuration -/
@[inline] def current : IO LeanServer.ServerConfig :=
  LeanServer.getServerConfig

/-- TLS content type constants -/
def contentHandshake : UInt8 := 0x16
def contentAppData : UInt8 := 0x17
def contentAlert : UInt8 := 0x15
def contentCCS : UInt8 := 0x14

end LeanServer.Config
