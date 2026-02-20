-- LeanServer/HTTPServer/TLSHandler.lean
-- Re-export TLS handshake and application loop components from HTTPServer
-- (#17: sub-module structure for HTTPServer.lean)
--
-- This module provides a clean import path for TLS-related functionality:
--   import LeanServer.Server.HTTPServer.TLSHandler
--
-- Key functions available through this module (defined in HTTPServer.lean):
--   • handleTLSHandshake — Full TLS 1.3 handshake state machine
--   • applicationDataLoop — Decrypts/processes post-handshake application data
--   • handleRealConnection — Top-level connection handler (TLS + HTTP dispatch)
--   • parseSNI — Server Name Indication extension parsing (via Crypto.lean)
--
-- Refer to HTTPServer.lean for the canonical implementations.
-- Future work: gradually move TLS functions here for better modularity.

import LeanServer.Server.HTTPServer

namespace LeanServer.TLSHandler

/-- Re-export marker — confirms TLSHandler sub-module is available -/
def available : Bool := true

end LeanServer.TLSHandler
