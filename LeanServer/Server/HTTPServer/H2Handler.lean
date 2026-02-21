-- LeanServer/HTTPServer/H2Handler.lean
-- Re-export HTTP/2 connection handling components from HTTPServer
-- Sub-module structure: splits HTTPServer.lean into focused import targets
--
-- This module provides a clean import path for HTTP/2 functionality:
--   import LeanServer.Server.HTTPServer.H2Handler
--
-- Key functions available through this module (defined in HTTPServer.lean):
--   • handleH2Connection — Full HTTP/2 connection handler (~410 LOC)
--   • processH2Frame — Frame-level HTTP/2 processing
--   • sendH2Response — Send HTTP/2 response with HPACK headers
--   • HTTP/2 flow control (updateConnectionWindow, updateStreamWindow)
--
-- HTTP/2 types are in HTTP2.lean (HTTP2Connection, HTTP2Frame, etc.).
-- Refer to HTTPServer.lean for the canonical implementations.
-- Future work: gradually move H2 functions here for better modularity.

import LeanServer.Server.HTTPServer

namespace LeanServer.H2Handler

/-- Re-export marker — confirms H2Handler sub-module is available -/
def available : Bool := true

end LeanServer.H2Handler
