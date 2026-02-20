-- LeanServer/HTTPServer/QUICHandler.lean
-- Re-export QUIC packet processing components from HTTPServer
-- (#17: sub-module structure for HTTPServer.lean)
--
-- This module provides a clean import path for QUIC-related functionality:
--   import LeanServer.Server.HTTPServer.QUICHandler
--
-- Key functions available through this module (defined in HTTPServer.lean):
--   • handleQUICLongHeader — Initial/Handshake/0-RTT packet processing (~850 LOC)
--   • handleQUICShortHeader — 1-RTT packet processing with decryption
--   • quicUdpLoop — Main UDP receive loop for QUIC packets
--   • quicRetransmitSweep — Loss detection and retransmission
--   • sendShortHeaderPacket — Encrypt and send QUIC Short Header packets
--   • processH3Request — HTTP/3 request handling over QUIC streams
--
-- QUIC state types are in QUIC.lean; HTTP/3 types in HTTP3.lean.
-- Refer to HTTPServer.lean for the canonical implementations.
-- Future work: gradually move QUIC functions here for better modularity.

import LeanServer.Server.HTTPServer

namespace LeanServer.QUICHandler

/-- Re-export marker — confirms QUICHandler sub-module is available -/
def available : Bool := true

end LeanServer.QUICHandler
