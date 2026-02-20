import LeanServer.Server.HTTPServer

/-!
  # Rate Limiter — Re-export Module
  Token bucket rate limiting per IP address.

  ## Key Types
  - `RateBucket` — Per-IP token bucket state
  - `RateLimiterConfig` — Rate limiting configuration

  ## Key Functions
  - `checkRateLimit` — Check if request from IP is allowed
-/

namespace LeanServer.RateLimiter

/-- Check rate limit for a given IP address -/
@[inline] def check (ip : String) (nowMs : UInt64) (config : LeanServer.RateLimiterConfig := {}) : IO Bool :=
  LeanServer.checkRateLimit ip nowMs config

end LeanServer.RateLimiter
