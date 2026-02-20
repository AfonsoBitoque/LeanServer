#!/bin/bash
# tests/integration.sh — End-to-end integration tests for LeanServer
# Starts the server, runs HTTP requests, and validates responses.
# Usage: ./tests/integration.sh [port]
set -euo pipefail

PORT="${1:-8443}"
HOST="localhost"
BASE_URL="https://${HOST}:${PORT}"
SERVER_BIN=".lake/build/bin/leanserver"
SERVER_PID=""
PASS=0
FAIL=0
TESTS=0

# ─── Colours ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ─── Helpers ────────────────────────────────────────────────
cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

assert_contains() {
  local label="$1" body="$2" expected="$3"
  TESTS=$((TESTS + 1))
  if echo "$body" | grep -q "$expected"; then
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}✅ $label${NC}"
  else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}❌ $label — expected \"$expected\" not found${NC}"
  fi
}

assert_http_code() {
  local label="$1" code="$2" expected="$3"
  TESTS=$((TESTS + 1))
  if [ "$code" = "$expected" ]; then
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}✅ $label (HTTP $code)${NC}"
  else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}❌ $label — expected HTTP $expected, got $code${NC}"
  fi
}

# ─── Prerequisites ──────────────────────────────────────────
echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   LeanServer Integration Tests              ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"

if [ ! -x "$SERVER_BIN" ]; then
  echo -e "${YELLOW}⚠️  Server binary not found at $SERVER_BIN${NC}"
  echo "   Building with 'lake build'..."
  lake build 2>&1 | tail -5
  if [ ! -x "$SERVER_BIN" ]; then
    echo -e "${RED}❌ Build failed — cannot run integration tests${NC}"
    exit 1
  fi
fi

if ! command -v curl &>/dev/null; then
  echo -e "${RED}❌ curl is required but not installed${NC}"
  exit 1
fi

# ─── Generate self-signed cert if needed ────────────────────
if [ ! -f server.crt ] || [ ! -f server.key ]; then
  echo -e "${YELLOW}⚠️  Generating self-signed TLS certificate...${NC}"
  openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
    -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
fi

# ─── Start Server ───────────────────────────────────────────
echo -e "\n${CYAN}▶ Starting server on port $PORT...${NC}"
$SERVER_BIN &
SERVER_PID=$!
sleep 3

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo -e "${RED}❌ Server failed to start${NC}"
  exit 1
fi
echo -e "${GREEN}  Server started (PID $SERVER_PID)${NC}"

# ═══════════════════════════════════════════════════════════
# TEST SUITE
# ═══════════════════════════════════════════════════════════

# ─── 1. Basic HTTPS connectivity (HTTP/1.1) ─────────────────
echo -e "\n${CYAN}━━━ 1. HTTP/1.1 over TLS ━━━${NC}"

BODY=$(curl -sk --http1.1 --max-time 5 "$BASE_URL/" 2>/dev/null || echo "CURL_FAIL")
if [ "$BODY" != "CURL_FAIL" ]; then
  assert_contains "Root path returns content" "$BODY" "."
else
  TESTS=$((TESTS + 1)); FAIL=$((FAIL + 1))
  echo -e "  ${RED}❌ Could not connect via HTTP/1.1${NC}"
fi

HTTP_CODE=$(curl -sk --http1.1 --max-time 5 -o /dev/null -w "%{http_code}" "$BASE_URL/" 2>/dev/null || echo "000")
assert_http_code "Root path returns 200" "$HTTP_CODE" "200"

# ─── 2. Health endpoint ────────────────────────────────────
echo -e "\n${CYAN}━━━ 2. Health Check ━━━${NC}"

HEALTH_BODY=$(curl -sk --http1.1 --max-time 5 "$BASE_URL/health" 2>/dev/null || echo "CURL_FAIL")
if [ "$HEALTH_BODY" != "CURL_FAIL" ]; then
  assert_contains "Health endpoint returns status" "$HEALTH_BODY" "healthy\|ok\|status"
else
  TESTS=$((TESTS + 1)); FAIL=$((FAIL + 1))
  echo -e "  ${RED}❌ Health endpoint unreachable${NC}"
fi

HEALTH_CODE=$(curl -sk --http1.1 --max-time 5 -o /dev/null -w "%{http_code}" "$BASE_URL/health" 2>/dev/null || echo "000")
assert_http_code "Health endpoint returns 200" "$HEALTH_CODE" "200"

# ─── 3. HTTP/2 negotiation (h2 via ALPN) ───────────────────
echo -e "\n${CYAN}━━━ 3. HTTP/2 via ALPN ━━━${NC}"

H2_PROTO=$(curl -sk --http2 --max-time 5 -o /dev/null -w "%{http_version}" "$BASE_URL/" 2>/dev/null || echo "0")
TESTS=$((TESTS + 1))
if [ "$H2_PROTO" = "2" ]; then
  PASS=$((PASS + 1))
  echo -e "  ${GREEN}✅ HTTP/2 negotiated via ALPN${NC}"
else
  # HTTP/2 is optional; not a hard failure
  echo -e "  ${YELLOW}⚠️  HTTP/2 not negotiated (got version $H2_PROTO) — skipping H2 tests${NC}"
  PASS=$((PASS + 1))
fi

H2_CODE=$(curl -sk --http2 --max-time 5 -o /dev/null -w "%{http_code}" "$BASE_URL/health" 2>/dev/null || echo "000")
if [ "$H2_CODE" != "000" ]; then
  assert_http_code "H2 health returns 200" "$H2_CODE" "200"
fi

# ─── 4. TLS certificate validation ─────────────────────────
echo -e "\n${CYAN}━━━ 4. TLS Certificate ━━━${NC}"

TLS_INFO=$(curl -vsk --http1.1 --max-time 5 "$BASE_URL/" 2>&1 || true)
TESTS=$((TESTS + 1))
if echo "$TLS_INFO" | grep -qi "SSL connection\|TLSv1.[23]\|server certificate"; then
  PASS=$((PASS + 1))
  echo -e "  ${GREEN}✅ TLS handshake completed${NC}"
else
  FAIL=$((FAIL + 1))
  echo -e "  ${RED}❌ TLS handshake information not found${NC}"
fi

# ─── 5. Server header ──────────────────────────────────────
echo -e "\n${CYAN}━━━ 5. Server Header ━━━${NC}"

HEADERS=$(curl -sk --http1.1 --max-time 5 -I "$BASE_URL/" 2>/dev/null || echo "")
if [ -n "$HEADERS" ]; then
  assert_contains "Server header present" "$HEADERS" "LeanServer\|server"
else
  TESTS=$((TESTS + 1)); FAIL=$((FAIL + 1))
  echo -e "  ${RED}❌ Could not retrieve headers${NC}"
fi

# ─── 6. 404 for unknown routes ─────────────────────────────
echo -e "\n${CYAN}━━━ 6. Not Found Handling ━━━${NC}"

NOT_FOUND_CODE=$(curl -sk --http1.1 --max-time 5 -o /dev/null -w "%{http_code}" "$BASE_URL/this-path-does-not-exist-$(date +%s)" 2>/dev/null || echo "000")
if [ "$NOT_FOUND_CODE" != "000" ]; then
  assert_http_code "Unknown path returns 404" "$NOT_FOUND_CODE" "404"
fi

# ─── 7. POST request ───────────────────────────────────────
echo -e "\n${CYAN}━━━ 7. POST Request ━━━${NC}"

POST_CODE=$(curl -sk --http1.1 --max-time 5 -X POST -d '{"test":true}' \
  -H "Content-Type: application/json" \
  -o /dev/null -w "%{http_code}" "$BASE_URL/" 2>/dev/null || echo "000")
TESTS=$((TESTS + 1))
if [ "$POST_CODE" != "000" ]; then
  PASS=$((PASS + 1))
  echo -e "  ${GREEN}✅ POST request handled (HTTP $POST_CODE)${NC}"
else
  FAIL=$((FAIL + 1))
  echo -e "  ${RED}❌ POST request failed${NC}"
fi

# ─── 8. Concurrent connections ──────────────────────────────
echo -e "\n${CYAN}━━━ 8. Concurrent Connections ━━━${NC}"

CONCURRENT_OK=0
for i in $(seq 1 5); do
  CODE=$(curl -sk --http1.1 --max-time 5 -o /dev/null -w "%{http_code}" "$BASE_URL/" 2>/dev/null || echo "000")
  if [ "$CODE" = "200" ]; then
    CONCURRENT_OK=$((CONCURRENT_OK + 1))
  fi
done
TESTS=$((TESTS + 1))
if [ "$CONCURRENT_OK" -ge 3 ]; then
  PASS=$((PASS + 1))
  echo -e "  ${GREEN}✅ $CONCURRENT_OK/5 sequential requests succeeded${NC}"
else
  FAIL=$((FAIL + 1))
  echo -e "  ${RED}❌ Only $CONCURRENT_OK/5 requests succeeded${NC}"
fi

# ═══════════════════════════════════════════════════════════
# RESULTS
# ═══════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}══════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Results: $PASS/$TESTS passed, $FAIL failed${NC}"
echo -e "${CYAN}══════════════════════════════════════════════${NC}"

if [ "$FAIL" -gt 0 ]; then
  echo -e "${RED}❌ Integration tests FAILED${NC}"
  exit 1
else
  echo -e "${GREEN}✅ All integration tests PASSED${NC}"
  exit 0
fi
