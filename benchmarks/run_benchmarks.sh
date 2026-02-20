#!/bin/bash
# ============================================================
# LeanServer Benchmark Suite
# Compare LeanServer against nginx, Caddy, and Hyper (Rust)
#
# Prerequisites:
#   - wrk (HTTP benchmark tool)
#   - h2load (HTTP/2 benchmark, from nghttp2)
#   - curl (for health checks)
#   - jq (for JSON processing)
#
# Usage:
#   ./benchmarks/run_benchmarks.sh [leanserver|nginx|caddy|all]
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results/$(date +%Y%m%d_%H%M%S)"
mkdir -p "${RESULTS_DIR}"

# Configuration
DURATION=30          # seconds per test
THREADS=4            # wrk threads
CONNECTIONS=100      # concurrent connections
H2_STREAMS=10        # h2load concurrent streams per connection

LEAN_HOST="https://localhost:4433"
LEAN_BIN="${SCRIPT_DIR}/../.lake/build/bin/leanserver"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[BENCH]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERROR]${NC} $*"; }

# ============================================================
# 1. Crypto Primitive Benchmarks (pure computation, no network)
# ============================================================
bench_crypto() {
  log "=== Crypto Primitive Benchmarks ==="
  local outfile="${RESULTS_DIR}/crypto.txt"

  cat > /tmp/bench_crypto.py << 'PYEOF'
import hashlib, time, os

def bench(name, fn, iterations=10000):
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    elapsed = time.perf_counter() - start
    ops_per_sec = iterations / elapsed
    print(f"{name}: {ops_per_sec:.0f} ops/sec ({elapsed*1000:.1f}ms for {iterations} iters)")

data_16 = os.urandom(16)
data_1k = os.urandom(1024)
data_64k = os.urandom(65536)

bench("SHA-256 (16B)", lambda: hashlib.sha256(data_16).digest())
bench("SHA-256 (1KB)", lambda: hashlib.sha256(data_1k).digest(), 5000)
bench("SHA-256 (64KB)", lambda: hashlib.sha256(data_64k).digest(), 1000)
bench("HMAC-SHA256 (16B)", lambda: __import__('hmac').new(data_16, data_16, 'sha256').digest())
PYEOF

  log "Python/OpenSSL reference (baseline):"
  python3 /tmp/bench_crypto.py 2>&1 | tee -a "${outfile}"

  log "LeanServer crypto benchmarks:"
  # Run the Lean crypto benchmark if available
  if [ -f "${SCRIPT_DIR}/../.lake/build/bin/test_integration" ]; then
    echo "--- LeanServer crypto benchmark ---" >> "${outfile}"
    # The test binary can be extended with benchmark mode
    echo "(Run manually: lake env lean --run TestCryptoPrimitives.lean)" >> "${outfile}"
  fi

  echo "" >> "${outfile}"
}

# ============================================================
# 2. HTTP/1.1 Throughput (wrk)
# ============================================================
bench_http1_wrk() {
  local target="${1:-$LEAN_HOST}"
  local label="${2:-leanserver}"
  local outfile="${RESULTS_DIR}/http1_${label}.txt"

  log "=== HTTP/1.1 Throughput: ${label} ==="

  if ! command -v wrk &>/dev/null; then
    warn "wrk not installed. Skipping HTTP/1.1 benchmark."
    return
  fi

  # Small response (health endpoint)
  log "  Small response (/health):"
  wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION}s \
    --timeout 5s "${target}/health" 2>&1 | tee -a "${outfile}"

  echo "---" >> "${outfile}"

  # Medium response (index page)
  log "  Medium response (/):"
  wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION}s \
    --timeout 5s "${target}/" 2>&1 | tee -a "${outfile}"
}

# ============================================================
# 3. HTTP/2 Throughput (h2load)
# ============================================================
bench_http2() {
  local target="${1:-$LEAN_HOST}"
  local label="${2:-leanserver}"
  local outfile="${RESULTS_DIR}/http2_${label}.txt"

  log "=== HTTP/2 Throughput: ${label} ==="

  if ! command -v h2load &>/dev/null; then
    warn "h2load not installed. Skipping HTTP/2 benchmark."
    echo "Install: apt install nghttp2-client" >> "${outfile}"
    return
  fi

  # Total requests, clients, max concurrent streams
  log "  h2load — 10000 requests, ${CONNECTIONS} clients, ${H2_STREAMS} streams:"
  h2load -n 10000 -c ${CONNECTIONS} -m ${H2_STREAMS} \
    --h2 "${target}/" 2>&1 | tee -a "${outfile}"
}

# ============================================================
# 4. TLS Handshake Latency
# ============================================================
bench_tls_handshake() {
  local target="${1:-localhost:4433}"
  local label="${2:-leanserver}"
  local outfile="${RESULTS_DIR}/tls_${label}.txt"

  log "=== TLS Handshake Latency: ${label} ==="

  echo "TLS Handshake Latency (10 samples):" > "${outfile}"
  for i in $(seq 1 10); do
    local start=$(date +%s%N)
    echo | openssl s_client -connect "${target}" -tls1_3 -brief 2>/dev/null || true
    local end=$(date +%s%N)
    local ms=$(( (end - start) / 1000000 ))
    echo "  Sample ${i}: ${ms}ms" >> "${outfile}"
  done
  cat "${outfile}"
}

# ============================================================
# 5. Latency Distribution (wrk with Lua)
# ============================================================
bench_latency() {
  local target="${1:-$LEAN_HOST}"
  local label="${2:-leanserver}"
  local outfile="${RESULTS_DIR}/latency_${label}.txt"

  log "=== Latency Distribution: ${label} ==="

  if ! command -v wrk &>/dev/null; then
    warn "wrk not installed. Skipping latency benchmark."
    return
  fi

  wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION}s \
    --latency --timeout 5s "${target}/health" 2>&1 | tee -a "${outfile}"
}

# ============================================================
# 6. Summary Report
# ============================================================
generate_report() {
  local report="${RESULTS_DIR}/SUMMARY.md"

  cat > "${report}" << EOF
# Benchmark Results — $(date +%Y-%m-%d)

## Environment
- OS: $(uname -sr)
- CPU: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
- RAM: $(free -h | grep Mem | awk '{print $2}')
- Lean: $(lean --version 2>/dev/null | head -1 || echo "unknown")

## Configuration
- Duration: ${DURATION}s per test
- Threads: ${THREADS}
- Connections: ${CONNECTIONS}
- H2 Streams: ${H2_STREAMS}

## Results

See individual files in this directory:
- \`crypto.txt\` — Crypto primitive throughput
- \`http1_*.txt\` — HTTP/1.1 throughput (wrk)
- \`http2_*.txt\` — HTTP/2 throughput (h2load)
- \`tls_*.txt\` — TLS handshake latency
- \`latency_*.txt\` — Latency distribution (p50/p95/p99)

## Comparison Matrix

| Metric | LeanServer | nginx | Caddy | Notes |
|--------|-----------|-------|-------|-------|
| HTTP/1.1 req/s | - | - | - | |
| HTTP/2 req/s | - | - | - | |
| TLS handshake (ms) | - | - | - | |
| p99 latency (ms) | - | - | - | |
| Memory (RSS MB) | - | - | - | |
| Binary size (MB) | $(du -m "${LEAN_BIN}" 2>/dev/null | cut -f1 || echo "?") | - | - | |

## Key Observations

1. **Where LeanServer wins**: Memory safety by construction, zero undefined behavior
2. **Where LeanServer loses**: GC pauses, no SIMD crypto optimization
3. **Acceptable for**: Internal services, research, education
4. **Not recommended for**: High-frequency trading, CDN edge servers
EOF

  log "Report: ${report}"
}

# ============================================================
# Main
# ============================================================
main() {
  local target="${1:-all}"

  log "LeanServer Benchmark Suite"
  log "Results directory: ${RESULTS_DIR}"

  case "${target}" in
    crypto)
      bench_crypto
      ;;
    leanserver)
      bench_crypto
      bench_http1_wrk "$LEAN_HOST" "leanserver"
      bench_http2 "$LEAN_HOST" "leanserver"
      bench_tls_handshake "localhost:4433" "leanserver"
      bench_latency "$LEAN_HOST" "leanserver"
      ;;
    all)
      bench_crypto
      # LeanServer
      bench_http1_wrk "$LEAN_HOST" "leanserver"
      bench_http2 "$LEAN_HOST" "leanserver"
      bench_tls_handshake "localhost:4433" "leanserver"
      bench_latency "$LEAN_HOST" "leanserver"
      # nginx (if running on :8443)
      if curl -sk https://localhost:8443/health &>/dev/null; then
        bench_http1_wrk "https://localhost:8443" "nginx"
        bench_http2 "https://localhost:8443" "nginx"
        bench_tls_handshake "localhost:8443" "nginx"
        bench_latency "https://localhost:8443" "nginx"
      else
        warn "nginx not running on :8443 — skipping"
      fi
      # Caddy (if running on :2443)
      if curl -sk https://localhost:2443/health &>/dev/null; then
        bench_http1_wrk "https://localhost:2443" "caddy"
        bench_http2 "https://localhost:2443" "caddy"
        bench_tls_handshake "localhost:2443" "caddy"
        bench_latency "https://localhost:2443" "caddy"
      else
        warn "Caddy not running on :2443 — skipping"
      fi
      ;;
    *)
      echo "Usage: $0 [crypto|leanserver|all]"
      exit 1
      ;;
  esac

  generate_report
  log "Done! Results in ${RESULTS_DIR}/"
}

main "$@"
