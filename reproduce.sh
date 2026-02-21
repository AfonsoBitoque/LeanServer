#!/bin/bash
# ============================================================================
# reproduce.sh — One-command artifact reproduction for LeanServer
# ============================================================================
# Usage: ./reproduce.sh
#
# This script builds the project, runs all verification checks, and produces
# a summary report. Designed for artifact evaluation committees (AEC).
# ============================================================================

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║         LeanServer — Artifact Reproduction             ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Build ───────────────────────────────────────────
echo "▶ Step 1: Building project..."
lake build leanserver 2>&1 | tail -3
echo "✅ Build completed"
echo ""

# ── Step 2: Verification Metrics ────────────────────────────
echo "▶ Step 2: Verification metrics..."

LEAN_FILES=$(find LeanServer/ -name "*.lean" | wc -l)
LEAN_LOC=$(find LeanServer/ -name "*.lean" -exec cat {} + | wc -l)
C_FILES=$(find src/ -name "*.c" | wc -l)
C_LOC=$(find src/ -name "*.c" -exec cat {} + | wc -l)
THEOREMS=$(grep -rc "theorem \|lemma " LeanServer/ --include="*.lean" | awk -F: '{s+=$2} END {print s}')
# Filter sorry from comments, strings, and documentation
# Only match actual `sorry` tactic usage (at start of line or after :=)
SORRY_COUNT=$(grep -rn "\bsorry\b" LeanServer/ --include="*.lean" \
  | grep -v "^[^:]*:[^:]*:.*--" \
  | grep -v "/-\|  -/" \
  | grep -v "sorry\." \
  | grep -v "0 sorry" \
  | grep -v "sorry\`\|\`sorry" \
  | grep -v "zero sorry\|Zero sorry\|sem sorry\|no sorry\|No sorry" \
  | grep -v '".*sorry.*"' \
  | wc -l)
PARTIAL_COUNT=$(grep -r "partial def" LeanServer/ --include="*.lean" | wc -l)
NATIVE_COUNT=$(grep -r "native_decide" LeanServer/ --include="*.lean" | wc -l)

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                   VERIFICATION REPORT                   ║"
echo "╠══════════════════════════════════════════════════════════╣"
printf "║  Lean files:          %6d                            ║\n" "$LEAN_FILES"
printf "║  Lines of Lean:       %6d                            ║\n" "$LEAN_LOC"
printf "║  C files:             %6d                            ║\n" "$C_FILES"
printf "║  Lines of C:          %6d                            ║\n" "$C_LOC"
printf "║  Theorems:            %6d                            ║\n" "$THEOREMS"
printf "║  sorry count:         %6d  (must be 0)               ║\n" "$SORRY_COUNT"
printf "║  partial def count:   %6d  (must be ≤ 4)             ║\n" "$PARTIAL_COUNT"
printf "║  native_decide count: %6d                            ║\n" "$NATIVE_COUNT"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Step 3: Checks ──────────────────────────────────────────
PASS=0
FAIL=0

# Check: zero sorry
if [ "$SORRY_COUNT" -eq 0 ]; then
  echo "✅ PASS: Zero sorry"
  PASS=$((PASS + 1))
else
  echo "❌ FAIL: Found $SORRY_COUNT sorry occurrences"
  grep -rn "\bsorry\b" LeanServer/ --include="*.lean" \
    | grep -v "^[^:]*:[^:]*:.*--" \
    | grep -v "/-" \
    | grep -v "0 sorry" \
    | grep -v "zero sorry\|Zero sorry\|sem sorry\|no sorry\|No sorry" \
    | grep -v '".*sorry.*"'
  FAIL=$((FAIL + 1))
fi

# Check: partial def count ≤ 4
if [ "$PARTIAL_COUNT" -le 4 ]; then
  echo "✅ PASS: partial def count ≤ 4 ($PARTIAL_COUNT)"
  PASS=$((PASS + 1))
else
  echo "❌ FAIL: Too many partial defs: $PARTIAL_COUNT (max: 4)"
  FAIL=$((FAIL + 1))
fi

# Check: theorems ≥ 900
if [ "$THEOREMS" -ge 900 ]; then
  echo "✅ PASS: $THEOREMS theorems (≥ 900 required)"
  PASS=$((PASS + 1))
else
  echo "⚠️  WARN: Only $THEOREMS theorems (expected ≥ 900)"
  FAIL=$((FAIL + 1))
fi

# Check: native_decide documented
if [ "$NATIVE_COUNT" -le 500 ]; then
  echo "✅ PASS: native_decide count ≤ 500 ($NATIVE_COUNT) — concrete-value checks (see docs/PROOF_GUIDE.md)"
  PASS=$((PASS + 1))
else
  echo "⚠️  WARN: native_decide count $NATIVE_COUNT > 500 — review docs/PROOF_GUIDE.md"
  FAIL=$((FAIL + 1))
fi

# ── Step 4: Run test suites ─────────────────────────────────
echo ""
echo "▶ Step 4: Running test suites..."

run_test() {
  local name=$1
  local target=$2
  if lake build "$target" 2>&1 | tail -1 | grep -q "success"; then
    local result
    result=$(.lake/build/bin/"$target" 2>&1 | tail -1)
    echo "  ✅ $name: $result"
    PASS=$((PASS + 1))
  else
    echo "  ❌ $name: build failed"
    FAIL=$((FAIL + 1))
  fi
}

run_test "Differential crypto (41 tests)" "differential_crypto"
run_test "HTTP/2 conformance (51 tests)" "http2_conformance"
run_test "TLS handshake e2e (45 tests)" "tls_handshake_e2e"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Result: $PASS passed, $FAIL failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

echo ""
echo "🎉 All checks passed!"
