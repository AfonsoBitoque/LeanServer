#!/usr/bin/env bash
# Executa todos os harnesses de fuzzing
# Uso: bash fuzz/run_all.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=========================================="
echo "  LeanServer — Fuzzing Suite"
echo "=========================================="
echo ""

# Verificar que o projecto está compilado
if [ ! -d ".lake/build" ]; then
  echo "⚙️  Compilando projecto..."
  lake build
fi

PASS=0
FAIL=0

for harness in fuzz/Fuzz*.lean; do
  name=$(basename "$harness" .lean)
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "▶ Executando $name..."
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if lake env lean "$harness" 2>&1; then
    PASS=$((PASS + 1))
    echo ""
  else
    FAIL=$((FAIL + 1))
    echo "❌ $name FALHOU!"
    echo ""
  fi
done

echo "=========================================="
echo "  Resultados: $PASS passed, $FAIL failed"
echo "=========================================="

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
