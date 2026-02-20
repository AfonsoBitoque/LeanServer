#!/bin/bash
# ─────────────────────────────────────────────────────────
# LeanServer API Documentation Generator (R20)
#
# Extracts documentation from Lean source files and generates
# a comprehensive API reference in Markdown format.
#
# Usage:
#   ./scripts/gen_api_docs.sh > docs/API_GENERATED.md
#
# What it extracts:
#   - Module-level docstrings (/- ... -/)
#   - Function signatures (def/theorem/structure/class)
#   - Docstring comments (/-- ... -/)
#   - Namespace structure
#   - Import dependencies
# ─────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/LeanServer"

# ─────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────
cat << 'HEADER'
# 📚 LeanServer API Reference (Auto-Generated)

> This document is automatically generated from source code docstrings.
> Do not edit manually — run `./scripts/gen_api_docs.sh > docs/API_GENERATED.md`.

## Table of Contents

HEADER

# ─────────────────────────────────────────────────────────
# Collect all modules
# ─────────────────────────────────────────────────────────
modules=()
while IFS= read -r -d '' file; do
  rel="${file#$SRC_DIR/}"
  modules+=("$rel")
done < <(find "$SRC_DIR" -name '*.lean' -type f -print0 | sort -z)

# Generate TOC
for mod in "${modules[@]}"; do
  mod_name="${mod%.lean}"
  mod_display="${mod_name//\//.}"
  anchor="${mod_display,,}"  # lowercase for anchor
  anchor="${anchor//./-}"
  echo "- [LeanServer.${mod_display}](#leanserver${anchor})"
done

echo ""
echo "---"
echo ""

# ─────────────────────────────────────────────────────────
# Process each module
# ─────────────────────────────────────────────────────────
for mod in "${modules[@]}"; do
  filepath="$SRC_DIR/$mod"
  mod_name="${mod%.lean}"
  mod_display="${mod_name//\//.}"

  echo "## LeanServer.${mod_display}"
  echo ""

  # Extract module-level docstring (first /- ... -/ block)
  if head -5 "$filepath" | grep -q '^/-'; then
    echo '```'
    awk '/^\/\-/{found=1} found{print} /^\-\//{if(found) exit}' "$filepath" | head -20
    echo '```'
    echo ""
  fi

  # Count lines
  total_lines=$(wc -l < "$filepath")
  echo "**Lines:** ${total_lines}"
  echo ""

  # Extract imports
  imports=$(grep '^import ' "$filepath" 2>/dev/null || true)
  if [ -n "$imports" ]; then
    echo "**Imports:**"
    echo '```lean'
    echo "$imports"
    echo '```'
    echo ""
  fi

  # Extract structures
  structs=$(grep -n '^structure\|^  structure' "$filepath" 2>/dev/null | head -20 || true)
  if [ -n "$structs" ]; then
    echo "### Structures"
    echo ""
    while IFS= read -r line; do
      linenum="${line%%:*}"
      decl="${line#*:}"
      decl=$(echo "$decl" | sed 's/ where$//' | sed 's/^  //')
      echo "- \`${decl}\` (line ${linenum})"
    done <<< "$structs"
    echo ""
  fi

  # Extract inductive types
  inductives=$(grep -n '^inductive ' "$filepath" 2>/dev/null | head -20 || true)
  if [ -n "$inductives" ]; then
    echo "### Inductive Types"
    echo ""
    while IFS= read -r line; do
      linenum="${line%%:*}"
      decl="${line#*:}"
      decl=$(echo "$decl" | sed 's/ where$//')
      echo "- \`${decl}\` (line ${linenum})"
    done <<< "$inductives"
    echo ""
  fi

  # Extract public function definitions (def, not private)
  defs=$(grep -n '^def \|^noncomputable def ' "$filepath" 2>/dev/null | grep -v '^[0-9]*:private ' | head -40 || true)
  if [ -n "$defs" ]; then
    echo "### Functions"
    echo ""
    while IFS= read -r line; do
      linenum="${line%%:*}"
      decl="${line#*:}"
      # Extract just name and type signature (up to :=)
      funcname=$(echo "$decl" | sed 's/def \([^ ]*\).*/\1/' | sed 's/noncomputable //')
      echo "- \`${funcname}\` (line ${linenum})"
    done <<< "$defs"
    echo ""
  fi

  # Extract theorems
  theorems=$(grep -n '^theorem ' "$filepath" 2>/dev/null | head -20 || true)
  if [ -n "$theorems" ]; then
    echo "### Theorems"
    echo ""
    while IFS= read -r line; do
      linenum="${line%%:*}"
      decl="${line#*:}"
      thmname=$(echo "$decl" | sed 's/theorem \([^ ]*\).*/\1/')
      echo "- \`${thmname}\` (line ${linenum})"
    done <<< "$theorems"
    echo ""
  fi

  # Extract docstrings (/-- ... -/) count
  doccount=$(grep -c '^/--' "$filepath" 2>/dev/null || echo 0)
  if [ "$doccount" -gt 0 ]; then
    echo "**Docstrings:** ${doccount}"
    echo ""
  fi

  echo "---"
  echo ""
done

# ─────────────────────────────────────────────────────────
# Summary statistics
# ─────────────────────────────────────────────────────────
echo "## Summary Statistics"
echo ""

total_modules=${#modules[@]}
total_lines=0
total_defs=0
total_theorems=0
total_structures=0
total_docstrings=0

for mod in "${modules[@]}"; do
  filepath="$SRC_DIR/$mod"
  lines=$(wc -l < "$filepath")
  defs=$(grep -c '^def \|^noncomputable def ' "$filepath" 2>/dev/null || echo 0)
  thms=$(grep -c '^theorem ' "$filepath" 2>/dev/null || echo 0)
  structs=$(grep -c '^structure ' "$filepath" 2>/dev/null || echo 0)
  docs=$(grep -c '^/--' "$filepath" 2>/dev/null || echo 0)
  total_lines=$((total_lines + lines))
  total_defs=$((total_defs + defs))
  total_theorems=$((total_theorems + thms))
  total_structures=$((total_structures + structs))
  total_docstrings=$((total_docstrings + docs))
done

echo "| Metric | Count |"
echo "|--------|-------|"
echo "| Modules | ${total_modules} |"
echo "| Total lines | ${total_lines} |"
echo "| Function definitions | ${total_defs} |"
echo "| Theorems | ${total_theorems} |"
echo "| Structures | ${total_structures} |"
echo "| Docstrings | ${total_docstrings} |"
echo ""
echo "> Generated on $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
