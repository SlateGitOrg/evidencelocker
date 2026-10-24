#!/usr/bin/env bash
# Runs the full test suite (including the exhaustive tamper tests) with
# coverage over the library and CLI packages and enforces a minimum total.
# Usage: scripts/coverage.sh [MIN_PERCENT]
set -euo pipefail
cd "$(dirname "$0")/.."
min="${1:-80}"
go test -covermode=atomic -coverprofile=coverage.out ./pkg/... ./internal/... >coverage.txt
cat coverage.txt
total=$(go tool cover -func=coverage.out | awk '/^total:/ {sub("%","",$3); print $3}')
echo "per-package coverage written to coverage.txt; total statements covered: ${total}%"
awk -v t="$total" -v m="$min" 'BEGIN { if (t + 0 < m + 0) { printf "coverage %.1f%% is below the %s%% threshold\n", t, m; exit 1 } }'
echo "coverage gate (>= ${min}%): ok"
