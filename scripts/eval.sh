#!/usr/bin/env bash
# Tamper-detection evaluation: exhaustive single-byte flips over a sealed
# fixture bundle (see tools/tampereval). Takes about 30 s.
set -euo pipefail
cd "$(dirname "$0")/.."
go run ./tools/tampereval -fixture "${1:-compromised}" -mask "${2:-0xff}"
