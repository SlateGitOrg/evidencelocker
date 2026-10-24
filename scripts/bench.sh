#!/usr/bin/env bash
# Micro-benchmarks quoted in the README. Numbers depend on the machine and
# on concurrent load; the README states the conditions they were taken under.
set -euo pipefail
cd "$(dirname "$0")/.."
go test -run '^$' -bench . -benchtime 5x -benchmem ./pkg/merkle ./pkg/bundle ./pkg/collectors/filehash
