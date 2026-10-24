#!/usr/bin/env bash
# Short fuzzing pass over every parser that consumes untrusted input.
# FUZZTIME (default 20s) applies per target.
set -euo pipefail
cd "$(dirname "$0")/.."
t=${FUZZTIME:-20s}
go test -run '^$' -fuzz '^FuzzVerifyInclusion$' -fuzztime "$t" ./pkg/merkle
go test -run '^$' -fuzz '^FuzzParsePlist$' -fuzztime "$t" ./pkg/collectors/persistence
go test -run '^$' -fuzz '^FuzzParseCronLine$' -fuzztime "$t" ./pkg/collectors/persistence
go test -run '^$' -fuzz '^FuzzParseUtmp$' -fuzztime "$t" ./pkg/collectors/users
go test -run '^$' -fuzz '^FuzzVerifyTar$' -fuzztime "$t" ./pkg/bundle
go test -run '^$' -fuzz '^FuzzCustodyVerify$' -fuzztime "$t" ./pkg/custody
