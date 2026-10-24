#!/usr/bin/env bash
# Offline end-to-end demo against the bundled synthetic fixtures:
# collect -> seal -> verify -> custody handoff -> baseline diff -> tamper
# detection -> selective-disclosure proof. Everything runs in ./.demo.
set -euo pipefail
cd "$(dirname "$0")/.."

GO=${GO:-go}
D=.demo
EL=bin/evidencelocker
rm -rf "$D"
mkdir -p "$D" bin
$GO build -o "$EL" ./cmd/evidencelocker
$GO build -o bin/tamper ./tools/tamper

step() { printf '\n\033[1m== %s\033[0m\n$ %s\n' "$1" "${*:2}"; }
# expect CODE CMD...: run CMD, show output, fail the demo if exit code differs.
expect() {
	local want=$1; shift
	set +e; "$@"; local got=$?; set -e
	if [ "$got" -ne "$want" ]; then echo "demo: expected exit $want, got $got: $*" >&2; exit 1; fi
}

step "1. keys for the collecting responder and the receiving analyst" "$EL keygen --out $D/responder; $EL keygen --out $D/analyst"
$EL keygen --out $D/responder
$EL keygen --out $D/analyst

step "2. collect the known-good baseline image" "$EL collect --root testdata/hosts/baseline ..."
$EL collect --root testdata/hosts/baseline --out $D/web01-baseline.tar.zst --key $D/responder.key \
	--case IR-2026-042 --examiner responder --note "golden image from build pipeline"

step "3. collect the suspect host (same server, after the incident)" "$EL collect --root testdata/hosts/compromised ..."
$EL collect --root testdata/hosts/compromised --out $D/web01-incident.tar.zst --key $D/responder.key \
	--case IR-2026-042 --examiner responder --note "live response, ticket 7731"

step "4. verify bundle + custody log, pinning the responder key" \
	"$EL verify --trusted-key $D/responder.pub --custody $D/web01-incident.tar.zst.custody.jsonl $D/web01-incident.tar.zst"
expect 0 $EL verify --trusted-key $D/responder.pub --custody $D/web01-incident.tar.zst.custody.jsonl $D/web01-incident.tar.zst

LOG=$D/web01-incident.tar.zst.custody.jsonl
step "5. hand custody to the analyst; analyst records an examination" "$EL custody append ... --action transfer --to analyst"
$EL custody append --log $LOG --key $D/responder.key --actor responder --action transfer \
	--to analyst --to-key $D/analyst.pub --note "sealed bag 17, courier"
$EL custody append --log $LOG --key $D/analyst.key --actor analyst --action access --note "opened in lab VM"
HEAD=$(tail -n 1 $LOG | sed -E 's/.*"hash":"([0-9a-f]+)".*/\1/')
step "   the former custodian can no longer sign" "$EL custody append --key $D/responder.key ..."
expect 2 $EL custody append --log $LOG --key $D/responder.key --actor responder --action note --note "late edit"
$EL custody show --log $LOG

step "6. diff against the baseline (exit 1 = findings at/above medium)" "$EL diff --trusted-key $D/responder.pub baseline incident"
expect 1 $EL diff --trusted-key $D/responder.pub $D/web01-baseline.tar.zst $D/web01-incident.tar.zst

step "7a. tamper: flip one byte inside files/etc/cron.d/sysupdate" "bin/tamper -mode content -path files/etc/cron.d/sysupdate -offset 40 ..."
bin/tamper -mode content -path files/etc/cron.d/sysupdate -offset 40 $D/web01-incident.tar.zst $D/t-content.tar.zst
expect 1 $EL verify --trusted-key $D/responder.pub $D/t-content.tar.zst

step "7b. tamper: flip one byte of the compressed file, checked against the custody seal" "bin/tamper -mode raw -offset 5000 ..."
bin/tamper -mode raw -offset 5000 $D/web01-incident.tar.zst $D/t-raw.tar.zst
cp $LOG $D/t-raw.tar.zst.custody.jsonl
expect 1 $EL verify --trusted-key $D/responder.pub --custody $D/t-raw.tar.zst.custody.jsonl $D/t-raw.tar.zst

step "7c. tamper: rewrite a custody note after the fact" "sed 's/sealed bag 17/sealed bag 71/' custody log"
sed 's/sealed bag 17/sealed bag 71/' $LOG > $D/t-custody.jsonl
expect 1 $EL custody verify --log $D/t-custody.jsonl

step "7d. tamper: drop the newest custody entry (caught only with an out-of-band head)" "head -n 2 log; custody verify --expect-head $HEAD"
head -n 2 $LOG > $D/t-truncated.jsonl
expect 0 $EL custody verify --log $D/t-truncated.jsonl
expect 1 $EL custody verify --log $D/t-truncated.jsonl --expect-head "$HEAD"

step "8. selective disclosure: prove one file is in the sealed bundle" "$EL prove --path files/etc/cron.d/sysupdate ...; $EL verify-proof ..."
$EL prove --path files/etc/cron.d/sysupdate -o $D/sysupdate.proof.json --trusted-key $D/responder.pub $D/web01-incident.tar.zst
$EL extract --path files/etc/cron.d/sysupdate -o $D/sysupdate $D/web01-incident.tar.zst
expect 0 $EL verify-proof --trusted-key $D/responder.pub --content $D/sysupdate $D/sysupdate.proof.json

printf '\ndemo: all steps behaved as expected (artifacts in %s)\n' "$D"
