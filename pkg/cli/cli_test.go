package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SlateGitOrg/evidencelocker/internal/testutil"
	"github.com/SlateGitOrg/evidencelocker/pkg/collector"
	"github.com/SlateGitOrg/evidencelocker/pkg/collectors/builtin"
)

type result struct {
	code           int
	stdout, stderr string
}

func run(t *testing.T, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	app := &App{
		Registry: builtin.Registry(),
		Clock:    collector.FixedClock{T: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)},
		Stdout:   &out, Stderr: &errb,
	}
	code := app.Run(context.Background(), args)
	return result{code, out.String(), errb.String()}
}

func mustOK(t *testing.T, r result) result {
	t.Helper()
	if r.code != ExitOK {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
	}
	return r
}

// workspace creates keys and two sealed fixture bundles via the CLI.
type workspace struct{ dir, collectorKey, collectorPub, analystKey, analystPub, base, cur string }

func setup(t *testing.T) workspace {
	t.Helper()
	d := t.TempDir()
	w := workspace{dir: d,
		collectorKey: filepath.Join(d, "collector.key"), collectorPub: filepath.Join(d, "collector.pub"),
		analystKey: filepath.Join(d, "analyst.key"), analystPub: filepath.Join(d, "analyst.pub"),
		base: filepath.Join(d, "base.tar.zst"), cur: filepath.Join(d, "cur.tar.zst"),
	}
	mustOK(t, run(t, "keygen", "--out", filepath.Join(d, "collector")))
	mustOK(t, run(t, "keygen", "--out", filepath.Join(d, "analyst")))
	cfg := filepath.Join(d, "cfg.json")
	os.WriteFile(cfg, []byte(`{"parallelism":3,"timeout":"1m","options":{"filehash":{"workers":2}}}`), 0o600)
	r := mustOK(t, run(t, "collect", "--root", testutil.Fixture(t, "baseline"), "--out", w.base, "--key", w.collectorKey,
		"--case", "IR-9", "--examiner", "first responder", "--config", cfg))
	if !strings.Contains(r.stdout, "persistence  ok") || !strings.Contains(r.stdout, "web01") {
		t.Fatalf("collect output:\n%s", r.stdout)
	}
	mustOK(t, run(t, "collect", "--root", testutil.Fixture(t, "compromised"), "--out", w.cur, "--key", w.collectorKey,
		"--case", "IR-9", "--examiner", "first responder", "--note", "seized 09:00"))
	return w
}

func TestEndToEnd(t *testing.T) {
	w := setup(t)
	logp := w.cur + ".custody.jsonl"

	r := mustOK(t, run(t, "verify", "--trusted-key", w.collectorPub, "--custody", logp, w.cur))
	if !strings.Contains(r.stdout, "result   OK") || !strings.Contains(r.stdout, "(trusted)") || !strings.Contains(r.stdout, "custodian first responder") {
		t.Fatalf("verify:\n%s", r.stdout)
	}
	// Custody handoff to the analyst, then analyst records access.
	mustOK(t, run(t, "custody", "append", "--log", logp, "--key", w.collectorKey, "--actor", "first responder",
		"--action", "transfer", "--to", "analyst", "--to-key", w.analystPub, "--note", "evidence bag 4"))
	r = mustOK(t, run(t, "custody", "append", "--log", logp, "--key", w.analystKey, "--actor", "analyst", "--action", "access"))
	head := strings.TrimSpace(r.stdout[strings.Index(r.stdout, "head ")+5:])
	// The collector no longer holds custody.
	if r := run(t, "custody", "append", "--log", logp, "--key", w.collectorKey, "--actor", "first responder", "--action", "note"); r.code != ExitUsage {
		t.Fatalf("former custodian appended: %d %s", r.code, r.stderr)
	}
	r = mustOK(t, run(t, "custody", "verify", "--log", logp, "--bundle", w.cur, "--trusted-key", w.collectorPub, "--expect-head", head))
	if !strings.Contains(r.stdout, "3 entries, current custodian analyst") {
		t.Fatalf("custody verify:\n%s", r.stdout)
	}
	r = mustOK(t, run(t, "custody", "show", "--log", logp))
	if !strings.Contains(r.stdout, "transfer  first responder") || !strings.Contains(r.stdout, "-> analyst") || !strings.Contains(r.stdout, `"evidence bag 4"`) {
		t.Fatalf("show:\n%s", r.stdout)
	}
	r = mustOK(t, run(t, "custody", "verify", "--json", "--log", logp))
	var crep map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &crep); err != nil || crep["ok"] != true {
		t.Fatalf("custody json: %v", err)
	}

	// Baseline diff: findings at/above medium -> exit 1.
	r = run(t, "diff", "--trusted-key", w.collectorPub, w.base, w.cur)
	if r.code != ExitFindings || !strings.Contains(r.stdout, "summary:  6 critical, 7 high, 1 medium, 2 low") {
		t.Fatalf("diff exit %d:\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	r = mustOK(t, run(t, "diff", "--fail-on", "critical", "--json", w.base, w.base))
	var drep map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &drep); err != nil || len(drep["findings"].([]any)) != 0 {
		t.Fatalf("diff json: %v", err)
	}

	r = mustOK(t, run(t, "inspect", "--trusted-key", w.collectorPub, w.cur))
	if !strings.Contains(r.stdout, "case       IR-9 (examiner first responder)") || !strings.Contains(r.stdout, "files/etc/cron.d/sysupdate") {
		t.Fatalf("inspect:\n%s", r.stdout)
	}
	r = mustOK(t, run(t, "inspect", "--json", w.cur))
	if !strings.Contains(r.stdout, `"format": "evidencelocker/manifest/v1"`) {
		t.Fatalf("inspect json:\n%s", r.stdout)
	}

	r = mustOK(t, run(t, "extract", "--path", "files/etc/cron.d/sysupdate", w.cur))
	if !strings.Contains(r.stdout, "203.0.113.50") {
		t.Fatalf("extract:\n%s", r.stdout)
	}
	extracted := filepath.Join(w.dir, "sysupdate")
	mustOK(t, run(t, "extract", "--path", "files/etc/cron.d/sysupdate", "-o", extracted, w.cur))
	if r := run(t, "extract", "--path", "files/nope", w.cur); r.code != ExitUsage {
		t.Fatal("extract of absent entry")
	}

	proof := filepath.Join(w.dir, "proof.json")
	mustOK(t, run(t, "prove", "--path", "files/etc/cron.d/sysupdate", "-o", proof, w.cur))
	r = mustOK(t, run(t, "verify-proof", "--trusted-key", w.collectorPub, "--content", extracted, proof))
	if !strings.Contains(r.stdout, "proof    OK") || !strings.Contains(r.stdout, "content  matches") {
		t.Fatalf("verify-proof:\n%s", r.stdout)
	}
	if r := run(t, "verify-proof", "--trusted-key", w.analystPub, proof); r.code != ExitFindings {
		t.Fatalf("proof with wrong trusted key: %d", r.code)
	}
	if r := run(t, "verify-proof", "--content", w.base, proof); r.code != ExitFindings || !strings.Contains(r.stdout, "INVALID") {
		t.Fatalf("proof with wrong content: %d %s", r.code, r.stdout)
	}
	r = mustOK(t, run(t, "prove", "--path", "collectors/accounts.json", w.cur))
	if !strings.Contains(r.stdout, `"audit_path"`) {
		t.Fatal("prove to stdout")
	}
}

func TestTamperDetectedThroughCLI(t *testing.T) {
	w := setup(t)
	raw, _ := os.ReadFile(w.cur)
	raw[len(raw)/2] ^= 0xff
	bad := filepath.Join(w.dir, "bad.tar.zst")
	os.WriteFile(bad, raw, 0o600)
	os.WriteFile(bad+".custody.jsonl", mustRead(t, w.cur+".custody.jsonl"), 0o600)
	r := run(t, "verify", "--custody", bad+".custody.jsonl", bad)
	if r.code != ExitFindings || !strings.Contains(r.stdout, "FILE_DIGEST_MISMATCH") || !strings.Contains(r.stdout, "BUNDLE_BINDING") {
		t.Fatalf("tampered verify exit %d:\n%s", r.code, r.stdout)
	}
	r = run(t, "verify", "--json", bad)
	var res verifyResult
	if err := json.Unmarshal([]byte(r.stdout), &res); err != nil || res.OK || r.code != ExitFindings {
		t.Fatalf("json: %v %s", err, r.stdout)
	}
	for _, cmd := range [][]string{{"inspect", bad}, {"extract", "--path", "collectors/users.json", bad}, {"prove", "--path", "collectors/users.json", bad}} {
		if r := run(t, cmd...); r.code != ExitFindings || !strings.Contains(r.stdout, "FAILED") {
			t.Errorf("%v on tampered bundle: exit %d", cmd, r.code)
		}
	}
	if r := run(t, "diff", w.base, bad); r.code != ExitUsage || !strings.Contains(r.stderr, "failed verification") {
		t.Fatalf("diff against tampered bundle: %d %s", r.code, r.stderr)
	}
	// Untrusted signer pinned -> failure.
	if r := run(t, "verify", "--trusted-key", w.analystPub, w.cur); r.code != ExitFindings || !strings.Contains(r.stdout, "UNTRUSTED_KEY") {
		t.Fatalf("untrusted: %d %s", r.code, r.stdout)
	}
	// Truncated custody log is caught with an anchor.
	logp := w.cur + ".custody.jsonl"
	mustOK(t, run(t, "custody", "append", "--log", logp, "--key", w.collectorKey, "--actor", "first responder", "--action", "verify"))
	full, _ := os.ReadFile(logp)
	lines := strings.SplitAfter(strings.TrimSpace(string(full)), "\n")
	var last map[string]any
	json.Unmarshal([]byte(lines[len(lines)-1]), &last)
	os.WriteFile(logp, []byte(lines[0]), 0o600)
	r = run(t, "custody", "verify", "--log", logp, "--expect-head", last["hash"].(string))
	if r.code != ExitFindings || !strings.Contains(r.stdout, "HEAD_MISMATCH") {
		t.Fatalf("truncation: %d %s", r.code, r.stdout)
	}
	if r := run(t, "custody", "show", "--log", logp+".missing"); r.code != ExitUsage {
		t.Fatal("show missing log")
	}
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUsageErrors(t *testing.T) {
	d := t.TempDir()
	cases := []struct {
		args []string
		code int
		msg  string
	}{
		{nil, ExitUsage, "usage:"},
		{[]string{"help"}, ExitOK, "commands:"},
		{[]string{"-h"}, ExitOK, "usage:"},
		{[]string{"bogus"}, ExitUsage, "unknown command"},
		{[]string{"--log-level", "loud", "version"}, ExitUsage, "--log-level"},
		{[]string{"--log-format", "xml", "version"}, ExitUsage, "--log-format"},
		{[]string{"--nope"}, ExitUsage, ""},
		{[]string{"version", "extra"}, ExitUsage, "wrong number"},
		{[]string{"verify"}, ExitUsage, "wrong number"},
		{[]string{"verify", "-h"}, ExitOK, "usage: evidencelocker verify"},
		{[]string{"verify", "--bogus", "x"}, ExitUsage, ""},
		{[]string{"verify", filepath.Join(d, "missing")}, ExitUsage, "no such file"},
		{[]string{"verify", "--trusted-key", filepath.Join(d, "nokey"), "x"}, ExitUsage, "trusted key"},
		{[]string{"collect"}, ExitUsage, "requires --out"},
		{[]string{"collect", "--out", filepath.Join(d, "o"), "--key", filepath.Join(d, "k"), "--case", "c", "--examiner", "e"}, ExitUsage, "no such file"},
		{[]string{"collect", "--out", "o", "--key", "k", "--case", "c", "--examiner", "e", "--config", filepath.Join(d, "nocfg")}, ExitUsage, "no such file"},
		{[]string{"keygen"}, ExitUsage, "usage"},
		{[]string{"diff", "a"}, ExitUsage, "wrong number"},
		{[]string{"diff", "--fail-on", "huge", "a", "b"}, ExitUsage, "unknown severity"},
		{[]string{"diff", "--show", "huge", "a", "b"}, ExitUsage, "unknown severity"},
		{[]string{"custody"}, ExitUsage, "usage"},
		{[]string{"custody", "help"}, ExitOK, "usage"},
		{[]string{"custody", "dance"}, ExitUsage, "unknown custody subcommand"},
		{[]string{"custody", "append"}, ExitUsage, "usage"},
		{[]string{"custody", "verify"}, ExitUsage, "usage"},
		{[]string{"custody", "show"}, ExitUsage, "usage"},
		{[]string{"extract", "x"}, ExitUsage, "usage"},
		{[]string{"prove", "x"}, ExitUsage, "usage"},
		{[]string{"verify-proof", filepath.Join(d, "noproof")}, ExitUsage, "no such file"},
	}
	for _, c := range cases {
		r := run(t, c.args...)
		if r.code != c.code || !strings.Contains(r.stdout+r.stderr, c.msg) {
			t.Errorf("%v: exit %d (want %d), output %q", c.args, r.code, c.code, r.stdout+r.stderr)
		}
	}
}

func TestCollectGuards(t *testing.T) {
	w := setup(t)
	// Refuses to overwrite an existing bundle.
	r := run(t, "collect", "--root", testutil.Fixture(t, "baseline"), "--out", w.base, "--key", w.collectorKey, "--case", "c", "--examiner", "e")
	if r.code != ExitUsage || !strings.Contains(r.stderr, "already exists") {
		t.Fatalf("overwrite: %d %s", r.code, r.stderr)
	}
	cfg := filepath.Join(w.dir, "bad.json")
	os.WriteFile(cfg, []byte(`{"options":{"filehash":{"workers":0}}}`), 0o600)
	out := filepath.Join(w.dir, "x.tar.zst")
	if r := run(t, "collect", "--out", out, "--key", w.collectorKey, "--case", "c", "--examiner", "e", "--config", cfg); r.code != ExitUsage {
		t.Fatal("invalid collector options accepted")
	}
	os.WriteFile(cfg, []byte(`{"timeout":"soon"}`), 0o600)
	if r := run(t, "collect", "--out", out, "--key", w.collectorKey, "--case", "c", "--examiner", "e", "--config", cfg); r.code != ExitUsage {
		t.Fatal("bad timeout accepted")
	}
	if r := run(t, "collect", "--root", testutil.Fixture(t, "macos"), "--out", out, "--key", w.collectorKey, "--case", "c",
		"--examiner", "e", "--collectors", "persistence,nope"); r.code != ExitUsage || !strings.Contains(r.stderr, "unknown collector") {
		t.Fatalf("unknown collector: %d %s", r.code, r.stderr)
	}
	r = mustOK(t, run(t, "--log-level", "debug", "--log-format", "json", "collect", "--root", testutil.Fixture(t, "macos"), "--out", out,
		"--key", w.collectorKey, "--case", "c", "--examiner", "e", "--collectors", "persistence,processes", "--parallel", "1",
		"--timeout", "30s", "--hostname", "mbp"))
	if !strings.Contains(r.stdout, "host       mbp (macOS 15.6)") || !strings.Contains(r.stdout, "processes    skipped") ||
		!strings.Contains(r.stderr, `"collector":"persistence"`) {
		t.Fatalf("macos collect:\n%s\n%s", r.stdout, r.stderr)
	}
	r = mustOK(t, run(t, "collectors"))
	if !strings.Contains(r.stdout, "persistence") || !strings.Contains(r.stdout, "[configurable]") {
		t.Fatal(r.stdout)
	}
	r = mustOK(t, run(t, "version"))
	if !strings.HasPrefix(r.stdout, "evidencelocker ") {
		t.Fatal(r.stdout)
	}
	if r := run(t, "keygen", "--out", filepath.Join(w.dir, "collector")); r.code != ExitUsage {
		t.Fatal("keygen overwrote a key")
	}
}

// The shipped example config must stay valid.
func TestExampleConfigLoads(t *testing.T) {
	cfg, err := loadConfig(filepath.Join(testutil.RepoRoot(), "configs", "collect.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := builtin.Registry().Configure(cfg.Options); err != nil {
		t.Fatal(err)
	}
	if _, err := builtin.Registry().Select(cfg.Collectors); err != nil {
		t.Fatal(err)
	}
}
