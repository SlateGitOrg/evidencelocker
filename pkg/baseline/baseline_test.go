package baseline

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/SlateGitOrg/evidencelocker/internal/sealtest"
	"github.com/SlateGitOrg/evidencelocker/internal/testutil"
	"github.com/SlateGitOrg/evidencelocker/pkg/bundle"
	"github.com/SlateGitOrg/evidencelocker/pkg/collector"
)

var (
	once       sync.Once
	base, comp *Snapshot
	loadErr    error
	dir        string
)

func TestMain(m *testing.M) {
	var err error
	if dir, err = os.MkdirTemp("", "baseline-test-"); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func trusted() bundle.VerifyOptions {
	return bundle.VerifyOptions{TrustedKeys: []ed25519.PublicKey{testutil.TestKey().Public().(ed25519.PublicKey)}}
}

func snapshots(t *testing.T) (*Snapshot, *Snapshot) {
	t.Helper()
	once.Do(func() {
		b := sealtest.SealFixture(t, "baseline", dir)
		c := sealtest.SealFixture(t, "compromised", dir)
		if base, loadErr = LoadSnapshot(b, trusted()); loadErr != nil {
			return
		}
		comp, loadErr = LoadSnapshot(c, trusted())
	})
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	return base, comp
}

func titles(rep *Report, sev Severity) []string {
	var out []string
	for _, f := range rep.Findings {
		if f.Severity == sev {
			out = append(out, f.Collector+": "+f.Title)
		}
	}
	return out
}

// TestCompromisedVsBaseline is the headline baseline-diff test: every
// planted change in the compromised fixture must surface at the expected
// severity, and nothing benign may be reported above low.
func TestCompromisedVsBaseline(t *testing.T) {
	b, c := snapshots(t)
	rep := Compare(b, c)
	want := map[Severity][]string{
		Critical: {
			"accounts: new UID 0 account sysupd",
			"persistence: new cron persistence in /etc/cron.d/sysupdate",
			"persistence: new cron persistence in /var/spool/cron/crontabs/www-data",
			"persistence: new ld-preload persistence in /etc/ld.so.preload",
			"persistence: new ssh-authorized-key persistence in /home/alice/.ssh/authorized_keys",
			"persistence: new systemd persistence in /etc/systemd/system/dbus-org.freedesktop.helper.service",
		},
		High: {
			"accounts: account added to privileged group: backup",
			"filehash: new executable in world-writable directory: /tmp/.cache/kworkerd",
			"filehash: binary replaced: /usr/bin/ls",
			"persistence: shell-rc persistence changed in /root/.bashrc",
			"processes: process running from world-writable directory: /tmp/.cache/kworkerd",
			"processes: process running from a deleted executable: /tmp/.cache/stage2",
			"sockets: new listener owned by a binary in a world-writable directory: tcp/0.0.0.0:4444",
		},
		Medium: {"filehash: new binary /usr/local/bin/sysupdate"},
		Low:    {"filehash: new file /tmp/.cache/notes.txt", "users: session added: sysupd@pts/1"},
	}
	for sev, w := range want {
		if got := titles(rep, sev); strings.Join(got, "\n") != strings.Join(w, "\n") {
			t.Errorf("%s findings:\n got: %q\nwant: %q", sev, got, w)
		}
	}
	if len(rep.Findings) != 16 || rep.Max() != Critical || rep.AtLeast(High) != 13 || len(rep.Notes) != 0 {
		t.Fatalf("findings=%d max=%s >=high=%d notes=%v", len(rep.Findings), rep.Max(), rep.AtLeast(High), rep.Notes)
	}
	// The changed rc file is shown as an exact line diff from the captures.
	for _, f := range rep.Findings {
		if f.Key == "shell-rc|/root/.bashrc" {
			if len(f.Details) != 1 || !strings.HasPrefix(f.Details[0], "+ export PROMPT_COMMAND=") {
				t.Fatalf("rc diff: %v", f.Details)
			}
		}
	}
}

func TestIdenticalAndReversed(t *testing.T) {
	b, c := snapshots(t)
	if rep := Compare(b, b); len(rep.Findings) != 0 || rep.Max() != Info {
		t.Fatalf("self-compare: %v", rep.Findings)
	}
	// Reversed: everything planted is now "removed", which is low/info.
	rep := Compare(c, b)
	// Only modifications stay serious when reversed: a file whose content
	// differs is suspicious in either direction.
	want := "filehash: binary replaced: /usr/bin/ls|persistence: shell-rc persistence changed in /root/.bashrc"
	if got := strings.Join(titles(rep, High), "|"); got != want || rep.AtLeast(Medium) != 2 {
		t.Fatalf("reverse high findings %q, >=medium %d", got, rep.AtLeast(Medium))
	}
	for _, f := range rep.Findings {
		if f.Change == Added {
			t.Fatalf("reverse comparison reported an addition: %+v", f)
		}
	}
}

func TestTextAndJSONRendering(t *testing.T) {
	b, c := snapshots(t)
	rep := Compare(b, c)
	var buf bytes.Buffer
	if err := rep.WriteText(&buf, High); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"summary:  6 critical, 7 high, 1 medium, 2 low", "[CRITICAL] accounts: new UID 0 account sysupd", "3 lower-severity findings hidden"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(raw, &back); err != nil || back.Findings[0].Severity != Critical {
		t.Fatalf("json round trip: %v", err)
	}
	empty := &Report{Counts: map[string]int{}}
	buf.Reset()
	empty.WriteText(&buf, Info)
	if !strings.Contains(buf.String(), "no differences") {
		t.Fatal("empty summary")
	}
}

func TestSeverityParsing(t *testing.T) {
	for i, n := range []string{"info", "LOW", "Medium", "high", "critical"} {
		s, err := ParseSeverity(n)
		if err != nil || int(s) != i {
			t.Fatalf("%s: %v", n, err)
		}
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Fatal("bad severity accepted")
	}
	var s Severity
	if err := s.UnmarshalText([]byte("nope")); err == nil {
		t.Fatal("UnmarshalText accepted junk")
	}
	if Severity(9).String() != "severity(9)" {
		t.Fatal("out-of-range String")
	}
}

func TestTamperedBundleRefused(t *testing.T) {
	snapshots(t)
	_, err := LoadSnapshot(dir+"/does-not-exist.tar.zst", trusted())
	if err == nil {
		t.Fatal("missing bundle loaded")
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
	_, err = LoadSnapshot(dir+"/baseline.tar.zst", bundle.VerifyOptions{TrustedKeys: []ed25519.PublicKey{other}})
	if !errors.Is(err, bundle.ErrNotVerified) {
		t.Fatalf("untrusted bundle loaded: %v", err)
	}
}

// Collectors unknown to the rule table still diff generically, and
// collectors present on only one side are noted, not silently skipped.
func TestGenericAndMissingCollectors(t *testing.T) {
	mk := func(recs ...collector.StoredRecord) *collector.RecordFile {
		return &collector.RecordFile{Collector: "custom", Status: collector.StatusOK, Records: recs}
	}
	r := func(k, d string) collector.StoredRecord {
		return collector.StoredRecord{Key: k, Digest: d, Data: json.RawMessage(`{}`)}
	}
	b := &Snapshot{Collectors: map[string]*collector.RecordFile{"custom": mk(r("a", "1"), r("b", "1")), "onlybase": mk()}}
	c := &Snapshot{Collectors: map[string]*collector.RecordFile{"custom": mk(r("b", "2"), r("c", "1"))}}
	c.Collectors["custom"].Status = collector.StatusPartial
	c.Collectors["custom"].Error = "limit"
	rep := Compare(b, c)
	if len(rep.Findings) != 3 || rep.Findings[0].Severity != Low || len(rep.Notes) != 2 {
		t.Fatalf("findings %+v notes %v", rep.Findings, rep.Notes)
	}
	// A rule that fails falls back to the generic rule, with a note.
	bad := &Snapshot{Collectors: map[string]*collector.RecordFile{"accounts": {Collector: "accounts", Status: collector.StatusOK,
		Records: []collector.StoredRecord{{Key: "x", Digest: "1", Data: json.RawMessage(`not json`)}}}}}
	empty := &Snapshot{Collectors: map[string]*collector.RecordFile{"accounts": {Collector: "accounts", Status: collector.StatusOK}}}
	rep = Compare(empty, bad)
	if len(rep.Findings) != 1 || len(rep.Notes) != 1 || !strings.Contains(rep.Notes[0], "rule failed") {
		t.Fatalf("fallback: %+v %v", rep.Findings, rep.Notes)
	}
}

func TestLineDiff(t *testing.T) {
	got := LineDiff("a\nb\nc\n", "a\nx\nc\nd\n", 100)
	if strings.Join(got, "|") != "- b|+ x|+ d" {
		t.Fatalf("diff %q", got)
	}
	if got := LineDiff("", "", 10); len(got) != 0 {
		t.Fatal("empty diff")
	}
	if got := LineDiff("a\nb\n", "", 10); strings.Join(got, "|") != "- a|- b" {
		t.Fatalf("deletion %q", got)
	}
	if got := LineDiff(strings.Repeat("x\n", 20), "y\n", 10); !strings.Contains(got[0], "too large") {
		t.Fatal("cap")
	}
}
