package processes

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SlateGitOrg/evidencelocker/internal/testutil"
	"github.com/SlateGitOrg/evidencelocker/pkg/collector"
)

func collect(t *testing.T, dir string) (*collector.Output, error) {
	t.Helper()
	return New().Collect(context.Background(), testutil.Env(t, dir))
}

func TestCompromisedFixture(t *testing.T) {
	out, err := collect(t, testutil.Fixture(t, "compromised"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Records) != 11 || out.Partial {
		t.Fatalf("records=%d partial=%v warnings=%v", len(out.Records), out.Partial, out.Warnings)
	}
	byPID := map[int]Process{}
	for _, r := range out.Records {
		p := r.(Process)
		byPID[p.PID] = p
	}
	k := byPID[4242]
	if k.Exe != "/tmp/.cache/kworkerd" || k.UID != 33 || k.PPID != 1 || k.Cwd != "/tmp/.cache" ||
		strings.Join(k.Cmdline, " ") != "/tmp/.cache/kworkerd --listen 4444" || k.StartTicks != 5242 {
		t.Fatalf("kworkerd: %+v", k)
	}
	if s := byPID[4300]; !s.ExeDeleted || s.Exe != "/tmp/.cache/stage2" {
		t.Fatalf("stage2: %+v", s)
	}
	if kt := byPID[2]; kt.Identity() != "[kthreadd]" || len(kt.Cmdline) != 0 {
		t.Fatalf("kernel thread: %+v", kt)
	}
	// Keys ignore PIDs: nginx master and worker differ by cmdline only.
	if byPID[700].Key() == byPID[701].Key() || byPID[700].Digest() == byPID[701].Digest() {
		t.Fatal("distinct nginx processes collapsed")
	}
}

func TestNotApplicableWithoutProc(t *testing.T) {
	_, err := collect(t, t.TempDir())
	if !errors.Is(err, collector.ErrNotApplicable) {
		t.Fatalf("want ErrNotApplicable, got %v", err)
	}
}

func TestBrokenProcessIsWarned(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "proc", "7"), 0o755)
	os.WriteFile(filepath.Join(dir, "proc", "7", "status"), []byte("State: S\nPPid: x\n"), 0o644)
	os.MkdirAll(filepath.Join(dir, "proc", "self"), 0o755)
	os.MkdirAll(filepath.Join(dir, "proc", "9"), 0o755) // vanished: no status
	out, err := collect(t, dir)
	if err != nil || !out.Partial || len(out.Warnings) != 1 || len(out.Records) != 0 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := New().Collect(ctx, testutil.Env(t, testutil.Fixture(t, "baseline")))
	if err == nil || !out.Partial {
		t.Fatal("cancellation ignored")
	}
}

func TestParsers(t *testing.T) {
	p, err := ParseStatus("Name:\tbash\nState:\tR (running)\nPPid:\t12\nUid:\t1000\t1000\t1000\t1000\n")
	if err != nil || p.Name != "bash" || p.State != "R" || p.PPID != 12 || p.UID != 1000 {
		t.Fatalf("%+v %v", p, err)
	}
	for _, bad := range []string{"State: R\n", "Name: x\nPPid: q\n", "Name: x\nUid:\n", "Name: x\nUid: z 1 1 1\n"} {
		if _, err := ParseStatus(bad); err == nil {
			t.Errorf("ParseStatus(%q) accepted", bad)
		}
	}
	// comm containing spaces and parentheses.
	st := "42 (weird) (name)) S 1 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1 2 3"
	if n, err := ParseStartTicks(st); err != nil || n != 98765 {
		t.Fatalf("starttime %d %v", n, err)
	}
	if _, err := ParseStartTicks("no paren"); err == nil {
		t.Fatal("missing paren")
	}
	if _, err := ParseStartTicks("1 (x) S 1"); err == nil {
		t.Fatal("short stat")
	}
	if got := ParseCmdline([]byte("a\x00b c\x00\x00")); len(got) != 2 || got[1] != "b c" {
		t.Fatalf("cmdline %q", got)
	}
}

func TestMetadata(t *testing.T) {
	c := New()
	if c.Name() != "processes" || c.Version() == "" || c.Description() == "" {
		t.Fatal("metadata")
	}
}
