//go:build unix

package persistence

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/archit2501/evidencelocker/internal/testutil"
	"github.com/archit2501/evidencelocker/pkg/collector"
)

// TestFIFOsAtPersistencePathsDoNotBlock reproduces the hostile-host case from
// review: any user can `mkfifo ~/.bashrc` (or plant one in a cron directory)
// and, before the fix, stall a root-run collection forever. The collector
// must return promptly, flag each special file in a warning, and still
// collect everything else.
func TestFIFOsAtPersistencePathsDoNotBlock(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"etc/cron.d", "home/u/.ssh"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "etc/crontab"), []byte("17 * * * * root /usr/bin/true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"etc/cron.d/evil", "home/u/.bashrc", "home/u/pipe"} {
		if err := syscall.Mkfifo(filepath.Join(dir, p), 0o644); err != nil {
			t.Skipf("mkfifo unsupported here: %v", err)
		}
	}
	if err := os.Symlink("/home/u/pipe", filepath.Join(dir, "home/u/.ssh/authorized_keys")); err != nil {
		t.Fatal(err)
	}

	type result struct {
		out *collector.Output
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := New().Collect(context.Background(), testutil.Env(t, dir))
		done <- result{out, err}
	}()
	var r result
	select {
	case r = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("persistence collector blocked on a FIFO")
	}
	if r.err != nil {
		t.Fatal(r.err)
	}
	if !r.out.Partial {
		t.Error("unread special files must mark the output partial")
	}
	warns := strings.Join(r.out.Warnings, "\n")
	for _, p := range []string{"/etc/cron.d/evil", "/home/u/.bashrc", "/home/u/.ssh/authorized_keys"} {
		if !strings.Contains(warns, p) {
			t.Errorf("no warning for %s in:\n%s", p, warns)
		}
	}
	for _, w := range r.out.Warnings {
		if strings.Count(w, "read ") != 1 {
			t.Errorf("warning repeats its prefix: %q", w)
		}
	}
	if strings.Count(warns, "named pipe") < 3 {
		t.Errorf("warnings should name the file type:\n%s", warns)
	}
	if len(r.out.Captures) != 1 || r.out.Captures[0].Path != "/etc/crontab" {
		t.Errorf("captures %+v, want only /etc/crontab", r.out.Captures)
	}
	found := false
	for _, rec := range r.out.Records {
		if e := rec.(Entry); e.Mechanism == MechCron && strings.Contains(e.Command, "/usr/bin/true") {
			found = true
		}
	}
	if !found {
		t.Errorf("regular crontab entry not collected alongside the FIFOs: %+v", r.out.Records)
	}
}
