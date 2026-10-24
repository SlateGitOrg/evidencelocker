//go:build unix

package fsroot

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// within fails the test if fn has not returned after d; a regression here
// would otherwise hang the whole test binary.
func within(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("call still blocked after %s", d)
	}
}

// TestSpecialFilesNeverBlock covers the hostile-host case: an unprivileged
// user plants a named pipe (or a link to one) where a collector reads, e.g.
// `mkfifo ~/.bashrc`. Opening a FIFO for reading blocks until a writer
// appears, so the read must be refused without opening it.
func TestSpecialFilesNeverBlock(t *testing.T) {
	dir := mk(t, "etc/cron.d/", "home/u/", "home/u/.profile -> /etc/cron.d/evil", "home/u/rel -> ../../etc/cron.d/evil")
	if err := syscall.Mkfifo(filepath.Join(dir, "etc/cron.d/evil"), 0o644); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	r := open(t, dir)
	for _, p := range []string{"/etc/cron.d/evil", "/home/u/.profile", "/home/u/rel"} {
		within(t, 5*time.Second, func() {
			_, err := r.ReadFile(p, 1<<20)
			if !errors.Is(err, ErrNotRegular) || !strings.Contains(err.Error(), "named pipe") {
				t.Errorf("ReadFile(%s): %v, want ErrNotRegular naming a named pipe", p, err)
			}
		})
	}
	within(t, 5*time.Second, func() {
		if _, _, err := r.OpenRegular("/etc/cron.d/evil"); !errors.Is(err, ErrNotRegular) {
			t.Errorf("OpenRegular(fifo): %v", err)
		}
	})
}

// TestSwapToFIFOAfterCheck swaps a regular file for a FIFO between the type
// check and the open (a live-system race). The open must not block
// (O_NONBLOCK) and the post-open Stat must reject the handle.
func TestSwapToFIFOAfterCheck(t *testing.T) {
	dir := mk(t, "f=data")
	r := open(t, dir)
	full := filepath.Join(dir, "f")
	testHookAfterLstat = func(string) {
		if err := os.Remove(full); err != nil {
			t.Error(err)
		}
		if err := syscall.Mkfifo(full, 0o644); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { testHookAfterLstat = nil })
	for _, fn := range []func() error{
		func() error { _, err := r.ReadFile("/f", 0); return err },
		func() error { _, _, err := r.OpenRegular("/f"); return err },
	} {
		within(t, 5*time.Second, func() {
			if err := fn(); !errors.Is(err, ErrNotRegular) {
				t.Errorf("swapped FIFO: %v, want ErrNotRegular", err)
			}
		})
		// Restore a regular file for the next variant.
		_ = os.Remove(full)
		if err := os.WriteFile(full, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestKindNames(t *testing.T) {
	dir := mk(t, "d/", "l -> d")
	if err := syscall.Mkfifo(filepath.Join(dir, "p"), 0o644); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	r := open(t, dir)
	for name, want := range map[string]string{"d": "directory", "l": "symlink", "p": "named pipe"} {
		fi, err := r.r.Lstat(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := kind(fi.Mode()); got != want {
			t.Errorf("kind(%s)=%q want %q", name, got, want)
		}
	}
}
