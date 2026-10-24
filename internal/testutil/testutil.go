// Package testutil holds helpers shared by collector tests.
package testutil

import (
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/archit2501/evidencelocker/pkg/collector"
	"github.com/archit2501/evidencelocker/pkg/fsroot"
)

// RepoRoot returns the repository root directory.
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// Fixture returns the path of a committed fixture host tree.
func Fixture(name string) string {
	return filepath.Join(RepoRoot(), "testdata", "hosts", name)
}

// Env opens dir as a collection root with a fixed clock and silent logger.
func Env(t testing.TB, dir string) *collector.Env {
	t.Helper()
	r, err := fsroot.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return &collector.Env{
		Root:   r,
		Clock:  collector.FixedClock{T: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}
