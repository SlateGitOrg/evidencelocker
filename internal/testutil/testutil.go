// Package testutil holds helpers shared by collector tests.
package testutil

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/archit2501/evidencelocker/pkg/collector"
	"github.com/archit2501/evidencelocker/pkg/collectors/builtin"
	"github.com/archit2501/evidencelocker/pkg/fsroot"
	"github.com/archit2501/evidencelocker/pkg/triage"
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

// TestKey is a deterministic signing key for tests (never use outside tests).
func TestKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
}

// SealFixture collects fixture host name with all built-in collectors and
// seals it to <dir>/<name>.tar.zst using TestKey, returning the path.
func SealFixture(t testing.TB, name, dir string) string {
	t.Helper()
	out := filepath.Join(dir, name+".tar.zst")
	_, err := triage.Run(context.Background(), triage.Options{
		Root: Fixture(name), Registry: builtin.Registry(), CaseID: "IR-TEST", Examiner: "tester",
		Signer: TestKey(), Out: out, ToolVersion: "test",
		Clock: collector.FixedClock{T: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
