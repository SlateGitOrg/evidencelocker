// Package testutil holds helpers shared by collector tests.
package testutil

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/SlateGitOrg/evidencelocker/internal/fixtree"
	"github.com/SlateGitOrg/evidencelocker/pkg/collector"
	"github.com/SlateGitOrg/evidencelocker/pkg/fsroot"
)

// RepoRoot returns the repository root directory.
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// Fixture materialises the committed fixture host tree name into a fresh
// temporary directory (regular files copied, symlinks recreated from
// testdata/hosts/symlinks.txt) and returns its path. The committed tree holds
// no symlinks, so tests never depend on them surviving a copy of the repo.
func Fixture(t testing.TB, name string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "hosts")
	if err := fixtree.Materialize(filepath.Join(RepoRoot(), "testdata", "hosts"), dst); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dst, name)
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
