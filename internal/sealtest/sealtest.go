// Package sealtest seals fixture hosts into bundles for tests. It is kept
// apart from testutil because it depends on the built-in collectors, whose
// own tests use testutil.
package sealtest

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/SlateGitOrg/evidencelocker/internal/testutil"
	"github.com/SlateGitOrg/evidencelocker/pkg/collector"
	"github.com/SlateGitOrg/evidencelocker/pkg/collectors/builtin"
	"github.com/SlateGitOrg/evidencelocker/pkg/triage"
)

// SealFixture collects fixture host name with all built-in collectors and
// seals it to <dir>/<name>.tar.zst using testutil.TestKey, returning the path.
func SealFixture(t testing.TB, name, dir string) string {
	t.Helper()
	out := filepath.Join(dir, name+".tar.zst")
	_, err := triage.Run(context.Background(), triage.Options{
		Root: testutil.Fixture(name), Registry: builtin.Registry(), CaseID: "IR-TEST", Examiner: "tester",
		Signer: testutil.TestKey(), Out: out, ToolVersion: "test",
		Clock: collector.FixedClock{T: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
