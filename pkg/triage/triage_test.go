package triage_test

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SlateGitOrg/evidencelocker/internal/testutil"
	"github.com/SlateGitOrg/evidencelocker/pkg/bundle"
	"github.com/SlateGitOrg/evidencelocker/pkg/collector"
	"github.com/SlateGitOrg/evidencelocker/pkg/collectors/builtin"
	"github.com/SlateGitOrg/evidencelocker/pkg/custody"
	"github.com/SlateGitOrg/evidencelocker/pkg/fsroot"
	"github.com/SlateGitOrg/evidencelocker/pkg/triage"
)

func TestRunProducesVerifiableBundleAndLog(t *testing.T) {
	out := filepath.Join(t.TempDir(), "b.tar.zst")
	res, err := triage.Run(context.Background(), triage.Options{
		Root: testutil.Fixture(t, "compromised"), Registry: builtin.Registry(), CaseID: "C1",
		Examiner: "tester", Signer: testutil.TestKey(), Out: out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Runs) != 6 || res.Host.Hostname != "web01" || res.Host.Live || len(res.Warnings) != 0 {
		t.Fatalf("result %+v", res)
	}
	pub := testutil.TestKey().Public().(ed25519.PublicKey)
	rep, err := bundle.VerifyFile(out, bundle.VerifyOptions{TrustedKeys: []ed25519.PublicKey{pub}, ExpectFileSHA256: res.Seal.BundleSHA256})
	if err != nil || !rep.OK {
		t.Fatalf("verify: %v %v", err, rep.Findings)
	}
	crep, err := custody.VerifyFile(res.CustodyLog, custody.VerifyOptions{
		Bundle: &custody.Bundle{CaseID: "C1", FileSHA256: rep.FileSHA256, MerkleRoot: rep.MerkleRoot}, SealKeys: []ed25519.PublicKey{pub}})
	if err != nil || !crep.OK {
		t.Fatalf("custody: %v %v", err, crep.Findings)
	}
	// Second run must refuse to overwrite.
	if _, err := triage.Run(context.Background(), triage.Options{Root: testutil.Fixture(t, "baseline"), Registry: builtin.Registry(),
		CaseID: "C1", Examiner: "tester", Signer: testutil.TestKey(), Out: out}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrite: %v", err)
	}
}

func TestRunValidation(t *testing.T) {
	if _, err := triage.Run(context.Background(), triage.Options{}); err == nil {
		t.Fatal("empty options accepted")
	}
	base := triage.Options{Registry: builtin.Registry(), CaseID: "c", Examiner: "e", Signer: testutil.TestKey(), Out: filepath.Join(t.TempDir(), "x")}
	bad := base
	bad.Collectors = []string{"nope"}
	if _, err := triage.Run(context.Background(), bad); err == nil {
		t.Fatal("unknown collector")
	}
	bad = base
	bad.Root = filepath.Join(t.TempDir(), "absent")
	if _, err := triage.Run(context.Background(), bad); err == nil {
		t.Fatal("absent root")
	}
	bad = base
	bad.Root = testutil.Fixture(t, "baseline")
	bad.CustodyLog = filepath.Join(t.TempDir(), "no", "such", "dir", "log")
	if _, err := triage.Run(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "custody") {
		t.Fatalf("custody failure not reported: %v", err)
	}
}

func TestAssembleDedupesCaptures(t *testing.T) {
	mk := func(name string, caps ...collector.Capture) collector.Result {
		return collector.Result{Name: name, Version: "1", Status: collector.StatusOK, Output: &collector.Output{Captures: caps}}
	}
	items, runs, warns, err := triage.Assemble([]collector.Result{
		mk("a", collector.Capture{Path: "/etc/x", Data: []byte("1")}, collector.Capture{Path: "/bad\xff", Data: nil}),
		mk("b", collector.Capture{Path: "/etc/x", Data: []byte("1")}, collector.Capture{Path: "etc/x", Data: []byte("2")}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 || runs[0].Captures != 1 || runs[1].Captures != 0 || len(warns) != 2 {
		t.Fatalf("items=%d runs=%+v warns=%v", len(items), runs, warns)
	}
}

func TestHostInfo(t *testing.T) {
	open := func(dir string) *fsroot.Root {
		r, err := fsroot.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { r.Close() })
		return r
	}
	if h := triage.HostInfo(open(testutil.Fixture(t, "macos")), ""); h.OS != "macOS 15.6" || h.Hostname != "macos" {
		t.Fatalf("macos: %+v", h)
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "etc"), 0o755)
	os.WriteFile(filepath.Join(dir, "etc", "os-release"), []byte("NAME=x\n"), 0o644)
	if h := triage.HostInfo(open(dir), "override"); h.OS != "unknown" || h.Hostname != "override" {
		t.Fatalf("%+v", h)
	}
	if h := triage.HostInfo(open("/"), ""); !h.Live || h.Hostname == "" {
		t.Fatalf("live: %+v", h)
	}
}
