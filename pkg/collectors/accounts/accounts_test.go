package accounts

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

func TestCompromisedFixture(t *testing.T) {
	out, err := New().Collect(context.Background(), testutil.Env(t, testutil.Fixture(t, "compromised")))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Records) != 9 || len(out.Captures) != 2 {
		t.Fatalf("records=%d captures=%d", len(out.Records), len(out.Captures))
	}
	by := map[string]Account{}
	for _, r := range out.Records {
		a := r.(Account)
		by[a.Name] = a
	}
	if s := by["sysupd"]; s.UID != 0 || !s.LoginShell {
		t.Fatalf("sysupd: %+v", s)
	}
	if b := by["backup"]; strings.Join(b.PrivGroups, ",") != "sudo" || b.LoginShell {
		t.Fatalf("backup: %+v", b)
	}
	if a := by["alice"]; strings.Join(a.PrivGroups, ",") != "sudo,adm" {
		t.Fatalf("alice groups in PrivilegedGroups order: %v", a.PrivGroups)
	}
}

func TestMalformedAndMissing(t *testing.T) {
	accts, bad := ParsePasswd("# comment\nroot:x:0:0:root:/root:/bin/bash\r\nshort:x:1\nnum:x:a:0::/:/bin/sh\n:x:1:1::/:/bin/sh\n")
	if len(accts) != 1 || len(bad) != 3 {
		t.Fatalf("accts=%v bad=%v", accts, bad)
	}
	g := ParseGroup("wheel:x:10:b, a ,\nbroken\n:x:1:z\n")
	if strings.Join(g["wheel"], ",") != "a,b" || len(g) != 1 {
		t.Fatalf("groups %v", g)
	}
	if _, err := New().Collect(context.Background(), testutil.Env(t, t.TempDir())); !errors.Is(err, collector.ErrNotApplicable) {
		t.Fatal("no passwd must be not applicable")
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "etc"), 0o755)
	os.WriteFile(filepath.Join(dir, "etc", "passwd"), []byte("ok:x:5:5::/:/bin/sh\nbad line\n"), 0o644)
	out, err := New().Collect(context.Background(), testutil.Env(t, dir))
	if err != nil || !out.Partial || len(out.Records) != 1 || len(out.Captures) != 1 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	a := out.Records[0].(Account)
	b := a
	b.Shell = "/bin/zsh"
	if a.Key() != b.Key() || a.Digest() == b.Digest() {
		t.Fatal("shell change must change digest only")
	}
	c := New()
	if c.Name() != "accounts" || c.Version() == "" || c.Description() == "" {
		t.Fatal("metadata")
	}
}
