package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRoot(t *testing.T, hosts string) string {
	t.Helper()
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc", "hosts"), []byte(hosts), 0o644)
	return root
}

func TestPluginThroughStockCLI(t *testing.T) {
	d := t.TempDir()
	app := newApp()
	var out, errb bytes.Buffer
	app.Stdout, app.Stderr = &out, &errb
	run := func(args ...string) int {
		out.Reset()
		errb.Reset()
		return app.Run(context.Background(), args)
	}
	if code := run("keygen", "--out", filepath.Join(d, "k")); code != 0 {
		t.Fatal(errb.String())
	}
	clean := writeRoot(t, "127.0.0.1 localhost\n::1 localhost ip6-localhost\n")
	dirty := writeRoot(t, "127.0.0.1 localhost\n::1 localhost ip6-localhost\n203.0.113.50 updates.example.com # injected\nnot-an-ip x\n")
	for _, c := range []struct{ name, root string }{{"a", clean}, {"b", dirty}} {
		name, root := c.name, c.root
		if code := run("collect", "--root", root, "--out", filepath.Join(d, name+".tar.zst"), "--key", filepath.Join(d, "k.key"),
			"--case", "EX", "--examiner", "examples", "--collectors", "hosts-file"); code != 0 {
			t.Fatalf("collect %s: %s", name, errb.String())
		}
	}
	if !strings.Contains(out.String(), "hosts-file   partial") {
		t.Fatalf("bad line must make the run partial:\n%s", out.String())
	}
	code := run("diff", filepath.Join(d, "a.tar.zst"), filepath.Join(d, "b.tar.zst"))
	if code != 1 || !strings.Contains(out.String(), "[MEDIUM] hosts-file: hosts override added: updates.example.com") {
		t.Fatalf("diff exit %d:\n%s%s", code, out.String(), errb.String())
	}
	if code := run("collectors"); code != 0 || !strings.Contains(out.String(), "hosts-file") {
		t.Fatal("plugin not listed")
	}
	if code := run("collect", "--root", t.TempDir(), "--out", filepath.Join(d, "c.tar.zst"), "--key", filepath.Join(d, "k.key"),
		"--case", "EX", "--examiner", "examples", "--collectors", "hosts-file"); code != 0 || !strings.Contains(out.String(), "skipped") {
		t.Fatalf("missing hosts file must be skipped: %s", out.String())
	}
}
