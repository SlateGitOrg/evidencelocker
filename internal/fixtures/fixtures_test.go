package fixtures

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/SlateGitOrg/evidencelocker/internal/fixtree"
)

type entry struct {
	link string
	data []byte
	exec bool
	dir  bool
}

func snapshot(t *testing.T, root string) map[string]entry {
	t.Helper()
	out := map[string]entry{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			l, lerr := os.Readlink(p)
			if lerr != nil {
				return lerr
			}
			out[rel] = entry{link: l}
		case d.IsDir():
			out[rel] = entry{dir: true}
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			fi, _ := d.Info()
			out[rel] = entry{data: b, exec: fi.Mode().Perm()&0o100 != 0}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestFixturesUpToDate regenerates every fixture and compares it with the
// committed tree after Materialize (content, symlink targets, executable bit - the only mode
// bit git preserves).
func TestFixturesUpToDate(t *testing.T) {
	committed := filepath.Join(t.TempDir(), "hosts")
	if err := fixtree.Materialize(filepath.Join("..", "..", "testdata", "hosts"), committed); err != nil {
		t.Fatal(err)
	}
	for _, h := range Hosts {
		dir := filepath.Join(t.TempDir(), h)
		if err := Build(dir, h); err != nil {
			t.Fatal(err)
		}
		want, got := snapshot(t, dir), snapshot(t, filepath.Join(committed, h))
		for p, w := range want {
			g, ok := got[p]
			if !ok {
				t.Errorf("%s: %s missing from testdata (run make fixtures)", h, p)
				continue
			}
			if g.link != w.link || g.dir != w.dir || g.exec != w.exec || !bytes.Equal(g.data, w.data) {
				t.Errorf("%s: %s differs from generator (run make fixtures)", h, p)
			}
		}
		for p := range got {
			if _, ok := want[p]; !ok {
				t.Errorf("%s: %s in testdata but not generated", h, p)
			}
		}
	}
	if err := Build(filepath.Join(t.TempDir(), "x"), "nope"); err == nil {
		t.Fatal("unknown fixture accepted")
	}
}

func TestMaterializeAndExport(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "x")
	if err := Export(dir); err != nil {
		t.Fatal(err)
	}
	if err := Export(dir); err == nil {
		t.Fatal("Export into existing dir accepted")
	}
	for p, e := range snapshot(t, dir) {
		if e.link != "" {
			t.Errorf("Export left symlink %s", p)
		}
	}
	out := filepath.Join(t.TempDir(), "y")
	if err := fixtree.Materialize(dir, out); err != nil {
		t.Fatal(err)
	}
	if err := fixtree.Materialize(dir, out); err == nil {
		t.Fatal("Materialize into existing dir accepted")
	}
	if l, err := os.Readlink(filepath.Join(out, "baseline", "bin")); err != nil || l != "usr/bin" {
		t.Fatalf("baseline/bin = %q, %v", l, err)
	}
	if err := fixtree.Materialize(filepath.Join(t.TempDir(), "none"), filepath.Join(t.TempDir(), "z")); err == nil {
		t.Fatal("missing source accepted")
	}
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, fixtree.ManifestName), []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fixtree.Materialize(bad, filepath.Join(t.TempDir(), "z")); err == nil {
		t.Fatal("malformed manifest accepted")
	}
	// a stray symlink in the source is ignored: the manifest is authoritative.
	stray := t.TempDir()
	if err := os.WriteFile(filepath.Join(stray, fixtree.ManifestName), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(stray, "s")); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "z")
	if err := fixtree.Materialize(stray, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "s")); err == nil {
		t.Fatal("stray symlink copied")
	}
}
