package fixtures

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
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
// committed tree (content, symlink targets, executable bit - the only mode
// bit git preserves).
func TestFixturesUpToDate(t *testing.T) {
	for _, h := range Hosts {
		dir := filepath.Join(t.TempDir(), h)
		if err := Build(dir, h); err != nil {
			t.Fatal(err)
		}
		want, got := snapshot(t, dir), snapshot(t, filepath.Join("..", "..", "testdata", "hosts", h))
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
