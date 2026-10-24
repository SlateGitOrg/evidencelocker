package filehash

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/archit2501/evidencelocker/internal/testutil"
)

func collect(t *testing.T, c *Collector, dir string) ([]File, []string, bool, map[string][]byte) {
	t.Helper()
	out, err := c.Collect(context.Background(), testutil.Env(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	var fs []File
	for _, r := range out.Records {
		fs = append(fs, r.(File))
	}
	caps := map[string][]byte{}
	for _, cp := range out.Captures {
		caps[cp.Path] = cp.Data
	}
	return fs, out.Warnings, out.Partial, caps
}

func TestCompromisedFixture(t *testing.T) {
	fs, warns, partial, caps := collect(t, New(), testutil.Fixture("compromised"))
	if partial || len(warns) != 0 {
		t.Fatalf("partial=%v warnings=%v", partial, warns)
	}
	if len(fs) != 17 {
		t.Fatalf("%d records", len(fs))
	}
	by := map[string]File{}
	for _, f := range fs {
		by[f.Path] = f
		if strings.HasPrefix(f.Path, "/bin/") || strings.HasPrefix(f.Path, "/sbin/") {
			t.Fatalf("merged-/usr link walked twice: %s", f.Path)
		}
	}
	k := by["/tmp/.cache/kworkerd"]
	data, _ := os.ReadFile(filepath.Join(testutil.Fixture("compromised"), "tmp", ".cache", "kworkerd"))
	sum := sha256.Sum256(data)
	if k.SHA256 != hex.EncodeToString(sum[:]) || !k.Executable || k.Type != "file" || k.Size != int64(len(data)) {
		t.Fatalf("kworkerd: %+v", k)
	}
	if string(caps["/tmp/.cache/kworkerd"]) != string(data) || caps["/usr/bin/ls"] != nil {
		t.Fatal("only staging-dir files are captured")
	}
	for i := 1; i < len(fs); i++ {
		if fs[i-1].Path >= fs[i].Path {
			t.Fatal("records not sorted")
		}
	}
}

func TestModesLinksAndLimits(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "usr", "bin"), 0o755))
	must(os.MkdirAll(filepath.Join(dir, "tmp"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "usr", "bin", "su"), []byte("su"), 0o755))
	must(os.Chmod(filepath.Join(dir, "usr", "bin", "su"), 0o4755|os.ModeSetuid))
	must(os.WriteFile(filepath.Join(dir, "usr", "bin", "big"), make([]byte, 2048), 0o644))
	must(os.Symlink("/usr/bin/su", filepath.Join(dir, "usr", "bin", "link")))
	must(os.WriteFile(filepath.Join(dir, "tmp", "a"), make([]byte, 100), 0o644))
	must(os.WriteFile(filepath.Join(dir, "tmp", "b"), make([]byte, 100), 0o644))
	must(os.WriteFile(filepath.Join(dir, "tmp", "huge"), make([]byte, 600), 0o644))

	c := New()
	must(c.Configure(json.RawMessage(`{"dirs":["/usr/bin","/tmp","/absent"],"max_file_size":1024,"capture_max_size":500,"capture_total":150,"workers":2}`)))
	fs, warns, _, caps := collect(t, c, dir)
	by := map[string]File{}
	for _, f := range fs {
		by[f.Path] = f
	}
	su := by["/usr/bin/su"]
	fi, _ := os.Stat(filepath.Join(dir, "usr", "bin", "su"))
	if fi.Mode()&os.ModeSetuid != 0 && (!su.Setuid || su.Mode != "4755") {
		t.Fatalf("setuid not reported: %+v", su)
	}
	if b := by["/usr/bin/big"]; b.SHA256 != "" || !strings.Contains(b.Skipped, "max_file_size") {
		t.Fatalf("big: %+v", b)
	}
	if l := by["/usr/bin/link"]; l.Type != "symlink" || l.LinkTarget != "/usr/bin/su" || l.SHA256 != "" {
		t.Fatalf("link: %+v", l)
	}
	if len(caps) != 1 || caps["/tmp/huge"] != nil {
		t.Fatalf("capture budget/size not enforced: %v", len(caps))
	}
	if !strings.Contains(strings.Join(warns, ";"), "capture budget exhausted") {
		t.Fatalf("warnings %v", warns)
	}

	lim := New()
	must(lim.Configure(json.RawMessage(`{"dirs":["/usr/bin","/tmp"],"max_files":2}`)))
	fs, warns, partial, _ := collect(t, lim, dir)
	if len(fs) != 2 || !partial || !strings.Contains(strings.Join(warns, ";"), "max_files") {
		t.Fatalf("max_files: %d %v %v", len(fs), partial, warns)
	}
}

func TestDeterministicAcrossWorkers(t *testing.T) {
	var prev string
	for _, w := range []int{1, 3, 8} {
		c := New()
		if err := c.Configure(json.RawMessage(`{"workers":` + string(rune('0'+w)) + `}`)); err != nil {
			t.Fatal(err)
		}
		fs, _, _, _ := collect(t, c, testutil.Fixture("baseline"))
		b, _ := json.Marshal(fs)
		if prev != "" && string(b) != prev {
			t.Fatalf("output differs with %d workers", w)
		}
		prev = string(b)
	}
}

func TestConfigureValidation(t *testing.T) {
	for _, bad := range []string{`{"workers":0}`, `{"max_files":-1}`, `{"max_file_size":0}`, `{"capture_total":-1}`, `{"x":1}`} {
		if err := New().Configure(json.RawMessage(bad)); err == nil {
			t.Errorf("Configure(%s) accepted", bad)
		}
	}
	c := New()
	if c.Name() != "filehash" || c.Version() == "" || c.Description() == "" {
		t.Fatal("metadata")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Collect(ctx, testutil.Env(t, testutil.Fixture("baseline"))); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestDigestIgnoresMtime(t *testing.T) {
	a := File{Path: "/x", Type: "file", SHA256: "aa", Mode: "0755"}
	b := a
	b.ModTime = b.ModTime.Add(3600e9)
	if a.Digest() != b.Digest() || a.Key() != "/x" {
		t.Fatal("mtime must not affect digest")
	}
	b.Mode = "4755"
	if a.Digest() == b.Digest() {
		t.Fatal("mode must affect digest")
	}
}
