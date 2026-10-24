package fsroot

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mk builds a tree: entries ending in "/" are dirs, "->" marks symlinks.
func mk(t *testing.T, spec ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, s := range spec {
		if name, target, ok := strings.Cut(s, " -> "); ok {
			full := filepath.Join(dir, name)
			os.MkdirAll(filepath.Dir(full), 0o755)
			if err := os.Symlink(target, full); err != nil {
				t.Fatal(err)
			}
			continue
		}
		name, content, _ := strings.Cut(s, "=")
		full := filepath.Join(dir, name)
		if strings.HasSuffix(name, "/") {
			os.MkdirAll(full, 0o755)
			continue
		}
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func open(t *testing.T, dir string) *Root {
	t.Helper()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func TestResolveChrootSemantics(t *testing.T) {
	dir := mk(t,
		"etc/passwd=fixture-passwd",
		"usr/bin/ls=ls",
		"bin -> usr/bin",
		"abs -> /etc/passwd",
		"escape -> ../../../../../../etc/passwd",
		"loop1 -> loop2",
		"loop2 -> loop1",
		"etc/alt -> ../usr/bin",
	)
	r := open(t, dir)
	cases := map[string]string{
		"/bin/ls":             "/usr/bin/ls",
		"bin/ls":              "/usr/bin/ls",
		"/abs":                "/etc/passwd",
		"/escape":             "/etc/passwd", // ".." clamps at the root
		"/etc/alt/ls":         "/usr/bin/ls",
		"/../../etc/passwd":   "/etc/passwd",
		"/missing/deeper/x":   "/missing/deeper/x",
		"/":                   "/",
		"/usr/./bin/../bin/x": "/usr/bin/x",
	}
	for in, want := range cases {
		got, err := r.Resolve(in)
		if err != nil || got != want {
			t.Errorf("Resolve(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := r.Resolve("/loop1"); !errors.Is(err, ErrTooManyLinks) {
		t.Errorf("loop: %v", err)
	}
	// Reads through escaping links stay inside the root.
	b, err := r.ReadFile("/escape", 0)
	if err != nil || string(b) != "fixture-passwd" {
		t.Fatalf("ReadFile via escaping link: %q %v", b, err)
	}
}

func TestReadFileLimits(t *testing.T) {
	r := open(t, mk(t, "big=0123456789", "d/"))
	if _, err := r.ReadFile("/big", 5); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	b, err := r.ReadFile("/big", 10)
	if err != nil || string(b) != "0123456789" {
		t.Fatalf("exact limit: %q %v", b, err)
	}
	if _, err := r.ReadFile("/d", 0); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("dir read: %v", err)
	}
	if _, err := r.ReadFile("/nope", 0); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
}

func TestStatLstatReadlinkExists(t *testing.T) {
	r := open(t, mk(t, "a/f=x", "l -> a/f", "dl -> a"))
	fi, err := r.Lstat("/l")
	if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatal("Lstat should not follow")
	}
	fi, err = r.Stat("/l")
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatal("Stat should follow")
	}
	if fi, err := r.Lstat("/dl/f"); err != nil || !fi.Mode().IsRegular() {
		t.Fatal("Lstat resolves intermediate links")
	}
	if tgt, err := r.Readlink("/l"); err != nil || tgt != "a/f" {
		t.Fatalf("Readlink: %q %v", tgt, err)
	}
	if !r.Exists("/l") || r.Exists("/missing") {
		t.Fatal("Exists")
	}
	if fi, err := r.Lstat("/"); err != nil || !fi.IsDir() {
		t.Fatal("Lstat root")
	}
	if r.IsLive() || r.Dir() == "" {
		t.Fatal("IsLive/Dir")
	}
}

func TestGlob(t *testing.T) {
	r := open(t, mk(t,
		"home/alice/.bashrc=a", "home/bob/.bashrc=b", "home/carol/notes=c",
		"home/link -> /home/alice", "etc/cron.d/a=1", "etc/cron.d/b=2",
	))
	got, err := r.Glob("/home/*/.bashrc")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/home/alice/.bashrc", "/home/bob/.bashrc"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Glob = %v, want %v", got, want)
	}
	got, _ = r.Glob("/etc/cron.d/*")
	if len(got) != 2 {
		t.Fatalf("cron.d: %v", got)
	}
	got, _ = r.Glob("/etc/cron.d/a")
	if len(got) != 1 {
		t.Fatalf("literal: %v", got)
	}
	got, _ = r.Glob("/nope/*")
	if len(got) != 0 {
		t.Fatalf("missing dir: %v", got)
	}
	if _, err := r.Glob("/home/[/x"); err == nil {
		t.Fatal("bad pattern accepted")
	}
}

func TestWalkAndReadDir(t *testing.T) {
	r := open(t, mk(t, "usr/bin/b=1", "usr/bin/a=1", "usr/bin/sub/c=1", "bin -> usr/bin", "usr/bin/link -> /etc"))
	var seen []string
	start, err := r.Walk("/bin", func(p string, d fs.DirEntry, err error) error {
		seen = append(seen, p)
		return err
	})
	if err != nil || start != "/usr/bin" {
		t.Fatalf("Walk start %q %v", start, err)
	}
	want := "/usr/bin,/usr/bin/a,/usr/bin/b,/usr/bin/link,/usr/bin/sub,/usr/bin/sub/c"
	if strings.Join(seen, ",") != want {
		t.Fatalf("walk order %v", seen)
	}
	ents, err := r.ReadDir("/bin")
	if err != nil || len(ents) != 4 || ents[0].Name() != "a" {
		t.Fatalf("ReadDir %v %v", ents, err)
	}
	if _, err := r.Walk("/", func(p string, d fs.DirEntry, err error) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRegular(t *testing.T) {
	r := open(t, mk(t, "f=data", "l -> f", "d/"))
	f, fi, err := r.OpenRegular("/f")
	if err != nil || fi.Size() != 4 {
		t.Fatal(err)
	}
	f.Close()
	if _, _, err := r.OpenRegular("/l"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("symlink must not be opened as regular: %v", err)
	}
	if _, _, err := r.OpenRegular("/d"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("dir: %v", err)
	}
	if _, _, err := r.OpenRegular("/missing"); err == nil {
		t.Fatal("missing")
	}
}

func TestOpenErrorsAndClean(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("open of absent dir succeeded")
	}
	for in, want := range map[string]string{"etc/passwd": "/etc/passwd", "/a/../b": "/b", "": "/", "//x//y/": "/x/y"} {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q)=%q want %q", in, got, want)
		}
	}
}
