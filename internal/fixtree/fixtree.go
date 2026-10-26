// Package fixtree turns the committed fixture tree (regular files plus a
// symlink manifest) into a real host tree with symlinks. It is separate from
// package fixtures so that collector tests can use it without an import cycle.
package fixtree

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ManifestName is the file in testdata/hosts that lists every fixture
// symlink as "path -> target" (path relative to testdata/hosts). The symlinks
// themselves are not committed: copy tools that only handle regular files
// would drop them, so Materialize recreates them at test time.
const ManifestName = "symlinks.txt"

// LinkSep separates path and target in a manifest line.
const LinkSep = " -> "

// Materialize copies the committed fixture tree src (testdata/hosts) to dst
// (which must not exist) and creates the symlinks listed in src's manifest.
// Symlinks that happen to exist in src are ignored; the manifest is the
// single source of truth, so the result is identical whether or not the copy
// of the repository kept its symlinks.
func Materialize(src, dst string) error {
	if err := os.Mkdir(dst, 0o750); err != nil {
		return err
	}
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		switch {
		case rel == ".":
			return nil
		case d.Type()&fs.ModeSymlink != 0:
			return nil
		case d.IsDir():
			return os.MkdirAll(filepath.Join(dst, rel), 0o750)
		case rel == ManifestName:
			return nil
		}
		return copyFile(p, filepath.Join(dst, rel), d)
	})
	if err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(src, ManifestName))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		path, target, ok := strings.Cut(line, LinkSep)
		if !ok {
			return fmt.Errorf("%s: malformed line %q", ManifestName, line)
		}
		full := filepath.Join(dst, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			return err
		}
		if err := os.Symlink(target, full); err != nil {
			return err
		}
	}
	return sc.Err()
}

func copyFile(src, dst string, d fs.DirEntry) error {
	fi, err := d.Info()
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fi.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, fi.Mode().Perm())
}
