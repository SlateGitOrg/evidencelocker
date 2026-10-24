// Package fsroot gives collectors read-only, chroot-style access to a host
// filesystem tree that is rooted at an arbitrary directory.
//
// Collectors never touch the real filesystem directly. They receive a *Root
// and address files with host-absolute paths such as "/etc/passwd". When the
// root is "/" this is the live system; when it is a mounted image or a test
// fixture directory the same collector code runs unchanged.
//
// Symbolic links are resolved with chroot semantics: an absolute link target
// restarts resolution at the root, and ".." never climbs above it. A link can
// therefore never make a collector read a file outside the root, which matters
// both for fixtures (a fixture's "/etc/passwd" link must not read the analyst's
// own /etc/passwd) and for hostile images.
package fsroot

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
)

// maxLinkHops bounds symlink resolution, mirroring the kernel's ELOOP limit.
const maxLinkHops = 40

// ErrTooLarge is returned by ReadFile when a file exceeds the caller's limit.
var ErrTooLarge = errors.New("file exceeds size limit")

// ErrNotRegular is returned when a regular file was required.
var ErrNotRegular = errors.New("not a regular file")

// ErrTooManyLinks is returned when symlink resolution exceeds maxLinkHops.
var ErrTooManyLinks = errors.New("too many levels of symbolic links")

// Root is a read-only view of a directory tree treated as a host's "/".
// It is safe for concurrent use.
type Root struct {
	dir string
	r   *os.Root
}

// Open opens dir as a root. The directory must exist.
func Open(dir string) (*Root, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open root %q: %w", dir, err)
	}
	return &Root{dir: dir, r: r}, nil
}

// Dir returns the directory the root was opened from.
func (r *Root) Dir() string { return r.dir }

// IsLive reports whether the root is the running system's own "/".
func (r *Root) IsLive() bool { return path.Clean(r.dir) == "/" }

// Close releases the root's directory handle.
func (r *Root) Close() error { return r.r.Close() }

// Clean converts a host path ("/etc/passwd", "etc/passwd", "/a/../b") into
// the canonical host-absolute form used in records ("/etc/passwd").
func Clean(p string) string { return path.Clean("/" + p) }

// rel converts a host-absolute path into an os.Root-relative name.
func rel(p string) string {
	c := strings.TrimPrefix(Clean(p), "/")
	if c == "" {
		return "."
	}
	return c
}

// Resolve resolves every symlink in p with chroot semantics and returns the
// resulting host-absolute path. Missing trailing components are kept as-is so
// that callers get a meaningful fs.ErrNotExist from the subsequent open.
func (r *Root) Resolve(p string) (string, error) {
	pending := splitPath(Clean(p))
	resolved := make([]string, 0, len(pending))
	hops := 0
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
			continue
		}
		cand := strings.Join(append(append([]string{}, resolved...), c), "/")
		fi, err := r.r.Lstat(cand)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				resolved = append(resolved, c)
				resolved = append(resolved, pending...)
				return "/" + strings.Join(resolved, "/"), nil
			}
			return "", fmt.Errorf("resolve %s: %w", p, err)
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			resolved = append(resolved, c)
			continue
		}
		hops++
		if hops > maxLinkHops {
			return "", fmt.Errorf("resolve %s: %w", p, ErrTooManyLinks)
		}
		target, err := r.r.Readlink(cand)
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", p, err)
		}
		if path.IsAbs(target) {
			resolved = resolved[:0]
		}
		pending = append(splitPath(target), pending...)
	}
	return "/" + strings.Join(resolved, "/"), nil
}

func splitPath(p string) []string {
	parts := strings.Split(p, "/")
	out := parts[:0]
	for _, s := range parts {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Lstat returns file info for p without following a final symlink.
// Intermediate symlinks are resolved with chroot semantics.
func (r *Root) Lstat(p string) (fs.FileInfo, error) {
	dir, base := path.Split(Clean(p))
	if base == "" {
		return r.r.Lstat(".")
	}
	rd, err := r.Resolve(dir)
	if err != nil {
		return nil, err
	}
	return r.r.Lstat(rel(path.Join(rd, base)))
}

// Stat returns file info for p, following symlinks with chroot semantics.
func (r *Root) Stat(p string) (fs.FileInfo, error) {
	rp, err := r.Resolve(p)
	if err != nil {
		return nil, err
	}
	return r.r.Stat(rel(rp))
}

// Exists reports whether p exists (following symlinks).
func (r *Root) Exists(p string) bool {
	_, err := r.Stat(p)
	return err == nil
}

// Readlink returns the raw target of the symlink at p.
func (r *Root) Readlink(p string) (string, error) {
	dir, base := path.Split(Clean(p))
	rd, err := r.Resolve(dir)
	if err != nil {
		return "", err
	}
	return r.r.Readlink(rel(path.Join(rd, base)))
}

// ReadDir lists the directory at p (following symlinks), sorted by name.
func (r *Root) ReadDir(p string) ([]fs.DirEntry, error) {
	rp, err := r.Resolve(p)
	if err != nil {
		return nil, err
	}
	ents, err := fs.ReadDir(r.r.FS(), rel(rp))
	if err != nil {
		return nil, err
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	return ents, nil
}

// ReadFile reads the regular file at p (following symlinks) up to max bytes.
// A max of zero or less means no limit.
func (r *Root) ReadFile(p string, max int64) ([]byte, error) {
	rp, err := r.Resolve(p)
	if err != nil {
		return nil, err
	}
	f, err := r.r.Open(rel(rp))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("read %s: %w", p, ErrNotRegular)
	}
	var rd io.Reader = f
	if max > 0 {
		rd = io.LimitReader(f, max+1)
	}
	b, err := io.ReadAll(rd)
	if err != nil {
		return nil, err
	}
	if max > 0 && int64(len(b)) > max {
		return b[:max], fmt.Errorf("read %s: %w (%d bytes)", p, ErrTooLarge, max)
	}
	return b, nil
}

// OpenRegular opens the regular file at the exact path p without following a
// final symlink, and re-checks after opening that the handle refers to the
// same regular file that was inspected (guarding against swap races on a live
// system).
func (r *Root) OpenRegular(p string) (*os.File, fs.FileInfo, error) {
	dir, base := path.Split(Clean(p))
	rd, err := r.Resolve(dir)
	if err != nil {
		return nil, nil, err
	}
	name := rel(path.Join(rd, base))
	before, err := r.r.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("open %s: %w", p, ErrNotRegular)
	}
	f, err := r.r.Open(name)
	if err != nil {
		return nil, nil, err
	}
	after, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !os.SameFile(before, after) {
		f.Close()
		return nil, nil, fmt.Errorf("open %s: file changed during open", p)
	}
	return f, after, nil
}

// Glob matches a host path pattern whose components may contain shell
// wildcards (path.Match syntax), e.g. "/home/*/.bashrc". Matches are returned
// as host-absolute paths in lexical order. Wildcard components do not descend
// through symlinked directories, which keeps globbing bounded.
func (r *Root) Glob(pattern string) ([]string, error) {
	parts := splitPath(Clean(pattern))
	cur := []string{"/"}
	for i, part := range parts {
		last := i == len(parts)-1
		var next []string
		if !hasMeta(part) {
			for _, c := range cur {
				p := path.Join(c, part)
				if _, err := r.Lstat(p); err == nil {
					next = append(next, p)
				}
			}
			cur = next
			continue
		}
		if _, err := path.Match(part, ""); err != nil {
			return nil, fmt.Errorf("glob %q: %w", pattern, err)
		}
		for _, c := range cur {
			ents, err := r.ReadDir(c)
			if err != nil {
				continue
			}
			for _, e := range ents {
				if ok, _ := path.Match(part, e.Name()); !ok {
					continue
				}
				if !last && !e.IsDir() {
					continue
				}
				next = append(next, path.Join(c, e.Name()))
			}
		}
		cur = next
	}
	sort.Strings(cur)
	return cur, nil
}

func hasMeta(s string) bool { return strings.ContainsAny(s, `*?[\`) }

// WalkFunc is called for every entry beneath a walked directory with its
// host-absolute path. Returning fs.SkipDir skips a directory.
type WalkFunc func(hostPath string, d fs.DirEntry, err error) error

// Walk walks the tree under p in lexical order without following symlinks
// below p itself. The start directory is resolved first so that, for
// example, a merged-/usr "/bin -> usr/bin" link is walked as "/usr/bin".
// The returned string is the resolved start path.
func (r *Root) Walk(p string, fn WalkFunc) (string, error) {
	rp, err := r.Resolve(p)
	if err != nil {
		return "", err
	}
	start := rel(rp)
	err = fs.WalkDir(r.r.FS(), start, func(name string, d fs.DirEntry, err error) error {
		host := "/" + name
		if name == "." {
			host = "/"
		}
		return fn(host, d, err)
	})
	return rp, err
}
