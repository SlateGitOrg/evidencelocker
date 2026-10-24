// Package filehash walks key directories (system binary paths and
// world-writable staging areas by default) and records the SHA-256, size,
// mode and setuid/setgid bits of every entry. Small files in staging
// directories are captured raw because that is where dropped tools live.
package filehash

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/archit2501/evidencelocker/pkg/collector"
)

// File is one hashed directory entry.
type File struct {
	Path       string    `json:"path"`
	Type       string    `json:"type"` // file, symlink, other
	Size       int64     `json:"size"`
	Mode       string    `json:"mode"` // octal permission bits incl. setuid/setgid/sticky
	Setuid     bool      `json:"setuid,omitempty"`
	Setgid     bool      `json:"setgid,omitempty"`
	Executable bool      `json:"executable,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	LinkTarget string    `json:"link_target,omitempty"`
	ModTime    time.Time `json:"mtime"`
	Skipped    string    `json:"skipped,omitempty"`
}

// Key is the host path.
func (f File) Key() string { return f.Path }

// Digest covers content and permissions but not mtime, which is trivially
// forgeable and churns on package updates that do not change content.
func (f File) Digest() string {
	return collector.DigestOf(struct {
		Type, Mode, SHA, Link string
		Size                  int64
	}{f.Type, f.Mode, f.SHA256, f.LinkTarget, f.Size})
}

// Options configure the collector.
type Options struct {
	Dirs           []string `json:"dirs"`
	CaptureDirs    []string `json:"capture_dirs"`
	MaxFileSize    int64    `json:"max_file_size"`
	MaxFiles       int      `json:"max_files"`
	CaptureMaxSize int64    `json:"capture_max_size"`
	CaptureTotal   int64    `json:"capture_total"`
	Workers        int      `json:"workers"`
}

// DefaultOptions returns the defaults documented in docs/COLLECTORS.md.
func DefaultOptions() Options {
	w := runtime.NumCPU()
	if w > 4 {
		w = 4
	}
	return Options{
		Dirs: []string{
			"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
			"/tmp", "/var/tmp", "/dev/shm",
		},
		CaptureDirs:    []string{"/tmp", "/var/tmp", "/dev/shm"},
		MaxFileSize:    256 << 20,
		MaxFiles:       250_000,
		CaptureMaxSize: 4 << 20,
		CaptureTotal:   64 << 20,
		Workers:        w,
	}
}

// Collector implements collector.Collector.
type Collector struct{ opts Options }

// New returns the filehash collector with default options.
func New() *Collector { return &Collector{opts: DefaultOptions()} }

// Name implements collector.Collector.
func (*Collector) Name() string { return "filehash" }

// Version implements collector.Collector.
func (*Collector) Version() string { return "1.0.0" }

// Description implements collector.Collector.
func (*Collector) Description() string {
	return "SHA-256, mode and setuid bits of files in key directories; raw capture of staging dirs"
}

// Configure implements collector.Configurable. Omitted fields keep defaults.
func (c *Collector) Configure(raw json.RawMessage) error {
	if err := collector.DecodeOptions(raw, &c.opts); err != nil {
		return err
	}
	o := c.opts
	if o.MaxFileSize <= 0 || o.MaxFiles <= 0 || o.Workers <= 0 || o.CaptureMaxSize < 0 || o.CaptureTotal < 0 {
		return errors.New("limits must be positive")
	}
	return nil
}

// Collect implements collector.Collector.
func (c *Collector) Collect(ctx context.Context, env *collector.Env) (*collector.Output, error) {
	out := &collector.Output{}
	files, err := c.enumerate(ctx, env, out)
	if err != nil {
		return out, err
	}
	c.hashAll(ctx, env, files)
	captureBudget := c.opts.CaptureTotal
	for i := range files {
		f := &files[i]
		if f.err != "" {
			out.Warnf("%s: %s", f.rec.Path, f.err)
			out.Partial = true
		}
		out.Records = append(out.Records, f.rec)
		if f.capture != nil {
			if int64(len(f.capture)) <= captureBudget {
				captureBudget -= int64(len(f.capture))
				out.Captures = append(out.Captures, collector.Capture{Path: f.rec.Path, Data: f.capture})
			} else {
				out.Warnf("capture budget exhausted; %s not captured", f.rec.Path)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		out.Partial = true
		return out, err
	}
	return out, nil
}

type item struct {
	rec     File
	capture []byte
	wantCap bool
	err     string
}

// enumerate walks the configured directories (deduplicating ones that
// resolve to the same place, such as /bin -> /usr/bin) without hashing.
func (c *Collector) enumerate(ctx context.Context, env *collector.Env, out *collector.Output) ([]item, error) {
	var items []item
	seen := map[string]bool{}
	for _, dir := range c.opts.Dirs {
		resolved, err := env.Root.Resolve(dir)
		if err != nil {
			out.Warnf("resolve %s: %v", dir, err)
			continue
		}
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		capture := c.isCaptureDir(env, resolved)
		_, err = env.Root.Walk(resolved, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) && p == resolved {
					return nil // directory absent on this host
				}
				out.Warnf("walk %s: %v", p, err)
				out.Partial = true
				return nil
			}
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			if d.IsDir() {
				if p != resolved && seen[p] {
					return fs.SkipDir
				}
				return nil
			}
			if len(items) >= c.opts.MaxFiles {
				out.Partial = true
				return fs.SkipAll
			}
			fi, err := d.Info()
			if err != nil {
				return nil
			}
			items = append(items, item{rec: describe(p, fi), wantCap: capture})
			return nil
		})
		if err != nil {
			return items, fmt.Errorf("walk %s: %w", dir, err)
		}
	}
	if len(items) >= c.opts.MaxFiles {
		out.Warnf("max_files limit %d reached; later files not recorded", c.opts.MaxFiles)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].rec.Path < items[j].rec.Path })
	return items, nil
}

func (c *Collector) isCaptureDir(env *collector.Env, resolved string) bool {
	for _, d := range c.opts.CaptureDirs {
		if r, err := env.Root.Resolve(d); err == nil && (resolved == r || strings.HasPrefix(resolved, r+"/")) {
			return true
		}
	}
	return false
}

func describe(p string, fi fs.FileInfo) File {
	m := fi.Mode()
	f := File{
		Path:       p,
		Size:       fi.Size(),
		Mode:       fmt.Sprintf("%04o", unixMode(m)),
		Setuid:     m&fs.ModeSetuid != 0,
		Setgid:     m&fs.ModeSetgid != 0,
		Executable: m.IsRegular() && m.Perm()&0o111 != 0,
		ModTime:    fi.ModTime().UTC().Truncate(time.Second),
	}
	switch {
	case m.IsRegular():
		f.Type = "file"
	case m&fs.ModeSymlink != 0:
		f.Type = "symlink"
	default:
		f.Type = "other"
	}
	return f
}

// unixMode converts Go's FileMode to the classic octal permission word.
func unixMode(m fs.FileMode) uint32 {
	v := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		v |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		v |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		v |= 0o1000
	}
	return v
}

// hashAll hashes regular files with a bounded worker pool. Results are
// written in place, so output order stays deterministic.
func (c *Collector) hashAll(ctx context.Context, env *collector.Env, items []item) {
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < c.opts.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 128<<10)
			for i := range jobs {
				c.hashOne(env, &items[i], buf)
			}
		}()
	}
	for i := range items {
		if ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}

func (c *Collector) hashOne(env *collector.Env, it *item, buf []byte) {
	r := &it.rec
	switch r.Type {
	case "symlink":
		t, err := env.Root.Readlink(r.Path)
		if err != nil {
			it.err = err.Error()
		}
		r.LinkTarget = t
		return
	case "other":
		r.Skipped = "not a regular file"
		return
	}
	if r.Size > c.opts.MaxFileSize {
		r.Skipped = fmt.Sprintf("larger than max_file_size (%d bytes)", c.opts.MaxFileSize)
		return
	}
	f, fi, err := env.Root.OpenRegular(r.Path)
	if err != nil {
		it.err = err.Error()
		r.Skipped = "unreadable"
		return
	}
	defer f.Close()
	h := sha256.New()
	var dst io.Writer = h
	var capBuf *captureBuffer
	if it.wantCap && fi.Size() <= c.opts.CaptureMaxSize {
		capBuf = &captureBuffer{limit: c.opts.CaptureMaxSize}
		dst = io.MultiWriter(h, capBuf)
	}
	n, err := io.CopyBuffer(dst, io.LimitReader(f, c.opts.MaxFileSize+1), buf)
	if err != nil {
		it.err = err.Error()
		r.Skipped = "read error"
		return
	}
	if n > c.opts.MaxFileSize {
		r.Skipped = "grew beyond max_file_size while hashing"
		return
	}
	// Size is what was hashed, not the earlier stat, so it matches SHA256.
	r.Size = n
	r.SHA256 = hex.EncodeToString(h.Sum(nil))
	if capBuf != nil && !capBuf.overflow {
		it.capture = capBuf.b
	}
}

type captureBuffer struct {
	b        []byte
	limit    int64
	overflow bool
}

func (c *captureBuffer) Write(p []byte) (int, error) {
	if int64(len(c.b)+len(p)) > c.limit {
		c.overflow = true
		return len(p), nil
	}
	c.b = append(c.b, p...)
	return len(p), nil
}
