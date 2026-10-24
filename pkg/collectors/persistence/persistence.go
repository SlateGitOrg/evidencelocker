// Package persistence enumerates autostart ("persistence") locations on
// Linux and macOS roots: cron, systemd units, launchd property lists, shell
// startup files, rc.local, ld.so.preload and SSH authorized_keys.
//
// Every parsed file is also captured raw into the bundle so an analyst (and
// the baseline differ) can see exact content, not just the parsed summary.
package persistence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/archit2501/evidencelocker/pkg/collector"
	"github.com/archit2501/evidencelocker/pkg/fsroot"
)

// Mechanism names.
const (
	MechCron       = "cron"
	MechCronScript = "cron-script"
	MechSystemd    = "systemd"
	MechLaunchd    = "launchd"
	MechShellRC    = "shell-rc"
	MechRCLocal    = "rc-local"
	MechLDPreload  = "ld-preload"
	MechSSHKey     = "ssh-authorized-key"
)

// Entry is one persistence item. Line-level mechanisms (cron lines, SSH keys,
// preload libraries) have Line > 0; file-level mechanisms (units, plists,
// rc files, cron scripts) have Line == 0 and are identified by their file.
type Entry struct {
	Mechanism  string   `json:"mechanism"`
	Location   string   `json:"location"`
	Line       int      `json:"line,omitempty"`
	Name       string   `json:"name,omitempty"`
	Command    string   `json:"command,omitempty"`
	User       string   `json:"user,omitempty"`
	Trigger    string   `json:"trigger,omitempty"`
	FileSHA256 string   `json:"file_sha256"`
	Notes      []string `json:"notes"`
}

// Key identifies the entry: mechanism, file, and for line-level entries the
// normalised line identity (so inserting a line above does not rename
// every line below it).
func (e Entry) Key() string {
	k := e.Mechanism + "|" + e.Location
	if e.Line > 0 || e.Name != "" {
		k += "|" + e.Name
	}
	return k
}

// Digest: file-level entries change with their file; line-level entries
// change only when the line's own meaning changes.
func (e Entry) Digest() string {
	v := struct {
		Command, User, Trigger, File string
	}{e.Command, e.User, e.Trigger, ""}
	if e.Line == 0 {
		v.File = e.FileSHA256
	}
	return collector.DigestOf(v)
}

// Options configure the collector.
type Options struct {
	// MaxFileSize caps how much of any one persistence file is read and
	// captured (default 1 MiB). Larger files are hashed by their prefix and
	// flagged partial.
	MaxFileSize int64 `json:"max_file_size"`
	// ExtraShellRC adds glob patterns to the shell startup file list.
	ExtraShellRC []string `json:"extra_shell_rc"`
}

// Collector implements collector.Collector.
type Collector struct{ opts Options }

// New returns the persistence collector with default options.
func New() *Collector { return &Collector{opts: Options{MaxFileSize: 1 << 20}} }

// Name implements collector.Collector.
func (*Collector) Name() string { return "persistence" }

// Version implements collector.Collector.
func (*Collector) Version() string { return "1.0.0" }

// Description implements collector.Collector.
func (*Collector) Description() string {
	return "autostart locations: cron, systemd, launchd, shell rc, rc.local, ld.so.preload, authorized_keys"
}

// Configure implements collector.Configurable.
func (c *Collector) Configure(raw json.RawMessage) error {
	if err := collector.DecodeOptions(raw, &c.opts); err != nil {
		return err
	}
	if c.opts.MaxFileSize <= 0 {
		return errors.New("max_file_size must be positive")
	}
	return nil
}

// scan carries per-run state shared by the mechanism scanners.
type scan struct {
	env      *collector.Env
	out      *collector.Output
	max      int64
	captured map[string]bool
}

// file is a read persistence file.
type file struct {
	path string
	data []byte
	sha  string
}

// read loads, hashes and captures a file. Missing files return ok=false
// silently; other errors become warnings.
func (s *scan) read(p string) (file, bool) {
	p = fsroot.Clean(p)
	fi, err := s.env.Root.Lstat(p)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.out.Warnf("stat %s: %v", p, err)
			s.out.Partial = true
		}
		return file{}, false
	}
	if fi.IsDir() {
		return file{}, false
	}
	b, err := s.env.Root.ReadFile(p, s.max)
	if err != nil && !errors.Is(err, fsroot.ErrTooLarge) {
		if !errors.Is(err, fs.ErrNotExist) {
			s.out.Warnf("read %s: %v", p, err)
			s.out.Partial = true
		}
		return file{}, false
	}
	if err != nil {
		s.out.Warnf("%s truncated to %d bytes", p, s.max)
		s.out.Partial = true
	}
	sum := sha256.Sum256(b)
	f := file{path: p, data: b, sha: hex.EncodeToString(sum[:])}
	if !s.captured[p] {
		s.captured[p] = true
		s.out.Captures = append(s.out.Captures, collector.Capture{Path: p, Data: b})
	}
	return f, true
}

// glob expands patterns into sorted, de-duplicated paths.
func (s *scan) glob(patterns ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, pat := range patterns {
		ms, err := s.env.Root.Glob(pat)
		if err != nil {
			s.out.Warnf("glob %s: %v", pat, err)
			continue
		}
		for _, m := range ms {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (s *scan) add(e Entry) {
	if e.Notes == nil {
		e.Notes = []string{}
	}
	s.out.Records = append(s.out.Records, e)
}

// Collect implements collector.Collector.
func (c *Collector) Collect(ctx context.Context, env *collector.Env) (*collector.Output, error) {
	s := &scan{env: env, out: &collector.Output{}, max: c.opts.MaxFileSize, captured: map[string]bool{}}
	scanners := []struct {
		name string
		fn   func(*scan)
	}{
		{"cron", scanCron},
		{"systemd", scanSystemd},
		{"launchd", scanLaunchd},
		{"shell", func(s *scan) { scanShell(s, c.opts.ExtraShellRC) }},
		{"preload", scanPreload},
		{"ssh", scanSSHKeys},
	}
	for _, sc := range scanners {
		if err := ctx.Err(); err != nil {
			s.out.Partial = true
			return s.out, fmt.Errorf("persistence %s: %w", sc.name, err)
		}
		sc.fn(s)
	}
	return s.out, nil
}
