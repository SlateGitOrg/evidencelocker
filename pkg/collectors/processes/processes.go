// Package processes collects the process table from a Linux procfs tree
// (<root>/proc). It reads only text pseudo-files and symlinks, so the same
// code runs against a live /proc or a captured fixture tree.
package processes

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/archit2501/evidencelocker/pkg/collector"
)

// Process is one row of the process table.
type Process struct {
	PID        int      `json:"pid"`
	PPID       int      `json:"ppid"`
	Name       string   `json:"name"`
	State      string   `json:"state"`
	UID        int      `json:"uid"`
	Exe        string   `json:"exe,omitempty"`
	ExeDeleted bool     `json:"exe_deleted,omitempty"`
	Cmdline    []string `json:"cmdline"`
	Cwd        string   `json:"cwd,omitempty"`
	StartTicks uint64   `json:"start_ticks"`
}

// Key identifies a process by what it runs, not by PID: PIDs churn between
// collections, executables and command lines are what an analyst diffs.
func (p Process) Key() string {
	return p.Identity() + "\x00" + strings.Join(p.Cmdline, " ")
}

// Identity is the executable path, or "[name]" for kernel threads and
// processes whose exe link is unreadable.
func (p Process) Identity() string {
	if p.Exe != "" {
		return p.Exe
	}
	return "[" + p.Name + "]"
}

// Digest covers the attributes that make two processes "the same program
// run the same way": executable, arguments and user.
func (p Process) Digest() string {
	return collector.DigestOf(struct {
		Exe     string
		Deleted bool
		Cmdline []string
		UID     int
	}{p.Exe, p.ExeDeleted, p.Cmdline, p.UID})
}

// Collector implements collector.Collector.
type Collector struct{}

// New returns the processes collector.
func New() *Collector { return &Collector{} }

// Name implements collector.Collector.
func (*Collector) Name() string { return "processes" }

// Version implements collector.Collector.
func (*Collector) Version() string { return "1.0.0" }

// Description implements collector.Collector.
func (*Collector) Description() string {
	return "process table from procfs: pid, parent, user, exe, cmdline, cwd"
}

// Collect implements collector.Collector.
func (c *Collector) Collect(ctx context.Context, env *collector.Env) (*collector.Output, error) {
	out := &collector.Output{}
	ents, err := env.Root.ReadDir("/proc")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return out, fmt.Errorf("no /proc under root: %w", collector.ErrNotApplicable)
		}
		return out, fmt.Errorf("list /proc: %w", err)
	}
	pids := make([]int, 0, len(ents))
	for _, e := range ents {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			out.Partial = true
			return out, err
		}
		p, err := ReadProcess(env, pid)
		if err != nil {
			// Processes exit mid-scan on a live host; that is expected.
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			out.Warnf("pid %d: %v", pid, err)
			out.Partial = true
			continue
		}
		out.Records = append(out.Records, *p)
	}
	return out, nil
}

// ReadProcess reads /proc/<pid> from env.Root.
func ReadProcess(env *collector.Env, pid int) (*Process, error) {
	base := fmt.Sprintf("/proc/%d", pid)
	status, err := env.Root.ReadFile(base+"/status", 1<<20)
	if err != nil {
		return nil, err
	}
	p, err := ParseStatus(string(status))
	if err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}
	p.PID = pid
	if cl, err := env.Root.ReadFile(base+"/cmdline", 1<<20); err == nil {
		p.Cmdline = ParseCmdline(cl)
	}
	if p.Cmdline == nil {
		p.Cmdline = []string{}
	}
	if exe, err := env.Root.Readlink(base + "/exe"); err == nil {
		p.Exe, p.ExeDeleted = strings.CutSuffix(exe, " (deleted)")
	}
	if cwd, err := env.Root.Readlink(base + "/cwd"); err == nil {
		p.Cwd = cwd
	}
	if st, err := env.Root.ReadFile(base+"/stat", 1<<16); err == nil {
		p.StartTicks, _ = ParseStartTicks(string(st))
	}
	return p, nil
}

// ParseStatus extracts Name, State, PPid and the real Uid from
// /proc/<pid>/status.
func ParseStatus(s string) (*Process, error) {
	p := &Process{}
	var haveName bool
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Name":
			p.Name, haveName = v, true
		case "State":
			p.State, _, _ = strings.Cut(v, " ")
		case "PPid":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("PPid %q: %w", v, err)
			}
			p.PPID = n
		case "Uid":
			f := strings.Fields(v)
			if len(f) == 0 {
				return nil, errors.New("empty Uid line")
			}
			n, err := strconv.Atoi(f[0])
			if err != nil {
				return nil, fmt.Errorf("uid %q: %w", v, err)
			}
			p.UID = n
		}
	}
	if !haveName {
		return nil, errors.New("missing Name field")
	}
	return p, nil
}

// ParseCmdline splits a NUL-separated /proc/<pid>/cmdline.
func ParseCmdline(b []byte) []string {
	s := strings.TrimRight(string(b), "\x00")
	if s == "" {
		return []string{}
	}
	return strings.Split(s, "\x00")
}

// ParseStartTicks returns field 22 (starttime) of /proc/<pid>/stat. The comm
// field may contain spaces and parentheses, so parsing starts after the last
// ')'.
func ParseStartTicks(s string) (uint64, error) {
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, errors.New("stat: no comm terminator")
	}
	f := strings.Fields(s[i+1:])
	// f[0] is field 3 (state); starttime is field 22 -> f[19].
	if len(f) < 20 {
		return 0, fmt.Errorf("stat: %d fields after comm, need 20", len(f))
	}
	return strconv.ParseUint(f[19], 10, 64)
}
