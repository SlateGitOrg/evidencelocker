// Package triage is the end-to-end collection pipeline: open a root, run
// collectors, seal the results into a signed bundle, and start the custody
// log. The CLI's collect command is a thin wrapper over Run; programs that
// embed evidencelocker call it directly.
package triage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/SlateGitOrg/evidencelocker/pkg/bundle"
	"github.com/SlateGitOrg/evidencelocker/pkg/collector"
	"github.com/SlateGitOrg/evidencelocker/pkg/collectors/persistence"
	"github.com/SlateGitOrg/evidencelocker/pkg/custody"
	"github.com/SlateGitOrg/evidencelocker/pkg/fsroot"
)

// Options configure one collection.
type Options struct {
	Root        string // directory treated as the host's "/"
	Registry    *collector.Registry
	Collectors  []string // empty = all registered
	Parallelism int      // default 2
	Timeout     time.Duration
	CaseID      string
	Examiner    string // first custodian
	Hostname    string // override; default read from the root
	Signer      ed25519.PrivateKey
	Out         string // bundle path (must not exist)
	CustodyLog  string // default Out + ".custody.jsonl"
	Note        string // custody seal note
	ToolVersion string
	Clock       collector.Clock
	Logger      *slog.Logger
}

// Result describes a completed collection.
type Result struct {
	Host       bundle.Host
	Runs       []bundle.CollectorRun
	Sealed     *bundle.Sealed
	Seal       *custody.Entry
	CustodyLog string
	Warnings   []string
}

// Run collects from opts.Root and seals the bundle and custody log.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if opts.Out == "" || opts.CaseID == "" || opts.Examiner == "" || opts.Signer == nil || opts.Registry == nil {
		return nil, errors.New("triage: Out, CaseID, Examiner, Signer and Registry are required")
	}
	if opts.CustodyLog == "" {
		opts.CustodyLog = opts.Out + ".custody.jsonl"
	}
	if opts.Parallelism <= 0 {
		opts.Parallelism = 2
	}
	if opts.Clock == nil {
		opts.Clock = collector.SystemClock{}
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	for _, p := range []string{opts.Out, opts.CustodyLog} {
		if _, err := os.Lstat(p); err == nil {
			return nil, fmt.Errorf("triage: %s already exists; refusing to overwrite evidence", p)
		}
	}
	selected, err := opts.Registry.Select(opts.Collectors)
	if err != nil {
		return nil, err
	}
	// The root is recorded as given, so manifests do not leak the
	// examiner workstation's directory layout beyond what was typed.
	r, err := fsroot.Open(filepath.Clean(opts.Root))
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()

	env := &collector.Env{Root: r, Clock: opts.Clock, Logger: opts.Logger}
	started := opts.Clock.Now()
	results := collector.Run(ctx, env, selected, collector.RunOptions{Parallelism: opts.Parallelism, Timeout: opts.Timeout})
	items, runs, warnings, err := Assemble(results)
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		opts.Logger.Warn(w)
	}
	host := HostInfo(r, opts.Hostname)
	sealed, err := bundle.SealFile(opts.Out, items, bundle.SealOptions{
		CaseID: opts.CaseID, Examiner: opts.Examiner, CreatedAt: started, Host: host,
		Tool: bundle.Tool{Name: "evidencelocker", Version: opts.ToolVersion}, Collectors: runs, Signer: opts.Signer,
	})
	if err != nil {
		return nil, err
	}
	seal, err := custody.Create(opts.CustodyLog,
		custody.Bundle{CaseID: opts.CaseID, FileSHA256: sealed.FileSHA256, MerkleRoot: sealed.Head.MerkleRoot},
		custody.Signer{Name: opts.Examiner, Key: opts.Signer}, opts.Clock.Now(), opts.Note)
	if err != nil {
		return nil, fmt.Errorf("triage: bundle written but custody log failed: %w", err)
	}
	return &Result{Host: host, Runs: runs, Sealed: sealed, Seal: seal, CustodyLog: opts.CustodyLog, Warnings: warnings}, nil
}

// Assemble turns run results into bundle items and manifest summaries.
// Captured files are stored under files/<host path>; when two collectors
// capture the same path the first copy wins (identical content is the norm;
// a mismatch means the file changed mid-collection and is warned about).
func Assemble(results []collector.Result) ([]bundle.Item, []bundle.CollectorRun, []string, error) {
	var items []bundle.Item
	var runs []bundle.CollectorRun
	var warnings []string
	captured := map[string][]byte{}
	for _, res := range results {
		data, err := res.Encode()
		if err != nil {
			return nil, nil, nil, err
		}
		items = append(items, bundle.Item{Path: "collectors/" + res.Name + ".json", Data: data})
		ncap := 0
		for _, c := range res.Output.Captures {
			p := "files" + fsroot.Clean(c.Path)
			if err := bundle.ValidatePath(p); err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: capture skipped: %v", res.Name, err))
				continue
			}
			if prev, dup := captured[p]; dup {
				if !bytes.Equal(prev, c.Data) {
					warnings = append(warnings, fmt.Sprintf("%s: %s changed during collection; kept first copy", res.Name, c.Path))
				}
				continue
			}
			captured[p] = c.Data
			items = append(items, bundle.Item{Path: p, Data: c.Data})
			ncap++
		}
		runs = append(runs, bundle.CollectorRun{
			Name: res.Name, Version: res.Version, Status: string(res.Status), StartedAt: res.StartedAt.UTC(),
			DurationMS: res.Duration.Milliseconds(), Records: len(res.Output.Records), Captures: ncap,
			Warnings: len(res.Output.Warnings), Error: res.Err,
		})
	}
	return items, runs, warnings, nil
}

// HostInfo describes the collection source from the root's own files.
func HostInfo(r *fsroot.Root, override string) bundle.Host {
	h := bundle.Host{Root: r.Dir(), Live: r.IsLive(), OS: "unknown"}
	switch {
	case override != "":
		h.Hostname = override
	case h.Live:
		h.Hostname, _ = os.Hostname()
	default:
		if b, err := r.ReadFile("/etc/hostname", 4096); err == nil {
			h.Hostname = strings.TrimSpace(string(b))
		}
	}
	if h.Hostname == "" {
		h.Hostname = filepath.Base(r.Dir())
	}
	if b, err := r.ReadFile("/etc/os-release", 64<<10); err == nil {
		h.OS = osRelease(string(b))
	} else if b, err := r.ReadFile("/System/Library/CoreServices/SystemVersion.plist", 64<<10); err == nil {
		if v, err := persistence.ParsePlist(b); err == nil {
			if m, ok := v.(map[string]any); ok {
				name, _ := m["ProductName"].(string)
				ver, _ := m["ProductVersion"].(string)
				h.OS = strings.TrimSpace(name + " " + ver)
			}
		}
	} else if h.Live {
		h.OS = runtime.GOOS
	}
	return h
}

func osRelease(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return "unknown"
}
