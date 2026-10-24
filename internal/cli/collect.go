package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/archit2501/evidencelocker/pkg/bundle"
	"github.com/archit2501/evidencelocker/pkg/collector"
	"github.com/archit2501/evidencelocker/pkg/collectors/persistence"
	"github.com/archit2501/evidencelocker/pkg/custody"
	"github.com/archit2501/evidencelocker/pkg/fsroot"
	"github.com/archit2501/evidencelocker/pkg/keys"
)

// Config is the optional --config file for collect.
type Config struct {
	Collectors  []string                   `json:"collectors"`
	Parallelism int                        `json:"parallelism"`
	Timeout     string                     `json:"timeout"`
	Options     map[string]json.RawMessage `json:"options"`
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &c, nil
}

func (a *App) cmdCollect(ctx context.Context, args []string) int {
	fs := a.newFlags("collect", "--root DIR --out FILE.tar.zst --key KEY --case ID --examiner NAME [flags]")
	root := fs.String("root", "/", "filesystem root to collect from (a mounted image or fixture tree)")
	out := fs.String("out", "", "bundle path to create (must not exist)")
	keyPath := fs.String("key", "", "ed25519 private key (PEM) that seals the bundle and the custody log")
	caseID := fs.String("case", "", "case identifier recorded in the manifest and custody log")
	examiner := fs.String("examiner", "", "collecting examiner (first custodian)")
	logPath := fs.String("custody", "", "custody log path (default: <out>.custody.jsonl)")
	only := fs.String("collectors", "", "comma-separated collectors to run (default: all)")
	cfgPath := fs.String("config", "", "JSON config file with collector options")
	parallel := fs.Int("parallel", 0, "collectors to run concurrently (default 2)")
	timeout := fs.Duration("timeout", 0, "per-collector timeout (default 10m)")
	hostname := fs.String("hostname", "", "override the recorded hostname")
	note := fs.String("note", "", "note recorded in the custody seal entry")
	if _, code, ok := a.parse(fs, args, 0, 0); !ok {
		return code
	}
	if *out == "" || *keyPath == "" || *caseID == "" || *examiner == "" {
		fmt.Fprintln(a.Stderr, "error: collect requires --out, --key, --case and --examiner")
		fs.Usage()
		return ExitUsage
	}
	cfg := &Config{}
	if *cfgPath != "" {
		var err error
		if cfg, err = loadConfig(*cfgPath); err != nil {
			return a.fail(err)
		}
	}
	if *only != "" {
		cfg.Collectors = strings.Split(*only, ",")
	}
	if *parallel > 0 {
		cfg.Parallelism = *parallel
	}
	if cfg.Parallelism == 0 {
		cfg.Parallelism = 2
	}
	to := 10 * time.Minute
	if cfg.Timeout != "" {
		d, err := time.ParseDuration(cfg.Timeout)
		if err != nil {
			return a.fail(fmt.Errorf("config timeout: %w", err))
		}
		to = d
	}
	if *timeout > 0 {
		to = *timeout
	}
	if *logPath == "" {
		*logPath = *out + ".custody.jsonl"
	}
	for _, p := range []string{*out, *logPath} {
		if _, err := os.Lstat(p); err == nil {
			return a.fail(fmt.Errorf("%s already exists; refusing to overwrite evidence", p))
		}
	}
	signer, err := keys.LoadPrivate(*keyPath)
	if err != nil {
		return a.fail(err)
	}
	if err := a.Registry.Configure(cfg.Options); err != nil {
		return a.fail(err)
	}
	selected, err := a.Registry.Select(cfg.Collectors)
	if err != nil {
		return a.fail(err)
	}
	// The root is recorded as given, so manifests do not leak the
	// examiner workstation's directory layout beyond what was typed.
	r, err := fsroot.Open(filepath.Clean(*root))
	if err != nil {
		return a.fail(err)
	}
	defer func() { _ = r.Close() }()

	env := &collector.Env{Root: r, Clock: a.Clock, Logger: a.Logger}
	started := a.Clock.Now()
	results := collector.Run(ctx, env, selected, collector.RunOptions{Parallelism: cfg.Parallelism, Timeout: to})
	items, runs, warnings, err := assemble(results)
	if err != nil {
		return a.fail(err)
	}
	for _, w := range warnings {
		a.Logger.Warn(w)
	}
	host := hostInfo(r, *hostname)
	sealed, err := bundle.SealFile(*out, items, bundle.SealOptions{
		CaseID: *caseID, Examiner: *examiner, CreatedAt: started, Host: host,
		Tool: bundle.Tool{Name: "evidencelocker", Version: Version}, Collectors: runs, Signer: signer,
	})
	if err != nil {
		return a.fail(err)
	}
	seal, err := custody.Create(*logPath,
		custody.Bundle{CaseID: *caseID, FileSHA256: sealed.FileSHA256, MerkleRoot: sealed.Head.MerkleRoot},
		custody.Signer{Name: *examiner, Key: signer}, a.Clock.Now(), *note)
	if err != nil {
		return a.fail(fmt.Errorf("bundle written but custody log failed: %w", err))
	}

	w := a.Stdout
	fmt.Fprintf(w, "host       %s (%s) root=%s live=%v\n", host.Hostname, host.OS, host.Root, host.Live)
	fmt.Fprintf(w, "collectors\n")
	for _, run := range runs {
		line := fmt.Sprintf("  %-12s %-8s %5d records %4d captures %3d warnings",
			run.Name, run.Status, run.Records, run.Captures, run.Warnings)
		if run.Error != "" {
			line += "  (" + run.Error + ")"
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintf(w, "bundle     %s (%d bytes, %d entries)\n", *out, sealed.FileSize, len(sealed.Manifest.Entries))
	fmt.Fprintf(w, "sha256     %s\n", sealed.FileSHA256)
	fmt.Fprintf(w, "merkle     %s\n", sealed.Head.MerkleRoot)
	fmt.Fprintf(w, "signed by  %s\n", sealed.Head.KeyID)
	fmt.Fprintf(w, "custody    %s (seal entry head %s)\n", *logPath, seal.Hash)
	return ExitOK
}

// assemble turns run results into bundle items and manifest summaries.
// Captured files are stored under files/<host path>; when two collectors
// capture the same path the first copy wins (identical content is the norm;
// a mismatch means the file changed mid-collection and is warned about).
func assemble(results []collector.Result) ([]bundle.Item, []bundle.CollectorRun, []string, error) {
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

// hostInfo describes the collection source from the root's own files.
func hostInfo(r *fsroot.Root, override string) bundle.Host {
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
