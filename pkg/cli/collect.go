package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/archit2501/evidencelocker/pkg/keys"
	"github.com/archit2501/evidencelocker/pkg/triage"
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
	signer, err := keys.LoadPrivate(*keyPath)
	if err != nil {
		return a.fail(err)
	}
	if err := a.Registry.Configure(cfg.Options); err != nil {
		return a.fail(err)
	}
	res, err := triage.Run(ctx, triage.Options{
		Root: *root, Registry: a.Registry, Collectors: cfg.Collectors, Parallelism: cfg.Parallelism, Timeout: to,
		CaseID: *caseID, Examiner: *examiner, Hostname: *hostname, Signer: signer, Out: *out,
		CustodyLog: *logPath, Note: *note, ToolVersion: Version, Clock: a.Clock, Logger: a.Logger,
	})
	if err != nil {
		return a.fail(err)
	}
	host, runs, sealed := res.Host, res.Runs, res.Sealed
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
	fmt.Fprintf(w, "custody    %s (seal entry head %s)\n", res.CustodyLog, res.Seal.Hash)
	return ExitOK
}
