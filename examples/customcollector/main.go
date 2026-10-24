// Command customcollector shows how to extend evidencelocker with your own
// collector and diff rule without forking it: implement collector.Collector,
// register it next to the built-ins, optionally add a baseline.Rule, and
// hand the registry to the stock CLI.
//
//	go run ./examples/customcollector collect --root testdata/hosts/baseline ...
//
// Every CLI command then knows about "hosts-file": it is collected, sealed,
// verified, and diffed like a built-in.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"strings"

	"github.com/archit2501/evidencelocker/internal/cli"
	"github.com/archit2501/evidencelocker/pkg/baseline"
	"github.com/archit2501/evidencelocker/pkg/collector"
	"github.com/archit2501/evidencelocker/pkg/collectors/builtin"
)

// HostsEntry is one name -> address mapping from /etc/hosts.
type HostsEntry struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Line    int    `json:"line"`
}

// Key is the hostname being resolved.
func (h HostsEntry) Key() string { return h.Name }

// Digest changes when the name points somewhere else.
func (h HostsEntry) Digest() string { return collector.DigestOf(h.Address) }

// HostsFile collects /etc/hosts overrides, a common way to redirect update
// or telemetry endpoints.
type HostsFile struct{}

// Name implements collector.Collector.
func (HostsFile) Name() string { return "hosts-file" }

// Version implements collector.Collector.
func (HostsFile) Version() string { return "0.1.0" }

// Description implements collector.Collector.
func (HostsFile) Description() string {
	return "static name overrides from /etc/hosts (example plugin)"
}

// Collect implements collector.Collector.
func (HostsFile) Collect(_ context.Context, env *collector.Env) (*collector.Output, error) {
	out := &collector.Output{}
	b, err := env.Root.ReadFile("/etc/hosts", 1<<20)
	if errors.Is(err, fs.ErrNotExist) {
		return out, fmt.Errorf("no /etc/hosts: %w", collector.ErrNotApplicable)
	}
	if err != nil {
		return out, err
	}
	out.Captures = append(out.Captures, collector.Capture{Path: "/etc/hosts", Data: b})
	for i, line := range strings.Split(string(b), "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if _, err := netip.ParseAddr(f[0]); err != nil {
			out.Warnf("line %d: bad address %q", i+1, f[0])
			out.Partial = true
			continue
		}
		for _, name := range f[1:] {
			out.Records = append(out.Records, HostsEntry{Name: name, Address: f[0], Line: i + 1})
		}
	}
	return out, nil
}

// hostsRule ranks hosts-file changes: a new or changed override is medium.
func hostsRule(_ *baseline.Context, ch baseline.Change, key string, _, _ *collector.StoredRecord) (baseline.Finding, error) {
	sev := baseline.Medium
	if ch == baseline.Removed {
		sev = baseline.Info
	}
	return baseline.Finding{Severity: sev, Title: fmt.Sprintf("hosts override %s: %s", ch, key)}, nil
}

func newApp() *cli.App {
	reg := builtin.Registry()
	reg.MustRegister(HostsFile{})
	baseline.Rules["hosts-file"] = hostsRule
	return &cli.App{Registry: reg, Clock: collector.SystemClock{}, Stdout: os.Stdout, Stderr: os.Stderr}
}

func main() {
	os.Exit(newApp().Run(context.Background(), os.Args[1:]))
}
