// Package cli implements the evidencelocker command line. It is a thin
// layer over the pkg/ libraries: argument parsing, output formatting and
// exit codes live here, all forensic logic lives in the libraries.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/archit2501/evidencelocker/pkg/collector"
	"github.com/archit2501/evidencelocker/pkg/collectors/builtin"
)

// Version is the tool version recorded in manifests (overridable with
// -ldflags "-X github.com/archit2501/evidencelocker/internal/cli.Version=...").
var Version = "0.1.0"

// Exit codes.
const (
	ExitOK       = 0
	ExitFindings = 1 // verification failed or diff found changes at/above threshold
	ExitUsage    = 2 // bad arguments, unreadable input, internal error
)

// App is one CLI invocation's dependencies. Embedders construct it with
// their own Registry to ship extra collectors (see examples/customcollector).
type App struct {
	Registry *collector.Registry
	Clock    collector.Clock
	Stdout   io.Writer
	Stderr   io.Writer
	Logger   *slog.Logger
}

// Main runs the CLI with built-in collectors and returns the exit code.
func Main(args []string) int {
	app := &App{Registry: builtin.Registry(), Clock: collector.SystemClock{}, Stdout: os.Stdout, Stderr: os.Stderr}
	return app.Run(context.Background(), args)
}

type command struct {
	name    string
	summary string
	run     func(a *App, ctx context.Context, args []string) int
}

func commands() []command {
	return []command{
		{"keygen", "generate an ed25519 key pair (PEM)", (*App).cmdKeygen},
		{"collectors", "list available collectors", (*App).cmdCollectors},
		{"collect", "run collectors against a root and seal a signed bundle + custody log", (*App).cmdCollect},
		{"verify", "verify a bundle (and optionally its custody log); report precise tampering", (*App).cmdVerify},
		{"inspect", "verify and summarise a bundle's manifest", (*App).cmdInspect},
		{"extract", "extract one verified entry from a bundle", (*App).cmdExtract},
		{"diff", "compare a bundle against a known-good baseline bundle", (*App).cmdDiff},
		{"custody", "append to, verify or show a custody log (custody help for details)", (*App).cmdCustody},
		{"prove", "export a Merkle inclusion proof for one entry", (*App).cmdProve},
		{"verify-proof", "check an inclusion proof (optionally against the file content)", (*App).cmdVerifyProof},
		{"version", "print the version", (*App).cmdVersion},
	}
}

// Run executes args (without the program name).
func (a *App) Run(ctx context.Context, args []string) int {
	gfs := flag.NewFlagSet("evidencelocker", flag.ContinueOnError)
	gfs.SetOutput(a.Stderr)
	level := gfs.String("log-level", "warn", "log level: debug, info, warn, error")
	format := gfs.String("log-format", "text", "log format: text or json")
	gfs.Usage = func() { a.usage() }
	if err := gfs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if a.Logger == nil {
		lg, err := newLogger(a.Stderr, *level, *format)
		if err != nil {
			fmt.Fprintln(a.Stderr, "error:", err)
			return ExitUsage
		}
		a.Logger = lg
	}
	rest := gfs.Args()
	if len(rest) == 0 {
		a.usage()
		return ExitUsage
	}
	if rest[0] == "help" || rest[0] == "-h" {
		a.usage()
		return ExitOK
	}
	for _, c := range commands() {
		if c.name == rest[0] {
			return c.run(a, ctx, rest[1:])
		}
	}
	fmt.Fprintf(a.Stderr, "error: unknown command %q\n", rest[0])
	a.usage()
	return ExitUsage
}

func (a *App) usage() {
	fmt.Fprintln(a.Stderr, "usage: evidencelocker [--log-level L] [--log-format text|json] <command> [flags] [args]")
	fmt.Fprintln(a.Stderr, "\ncommands:")
	for _, c := range commands() {
		fmt.Fprintf(a.Stderr, "  %-13s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(a.Stderr, "\nrun 'evidencelocker <command> -h' for command flags")
}

func newLogger(w io.Writer, level, format string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("--log-level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: l}
	switch format {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	}
	return nil, fmt.Errorf("--log-format %q: want text or json", format)
}

// newFlags returns a flag set whose errors and help go to stderr.
func (a *App) newFlags(name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(a.Stderr, "usage: evidencelocker %s %s\n", name, usage)
		fs.PrintDefaults()
	}
	return fs
}

// parse parses flags that may be interspersed with positional arguments
// and checks the positional count.
func (a *App) parse(fs *flag.FlagSet, args []string, minPos, maxPos int) ([]string, int, bool) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, ExitOK, false
			}
			return nil, ExitUsage, false
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	if len(pos) < minPos || (maxPos >= 0 && len(pos) > maxPos) {
		fmt.Fprintf(a.Stderr, "error: %s: wrong number of arguments\n", fs.Name())
		fs.Usage()
		return nil, ExitUsage, false
	}
	return pos, 0, true
}

func (a *App) fail(err error) int {
	fmt.Fprintln(a.Stderr, "error:", err)
	return ExitUsage
}

func (a *App) printJSON(v any) int {
	enc := json.NewEncoder(a.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return a.fail(err)
	}
	return ExitOK
}

// listFlag collects a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

// Set implements flag.Value.
func (l *listFlag) Set(s string) error {
	*l = append(*l, s)
	return nil
}

func (a *App) cmdVersion(_ context.Context, args []string) int {
	fs := a.newFlags("version", "")
	if _, code, ok := a.parse(fs, args, 0, 0); !ok {
		return code
	}
	fmt.Fprintf(a.Stdout, "evidencelocker %s\n", Version)
	return ExitOK
}

func (a *App) cmdCollectors(_ context.Context, args []string) int {
	fs := a.newFlags("collectors", "")
	if _, code, ok := a.parse(fs, args, 0, 0); !ok {
		return code
	}
	names := a.Registry.Names()
	sort.Strings(names)
	for _, n := range names {
		c, _ := a.Registry.Get(n)
		_, cfg := c.(collector.Configurable)
		opt := ""
		if cfg {
			opt = " [configurable]"
		}
		fmt.Fprintf(a.Stdout, "%-12s %-6s %s%s\n", n, c.Version(), c.Description(), opt)
	}
	return ExitOK
}
