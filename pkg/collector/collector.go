// Package collector defines the plugin interface every triage collector
// implements, the registry that holds them, and the runner that executes
// them with timeouts, panic isolation and bounded parallelism.
//
// A collector inspects a host through an *fsroot.Root (never the raw
// filesystem), and returns keyed records plus optional raw file captures.
// Records are the unit of baseline diffing: Key identifies "the same thing"
// across two collections and Digest changes when that thing changes.
package collector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"time"

	"github.com/archit2501/evidencelocker/pkg/fsroot"
)

// Collector is the plugin interface. Implementations must be safe to call
// once per run; the runner never calls Collect concurrently on one instance.
type Collector interface {
	// Name is a stable identifier ([a-z0-9-]+) used for selection, the
	// bundle path collectors/<name>.json, and diff rule lookup.
	Name() string
	// Version is recorded in the manifest so analysts know which parser
	// produced a record set.
	Version() string
	// Description is a one-line human summary.
	Description() string
	// Collect inspects env.Root. Returning ErrNotApplicable (possibly
	// wrapped) marks the collector "skipped" rather than failed.
	Collect(ctx context.Context, env *Env) (*Output, error)
}

// Configurable collectors accept a JSON options object from the collection
// config file. Unknown fields must be rejected.
type Configurable interface {
	Configure(raw json.RawMessage) error
}

// Record is one keyed observation.
type Record interface {
	// Key identifies the observed object across collections.
	Key() string
	// Digest summarises the attributes whose change is meaningful.
	Digest() string
}

// Capture is a raw copy of a file embedded in the bundle under
// files/<host path>.
type Capture struct {
	Path string // host-absolute path, e.g. /etc/crontab
	Data []byte
}

// Output is what a collector returns.
type Output struct {
	Records  []Record
	Captures []Capture
	Warnings []string
	// Partial marks output that hit a configured limit or a read error and
	// is therefore known to be incomplete.
	Partial bool
}

// Warnf appends a formatted warning.
func (o *Output) Warnf(format string, args ...any) {
	o.Warnings = append(o.Warnings, fmt.Sprintf(format, args...))
}

// ErrNotApplicable signals that the root lacks what a collector needs (for
// example no /proc on a macOS host or an offline disk image).
var ErrNotApplicable = errors.New("not applicable to this root")

// Clock abstracts time so collections and tests are reproducible.
type Clock interface{ Now() time.Time }

// SystemClock is the real clock in UTC.
type SystemClock struct{}

// Now returns the current UTC time.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// FixedClock always returns T. Useful for golden tests and demos.
type FixedClock struct{ T time.Time }

// Now returns the fixed time.
func (c FixedClock) Now() time.Time { return c.T }

// Env is the read-only context passed to collectors.
type Env struct {
	Root   *fsroot.Root
	Clock  Clock
	Logger *slog.Logger
}

// DigestOf returns the hex SHA-256 of v's JSON encoding. Struct field order
// makes the encoding deterministic, so equal values give equal digests.
func DigestOf(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Records are plain data structs; failure here is a programming error.
		panic(fmt.Sprintf("collector: digest of %T: %v", v, err))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidName reports whether s is an acceptable collector name.
func ValidName(s string) bool { return nameRE.MatchString(s) }

// Registry holds collectors by name.
type Registry struct {
	m map[string]Collector
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{m: map[string]Collector{}} }

// Register adds c, rejecting invalid or duplicate names.
func (r *Registry) Register(c Collector) error {
	name := c.Name()
	if !ValidName(name) {
		return fmt.Errorf("collector name %q is invalid (want [a-z0-9-]+)", name)
	}
	if _, dup := r.m[name]; dup {
		return fmt.Errorf("collector %q already registered", name)
	}
	r.m[name] = c
	return nil
}

// MustRegister is Register that panics; intended for init-time wiring.
func (r *Registry) MustRegister(c Collector) {
	if err := r.Register(c); err != nil {
		panic(err)
	}
}

// Get returns the named collector.
func (r *Registry) Get(name string) (Collector, bool) {
	c, ok := r.m[name]
	return c, ok
}

// Names lists registered names in sorted order.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.m))
	for n := range r.m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Select returns the named collectors (all of them, sorted, when names is
// empty). Unknown names are an error.
func (r *Registry) Select(names []string) ([]Collector, error) {
	if len(names) == 0 {
		names = r.Names()
	}
	seen := map[string]bool{}
	out := make([]Collector, 0, len(names))
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		c, ok := r.m[n]
		if !ok {
			return nil, fmt.Errorf("unknown collector %q (have %v)", n, r.Names())
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

// Configure applies per-collector options from a config map keyed by
// collector name. Options for unselected collectors are ignored; options for
// unknown or non-configurable collectors are an error.
func (r *Registry) Configure(opts map[string]json.RawMessage) error {
	names := make([]string, 0, len(opts))
	for n := range opts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c, ok := r.m[n]
		if !ok {
			return fmt.Errorf("config: unknown collector %q", n)
		}
		cfg, ok := c.(Configurable)
		if !ok {
			return fmt.Errorf("config: collector %q takes no options", n)
		}
		if err := cfg.Configure(opts[n]); err != nil {
			return fmt.Errorf("config: collector %q: %w", n, err)
		}
	}
	return nil
}

// DecodeOptions strictly decodes a collector's JSON options into dst,
// rejecting unknown fields so typos in config files fail loudly.
func DecodeOptions(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("options: %w", err)
	}
	return nil
}
