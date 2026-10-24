// Package baseline compares a bundle against a known-good baseline bundle
// and reports what changed, ranked by how strongly each change suggests
// compromise: new persistence, new or replaced binaries, new listeners, new
// privileged accounts.
//
// The comparison is generic over collectors (records are matched by Key and
// compared by Digest), and per-collector rules decide severity and wording.
// Collectors without a rule still diff, at low severity, so third-party
// plugins participate without code changes here.
package baseline

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/archit2501/evidencelocker/pkg/bundle"
	"github.com/archit2501/evidencelocker/pkg/collector"
)

// Severity ranks findings.
type Severity int

// Severities, lowest first.
const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var sevNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return sevNames[s]
}

// MarshalText implements encoding.TextMarshaler.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	*s = v
	return err
}

// ParseSeverity parses a severity name.
func ParseSeverity(s string) (Severity, error) {
	for i, n := range sevNames {
		if strings.EqualFold(s, n) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want one of %s)", s, strings.Join(sevNames, ", "))
}

// Change is the kind of difference.
type Change string

// Change kinds.
const (
	Added    Change = "added"
	Removed  Change = "removed"
	Modified Change = "modified"
)

// Finding is one reported difference.
type Finding struct {
	Severity  Severity `json:"severity"`
	Collector string   `json:"collector"`
	Change    Change   `json:"change"`
	Key       string   `json:"key"`
	Title     string   `json:"title"`
	Details   []string `json:"details,omitempty"`
}

// Snapshot is the decoded, verified content of one bundle.
type Snapshot struct {
	Source     string
	CaseID     string
	Hostname   string
	CreatedAt  time.Time
	MerkleRoot string
	Collectors map[string]*collector.RecordFile
	// Files maps captured host paths (e.g. "/etc/crontab") to content.
	Files map[string][]byte
}

// FilesPrefix is where captured files live inside a bundle.
const FilesPrefix = "files"

// CollectorsPrefix is where record files live inside a bundle.
const CollectorsPrefix = "collectors/"

// LoadSnapshot verifies a bundle (refusing tampered ones) and decodes it.
func LoadSnapshot(path string, opts bundle.VerifyOptions) (*Snapshot, error) {
	b, err := bundle.Open(path, opts)
	if err != nil {
		return nil, err
	}
	return FromBundle(b)
}

// FromBundle decodes an opened bundle.
func FromBundle(b *bundle.Bundle) (*Snapshot, error) {
	ents, err := b.ReadEntries(func(p string) bool {
		return strings.HasPrefix(p, CollectorsPrefix) || strings.HasPrefix(p, FilesPrefix+"/")
	})
	if err != nil {
		return nil, err
	}
	s := &Snapshot{
		Source: b.Path, CaseID: b.Manifest.CaseID, Hostname: b.Manifest.Host.Hostname,
		CreatedAt: b.Manifest.CreatedAt, MerkleRoot: b.Head.MerkleRoot,
		Collectors: map[string]*collector.RecordFile{}, Files: map[string][]byte{},
	}
	for p, data := range ents {
		if host, ok := strings.CutPrefix(p, FilesPrefix); ok {
			s.Files[host] = data
			continue
		}
		rf, err := collector.DecodeRecordFile(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		s.Collectors[rf.Collector] = rf
	}
	return s, nil
}

// SnapshotInfo summarises a snapshot in a report.
type SnapshotInfo struct {
	Source     string    `json:"source"`
	CaseID     string    `json:"case_id"`
	Hostname   string    `json:"hostname"`
	CreatedAt  time.Time `json:"created_at"`
	MerkleRoot string    `json:"merkle_root"`
}

func (s *Snapshot) info() SnapshotInfo {
	return SnapshotInfo{s.Source, s.CaseID, s.Hostname, s.CreatedAt, s.MerkleRoot}
}

// Report is a comparison result.
type Report struct {
	Baseline SnapshotInfo   `json:"baseline"`
	Current  SnapshotInfo   `json:"current"`
	Findings []Finding      `json:"findings"`
	Counts   map[string]int `json:"counts"`
	Notes    []string       `json:"notes"`
}

// Max returns the highest severity present (Info when there are none).
func (r *Report) Max() Severity {
	m := Info
	for _, f := range r.Findings {
		if f.Severity > m {
			m = f.Severity
		}
	}
	return m
}

// AtLeast counts findings with severity >= s.
func (r *Report) AtLeast(s Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity >= s {
			n++
		}
	}
	return n
}

// Context gives rules access to both snapshots for cross-referencing.
type Context struct {
	Base, Cur *Snapshot
	known     map[string]bool
}

// Rule turns one keyed change into a finding. old is nil for Added, cur is
// nil for Removed.
type Rule func(ctx *Context, ch Change, key string, old, cur *collector.StoredRecord) (Finding, error)

// Rules maps collector name to its rule. Callers may add rules for their
// own collectors before calling Compare.
var Rules = map[string]Rule{
	"persistence": persistenceRule,
	"filehash":    filehashRule,
	"processes":   processRule,
	"sockets":     socketRule,
	"accounts":    accountRule,
	"users":       sessionRule,
}

// Compare diffs cur against base.
func Compare(base, cur *Snapshot) *Report {
	rep := &Report{Baseline: base.info(), Current: cur.info(), Findings: []Finding{}, Notes: []string{}, Counts: map[string]int{}}
	ctx := &Context{Base: base, Cur: cur}
	names := map[string]bool{}
	for n := range base.Collectors {
		names[n] = true
	}
	for n := range cur.Collectors {
		names[n] = true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		b, c := base.Collectors[name], cur.Collectors[name]
		if b == nil || c == nil {
			side := "baseline"
			if c == nil {
				side = "current bundle"
			}
			rep.Notes = append(rep.Notes, fmt.Sprintf("%s: not collected in %s; not compared", name, side))
			continue
		}
		for _, side := range []struct {
			label string
			rf    *collector.RecordFile
		}{{"baseline", b}, {"current", c}} {
			if side.rf.Status != collector.StatusOK {
				msg := fmt.Sprintf("%s: %s status is %q", name, side.label, side.rf.Status)
				if side.rf.Error != "" {
					msg += " (" + side.rf.Error + ")"
				}
				rep.Notes = append(rep.Notes, msg+"; comparison may be incomplete")
			}
		}
		rule := Rules[name]
		if rule == nil {
			rule = genericRule
		}
		diffCollector(rep, ctx, name, b, c, rule)
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Collector != b.Collector {
			return a.Collector < b.Collector
		}
		return a.Key < b.Key
	})
	for _, f := range rep.Findings {
		rep.Counts[f.Severity.String()]++
	}
	return rep
}

func group(rf *collector.RecordFile) map[string][]*collector.StoredRecord {
	m := map[string][]*collector.StoredRecord{}
	for i := range rf.Records {
		r := &rf.Records[i]
		m[r.Key] = append(m[r.Key], r)
	}
	return m
}

func digests(rs []*collector.StoredRecord) string {
	ds := make([]string, len(rs))
	for i, r := range rs {
		ds[i] = r.Digest
	}
	sort.Strings(ds)
	return strings.Join(ds, ",")
}

// diffCollector matches records by key: O(n+m) map work plus sorting keys.
func diffCollector(rep *Report, ctx *Context, name string, b, c *collector.RecordFile, rule Rule) {
	bm, cm := group(b), group(c)
	keys := make([]string, 0, len(bm)+len(cm))
	for k := range bm {
		keys = append(keys, k)
	}
	for k := range cm {
		if _, ok := bm[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		old, cur := bm[k], cm[k]
		var ch Change
		var o, n *collector.StoredRecord
		switch {
		case old == nil:
			ch, n = Added, cur[0]
		case cur == nil:
			ch, o = Removed, old[0]
		case digests(old) != digests(cur):
			ch, o, n = Modified, old[0], cur[0]
		default:
			continue
		}
		f, err := rule(ctx, ch, k, o, n)
		if err != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("%s: rule failed on %q: %v; reported generically", name, k, err))
			f, _ = genericRule(ctx, ch, k, o, n)
		}
		f.Collector, f.Change, f.Key = name, ch, k
		rep.Findings = append(rep.Findings, f)
	}
}

func genericRule(_ *Context, ch Change, key string, _, _ *collector.StoredRecord) (Finding, error) {
	sev := Low
	if ch == Removed {
		sev = Info
	}
	return Finding{Severity: sev, Title: fmt.Sprintf("%s record %s", ch, key)}, nil
}

// decode2 unmarshals the non-nil records of a change.
func decode2[T any](old, cur *collector.StoredRecord) (o, c *T, err error) {
	if old != nil {
		o = new(T)
		if err = json.Unmarshal(old.Data, o); err != nil {
			return nil, nil, err
		}
	}
	if cur != nil {
		c = new(T)
		if err = json.Unmarshal(cur.Data, c); err != nil {
			return nil, nil, err
		}
	}
	return o, c, nil
}
