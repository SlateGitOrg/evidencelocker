package baseline

import (
	"fmt"
	"io"
	"strings"
)

// WriteText renders a report for terminals and case notes.
func (r *Report) WriteText(w io.Writer, min Severity) error {
	var b strings.Builder
	fmt.Fprintf(&b, "baseline: %s (case %s, host %s, %s)\n", r.Baseline.Source, r.Baseline.CaseID, r.Baseline.Hostname, r.Baseline.CreatedAt.Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(&b, "current:  %s (case %s, host %s, %s)\n", r.Current.Source, r.Current.CaseID, r.Current.Hostname, r.Current.CreatedAt.Format("2006-01-02T15:04:05Z"))
	var counts []string
	for s := Critical; s >= Info; s-- {
		if n := r.Counts[s.String()]; n > 0 {
			counts = append(counts, fmt.Sprintf("%d %s", n, s))
		}
	}
	if len(counts) == 0 {
		counts = []string{"no differences"}
	}
	fmt.Fprintf(&b, "summary:  %s\n", strings.Join(counts, ", "))
	shown := 0
	for _, f := range r.Findings {
		if f.Severity < min {
			continue
		}
		shown++
		fmt.Fprintf(&b, "\n[%s] %s: %s\n", strings.ToUpper(f.Severity.String()), f.Collector, f.Title)
		for _, d := range f.Details {
			fmt.Fprintf(&b, "    %s\n", d)
		}
	}
	if hidden := len(r.Findings) - shown; hidden > 0 {
		fmt.Fprintf(&b, "\n(%d lower-severity findings hidden; use --show info to list all)\n", hidden)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
