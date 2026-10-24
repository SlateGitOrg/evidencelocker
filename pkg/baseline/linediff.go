package baseline

import (
	"fmt"
	"strings"
)

// LineDiff returns a minimal line diff of a -> b as "- old" / "+ new" lines
// (unchanged lines omitted), computed by longest common subsequence.
// Inputs over maxLines lines are summarised instead: LCS is O(n*m).
func LineDiff(a, b string, maxLines int) []string {
	al, bl := splitLines(a), splitLines(b)
	if len(al) > maxLines || len(bl) > maxLines {
		return []string{fmt.Sprintf("content changed (%d -> %d lines; too large to diff inline)", len(al), len(bl))}
	}
	n, m := len(al), len(bl)
	// lcs[i][j] = LCS length of al[i:], bl[j:], stored row-major.
	lcs := make([]int32, (n+1)*(m+1))
	at := func(i, j int) *int32 { return &lcs[i*(m+1)+j] }
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if al[i] == bl[j] {
				*at(i, j) = *at(i+1, j+1) + 1
			} else {
				*at(i, j) = max(*at(i+1, j), *at(i, j+1))
			}
		}
	}
	var out []string
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case al[i] == bl[j]:
			i++
			j++
		case *at(i+1, j) >= *at(i, j+1):
			out = append(out, "- "+al[i])
			i++
		default:
			out = append(out, "+ "+bl[j])
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, "- "+al[i])
	}
	for ; j < m; j++ {
		out = append(out, "+ "+bl[j])
	}
	return out
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
