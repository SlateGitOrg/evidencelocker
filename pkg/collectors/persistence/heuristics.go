package persistence

import (
	"fmt"
	"regexp"
	"strings"
)

// A heuristic tags command text with an analyst-facing note. These are
// triage hints, not detections: they are cheap, explainable and expected to
// have false positives (see docs/THREAT_MODEL.md).
type heuristic struct {
	tag string
	re  *regexp.Regexp
}

var heuristics = []heuristic{
	{"download-piped-to-shell", regexp.MustCompile(`(curl|wget|fetch)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b`)},
	{"network-fetch", regexp.MustCompile(`\b(curl|wget|fetch|nc|ncat|socat)\b`)},
	{"dev-tcp-redirect", regexp.MustCompile(`/dev/(tcp|udp)/`)},
	{"base64-decode", regexp.MustCompile(`base64\s+(-d|--decode|-D)\b|b64decode`)},
	{"writable-dir-exec", regexp.MustCompile(`(^|[\s'"=:;(])/(tmp|var/tmp|dev/shm)/`)},
	{"hidden-path", regexp.MustCompile(`/\.[A-Za-z0-9_-]+(/|\s|$)`)},
	{"inline-interpreter", regexp.MustCompile(`\b(python[0-9.]*|perl|ruby|php|node)\s+-(c|e|r)\b`)},
	{"preload-injection", regexp.MustCompile(`\b(LD_PRELOAD|DYLD_INSERT_LIBRARIES)\b`)},
	{"prompt-hook", regexp.MustCompile(`\bPROMPT_COMMAND\b|\bprecmd\b`)},
	{"sudo-alias", regexp.MustCompile(`\balias\s+sudo=`)},
	{"eval", regexp.MustCompile(`\beval\b`)},
}

// Assess returns the sorted heuristic tags matching a single command.
func Assess(cmd string) []string {
	out := []string{}
	for _, h := range heuristics {
		if h.re.MatchString(cmd) {
			out = append(out, h.tag)
		}
	}
	return out
}

// scriptNotes applies Assess to each non-comment line of a script or rc
// file and reports "line N: tag[,tag]: text" notes.
func scriptNotes(text string) []string {
	out := []string{}
	for i, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		tags := Assess(t)
		if len(tags) == 0 {
			continue
		}
		if len(t) > 160 {
			t = t[:160] + "..."
		}
		out = append(out, fmt.Sprintf("line %d: %s: %s", i+1, strings.Join(tags, ","), t))
	}
	return out
}
