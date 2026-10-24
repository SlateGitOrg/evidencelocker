package persistence

import (
	"path"
	"regexp"
	"strings"
)

// System crontabs carry a user field; per-user spools do not.
var (
	systemCrontabs = []string{"/etc/crontab", "/etc/cron.d/*"}
	userCrontabs   = []string{
		"/var/spool/cron/crontabs/*", // Debian/Ubuntu
		"/var/spool/cron/*",          // RHEL/Fedora
		"/usr/lib/cron/tabs/*",       // macOS
		"/var/at/tabs/*",             // FreeBSD/macOS
	}
	cronScriptDirs = []string{"hourly", "daily", "weekly", "monthly"}
)

var envAssign = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=`)

// CronLine is one parsed crontab job.
type CronLine struct {
	Schedule string
	User     string
	Command  string
}

func scanCron(s *scan) {
	for _, p := range s.glob(systemCrontabs...) {
		if f, ok := s.read(p); ok {
			emitCron(s, f, true, "")
		}
	}
	for _, p := range s.glob(userCrontabs...) {
		if f, ok := s.read(p); ok {
			emitCron(s, f, false, path.Base(p))
		}
	}
	for _, d := range cronScriptDirs {
		for _, p := range s.glob("/etc/cron." + d + "/*") {
			f, ok := s.read(p)
			if !ok {
				continue
			}
			s.add(Entry{
				Mechanism: MechCronScript, Location: p, Command: p, User: "root",
				Trigger: d, FileSHA256: f.sha, Notes: scriptNotes(string(f.data)),
			})
		}
	}
}

func emitCron(s *scan, f file, system bool, user string) {
	for i, raw := range strings.Split(string(f.data), "\n") {
		cl, ok := ParseCronLine(raw, system)
		if !ok {
			continue
		}
		if !system {
			cl.User = user
		}
		s.add(Entry{
			Mechanism: MechCron, Location: f.path, Line: i + 1,
			Name:    strings.Join(strings.Fields(raw), " "),
			Command: cl.Command, User: cl.User, Trigger: cl.Schedule,
			FileSHA256: f.sha, Notes: Assess(cl.Command),
		})
	}
}

// ParseCronLine parses one crontab line. system selects the /etc/crontab
// format with a user column. Comments, blanks, environment assignments and
// malformed lines return ok=false.
func ParseCronLine(line string, system bool) (CronLine, bool) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") || envAssign.MatchString(t) {
		return CronLine{}, false
	}
	nsched := 5
	if strings.HasPrefix(t, "@") {
		nsched = 1
	}
	need := nsched
	if system {
		need++
	}
	toks, rest := splitN(t, need)
	if len(toks) < need || strings.TrimSpace(rest) == "" {
		return CronLine{}, false
	}
	cl := CronLine{Schedule: strings.Join(toks[:nsched], " "), Command: strings.TrimSpace(rest)}
	if system {
		cl.User = toks[nsched]
	}
	return cl, true
}

// splitN splits off the first n whitespace-separated tokens and returns the
// untouched remainder, preserving the command's own spacing.
func splitN(s string, n int) ([]string, string) {
	var toks []string
	for len(toks) < n {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			break
		}
		i := strings.IndexAny(s, " \t")
		if i < 0 {
			toks = append(toks, s)
			s = ""
			break
		}
		toks = append(toks, s[:i])
		s = s[i:]
	}
	return toks, s
}
