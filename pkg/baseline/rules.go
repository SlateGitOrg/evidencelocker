package baseline

import (
	"fmt"
	"slices"
	"strings"

	"github.com/SlateGitOrg/evidencelocker/pkg/collector"
	"github.com/SlateGitOrg/evidencelocker/pkg/collectors/accounts"
	"github.com/SlateGitOrg/evidencelocker/pkg/collectors/filehash"
	"github.com/SlateGitOrg/evidencelocker/pkg/collectors/persistence"
	"github.com/SlateGitOrg/evidencelocker/pkg/collectors/processes"
	"github.com/SlateGitOrg/evidencelocker/pkg/collectors/sockets"
	"github.com/SlateGitOrg/evidencelocker/pkg/collectors/users"
)

// WritableDirs are world-writable staging areas; executables there are a
// classic sign of a dropped tool.
var WritableDirs = []string{"/tmp", "/var/tmp", "/dev/shm", "/run/shm"}

func inWritable(p string) bool {
	for _, d := range WritableDirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// strongTags escalate new persistence to critical.
var strongTags = []string{"download-piped-to-shell", "dev-tcp-redirect", "global-preload", "writable-dir-exec", "base64-decode"}

func persistenceRule(ctx *Context, ch Change, _ string, old, cur *collector.StoredRecord) (Finding, error) {
	o, c, err := decode2[persistence.Entry](old, cur)
	if err != nil {
		return Finding{}, err
	}
	switch ch {
	case Added:
		f := Finding{Severity: High, Title: fmt.Sprintf("new %s persistence in %s", c.Mechanism, c.Location)}
		f.Details = entryDetails(c)
		if slices.ContainsFunc(c.Notes, isStrong) {
			f.Severity = Critical
		}
		if c.Line == 0 {
			f.Details = append(f.Details, contentLines(ctx.Cur.Files[c.Location], 12)...)
		}
		return f, nil
	case Removed:
		return Finding{Severity: Low, Title: fmt.Sprintf("%s persistence removed from %s", o.Mechanism, o.Location), Details: entryDetails(o)}, nil
	}
	f := Finding{Severity: High, Title: fmt.Sprintf("%s persistence changed in %s", c.Mechanism, c.Location)}
	if o.Command != c.Command {
		f.Details = append(f.Details, "command: "+o.Command+" -> "+c.Command)
	}
	if o.User != c.User {
		f.Details = append(f.Details, "user: "+o.User+" -> "+c.User)
	}
	if o.Trigger != c.Trigger {
		f.Details = append(f.Details, "trigger: "+o.Trigger+" -> "+c.Trigger)
	}
	if o.FileSHA256 != c.FileSHA256 && c.Line == 0 {
		f.Details = append(f.Details, LineDiff(string(ctx.Base.Files[o.Location]), string(ctx.Cur.Files[c.Location]), 2000)...)
	}
	if slices.ContainsFunc(c.Notes, isStrong) {
		f.Severity = Critical
	}
	return f, nil
}

func isStrong(note string) bool {
	for _, t := range strongTags {
		if strings.Contains(note, t) {
			return true
		}
	}
	return false
}

func entryDetails(e *persistence.Entry) []string {
	var d []string
	if e.Name != "" && e.Line == 0 {
		d = append(d, "name: "+e.Name)
	}
	if e.Line > 0 {
		d = append(d, fmt.Sprintf("line %d: %s", e.Line, e.Name))
	}
	if e.Command != "" {
		d = append(d, "command: "+e.Command)
	}
	if e.User != "" {
		d = append(d, "runs as: "+e.User)
	}
	if e.Trigger != "" {
		d = append(d, "trigger: "+e.Trigger)
	}
	for _, n := range e.Notes {
		d = append(d, "heuristic: "+n)
	}
	return d
}

func contentLines(b []byte, max int) []string {
	if b == nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if len(out) == max {
			out = append(out, "  ...")
			break
		}
		out = append(out, "  | "+l)
	}
	return out
}

func filehashRule(_ *Context, ch Change, _ string, old, cur *collector.StoredRecord) (Finding, error) {
	o, c, err := decode2[filehash.File](old, cur)
	if err != nil {
		return Finding{}, err
	}
	switch ch {
	case Added:
		f := Finding{Severity: Medium, Title: "new file " + c.Path, Details: fileDetails(c)}
		switch {
		case c.Setuid || c.Setgid:
			f.Severity, f.Title = Critical, "new setuid/setgid file "+c.Path
		case inWritable(c.Path) && c.Executable:
			f.Severity, f.Title = High, "new executable in world-writable directory: "+c.Path
		case inWritable(c.Path):
			f.Severity = Low
		case c.Executable:
			f.Title = "new binary " + c.Path
		}
		return f, nil
	case Removed:
		return Finding{Severity: Low, Title: "file removed: " + o.Path}, nil
	}
	f := Finding{Severity: Medium, Title: "file changed: " + c.Path}
	if o.SHA256 != c.SHA256 {
		f.Details = append(f.Details, fmt.Sprintf("sha256: %s -> %s", abbrev(o.SHA256), abbrev(c.SHA256)))
		if c.Executable || o.Executable {
			f.Severity, f.Title = High, "binary replaced: "+c.Path
		}
	}
	if o.Mode != c.Mode {
		f.Details = append(f.Details, "mode: "+o.Mode+" -> "+c.Mode)
		if (c.Setuid && !o.Setuid) || (c.Setgid && !o.Setgid) {
			f.Severity, f.Title = Critical, "setuid/setgid bit added: "+c.Path
		}
	}
	if o.LinkTarget != c.LinkTarget {
		f.Details = append(f.Details, "link: "+o.LinkTarget+" -> "+c.LinkTarget)
	}
	if o.Type != c.Type {
		f.Details = append(f.Details, "type: "+o.Type+" -> "+c.Type)
	}
	return f, nil
}

func fileDetails(f *filehash.File) []string {
	d := []string{fmt.Sprintf("type %s, mode %s, %d bytes", f.Type, f.Mode, f.Size)}
	if f.SHA256 != "" {
		d = append(d, "sha256: "+f.SHA256)
	}
	if f.LinkTarget != "" {
		d = append(d, "link: "+f.LinkTarget)
	}
	if f.Skipped != "" {
		d = append(d, "not hashed: "+f.Skipped)
	}
	return d
}

func abbrev(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	if h == "" {
		return "(none)"
	}
	return h
}

func processRule(ctx *Context, ch Change, _ string, old, cur *collector.StoredRecord) (Finding, error) {
	o, c, err := decode2[processes.Process](old, cur)
	if err != nil {
		return Finding{}, err
	}
	switch ch {
	case Removed:
		return Finding{Severity: Info, Title: "process no longer running: " + o.Identity()}, nil
	case Modified:
		return Finding{Severity: Low, Title: "process attributes changed: " + c.Identity(),
			Details: []string{fmt.Sprintf("uid %d -> %d", o.UID, c.UID)}}, nil
	}
	f := Finding{Severity: Low, Title: "new process " + c.Identity(), Details: []string{
		fmt.Sprintf("pid %d ppid %d uid %d", c.PID, c.PPID, c.UID),
		"cmdline: " + strings.Join(c.Cmdline, " "),
	}}
	if c.Cwd != "" {
		f.Details = append(f.Details, "cwd: "+c.Cwd)
	}
	switch {
	case c.ExeDeleted:
		f.Severity, f.Title = High, "process running from a deleted executable: "+c.Exe
	case inWritable(c.Exe):
		f.Severity, f.Title = High, "process running from world-writable directory: "+c.Exe
	case c.Exe != "" && !knownBinary(ctx, c.Exe):
		f.Severity = Medium
		f.Details = append(f.Details, "executable not seen in baseline process list or file hashes")
	}
	return f, nil
}

// knownBinary reports whether the baseline knew this executable, either as
// a running process or as a hashed file. The lookup set is built once per
// comparison, so the rule stays O(1) per process.
func knownBinary(ctx *Context, exe string) bool {
	if ctx.known == nil {
		ctx.known = map[string]bool{}
		if rf := ctx.Base.Collectors["filehash"]; rf != nil {
			for _, r := range rf.Records {
				ctx.known[r.Key] = true
			}
		}
		if rf := ctx.Base.Collectors["processes"]; rf != nil {
			for _, r := range rf.Records {
				exe, _, _ := strings.Cut(r.Key, "\x00")
				ctx.known[exe] = true
			}
		}
	}
	return ctx.known[exe]
}

func socketRule(_ *Context, ch Change, key string, old, cur *collector.StoredRecord) (Finding, error) {
	o, c, err := decode2[sockets.Socket](old, cur)
	if err != nil {
		return Finding{}, err
	}
	switch ch {
	case Removed:
		return Finding{Severity: Info, Title: "listener closed: " + key}, nil
	case Modified:
		return Finding{Severity: Medium, Title: "listener changed owner: " + key,
			Details: []string{fmt.Sprintf("owner: %s (uid %d) -> %s (uid %d)", owner(o), o.UID, owner(c), c.UID)}}, nil
	}
	f := Finding{Severity: Medium, Title: "new listening socket " + key,
		Details: []string{fmt.Sprintf("owner: %s pid %d uid %d", owner(c), c.PID, c.UID)}}
	if inWritable(c.Exe) {
		f.Severity, f.Title = High, "new listener owned by a binary in a world-writable directory: "+key
	}
	return f, nil
}

func owner(s *sockets.Socket) string {
	if s.Exe != "" {
		return s.Exe
	}
	if s.Process != "" {
		return s.Process
	}
	return "unknown"
}

func accountRule(_ *Context, ch Change, _ string, old, cur *collector.StoredRecord) (Finding, error) {
	o, c, err := decode2[accounts.Account](old, cur)
	if err != nil {
		return Finding{}, err
	}
	switch ch {
	case Removed:
		return Finding{Severity: Low, Title: "account removed: " + o.Name}, nil
	case Added:
		f := Finding{Severity: Low, Title: "new account " + c.Name, Details: acctDetails(c)}
		switch {
		case c.UID == 0:
			f.Severity, f.Title = Critical, "new UID 0 account "+c.Name
		case len(c.PrivGroups) > 0:
			f.Severity, f.Title = High, "new account in privileged groups: "+c.Name
		case c.LoginShell:
			f.Severity = Medium
		}
		return f, nil
	}
	f := Finding{Severity: Low, Title: "account changed: " + c.Name}
	if o.UID != c.UID {
		f.Details = append(f.Details, fmt.Sprintf("uid: %d -> %d", o.UID, c.UID))
		if c.UID == 0 {
			f.Severity, f.Title = Critical, "account changed to UID 0: "+c.Name
		}
	}
	if o.Shell != c.Shell {
		f.Details = append(f.Details, "shell: "+o.Shell+" -> "+c.Shell)
		if c.LoginShell && !o.LoginShell && f.Severity < Medium {
			f.Severity, f.Title = Medium, "service account gained a login shell: "+c.Name
		}
	}
	var gained []string
	for _, g := range c.PrivGroups {
		if !slices.Contains(o.PrivGroups, g) {
			gained = append(gained, g)
		}
	}
	if len(gained) > 0 {
		f.Details = append(f.Details, "added to privileged groups: "+strings.Join(gained, ", "))
		if f.Severity < High {
			f.Severity, f.Title = High, "account added to privileged group: "+c.Name
		}
	}
	if o.Home != c.Home {
		f.Details = append(f.Details, "home: "+o.Home+" -> "+c.Home)
	}
	return f, nil
}

func acctDetails(a *accounts.Account) []string {
	d := []string{fmt.Sprintf("uid %d gid %d home %s shell %s", a.UID, a.GID, a.Home, a.Shell)}
	if len(a.PrivGroups) > 0 {
		d = append(d, "privileged groups: "+strings.Join(a.PrivGroups, ", "))
	}
	return d
}

func sessionRule(_ *Context, ch Change, key string, _, cur *collector.StoredRecord) (Finding, error) {
	_, c, err := decode2[users.Session](nil, cur)
	if err != nil {
		return Finding{}, err
	}
	if ch == Removed {
		return Finding{Severity: Info, Title: "session ended: " + key}, nil
	}
	f := Finding{Severity: Low, Title: "session " + string(ch) + ": " + key,
		Details: []string{fmt.Sprintf("login %s pid %d", c.LoginTime.Format("2006-01-02 15:04:05Z07:00"), c.PID)}}
	if c.Host != "" {
		f.Details = append(f.Details, "from: "+c.Host)
	}
	return f, nil
}
