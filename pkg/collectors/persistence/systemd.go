package persistence

import (
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Directories searched for unit files (system and user scope).
var unitDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
	"/usr/local/lib/systemd/system",
	"/etc/systemd/user",
	"/usr/lib/systemd/user",
	"/root/.config/systemd/user",
	"/home/*/.config/systemd/user",
}

var unitSuffixes = map[string]bool{".service": true, ".timer": true, ".socket": true, ".path": true}

// Unit is the persistence-relevant subset of a systemd unit file.
type Unit struct {
	Description string
	Exec        []string // ExecStart*, ExecStop*, ExecReload in file order
	User        string
	WantedBy    []string // WantedBy= and RequiredBy=
	Timers      []string // OnCalendar=, OnBootSec=, ... (".timer" units)
}

// ParseUnit parses systemd.unit(5) INI text: [Section] headers, key=value
// pairs, '#'/';' comments and backslash line continuations.
func ParseUnit(text string) Unit {
	var u Unit
	section := ""
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		for strings.HasSuffix(line, `\`) && i+1 < len(lines) {
			i++
			line = strings.TrimSpace(strings.TrimSuffix(line, `\`)) + " " + strings.TrimSpace(lines[i])
		}
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch {
		case section == "Unit" && k == "Description":
			u.Description = v
		case section == "Service" && strings.HasPrefix(k, "Exec") && v != "":
			u.Exec = append(u.Exec, v)
		case section == "Service" && k == "User":
			u.User = v
		case section == "Install" && (k == "WantedBy" || k == "RequiredBy"):
			u.WantedBy = append(u.WantedBy, strings.Fields(v)...)
		case section == "Timer" && strings.HasPrefix(k, "On"):
			u.Timers = append(u.Timers, k+"="+v)
		}
	}
	return u
}

func scanSystemd(s *scan) {
	type unitFile struct{ path, name string }
	var units []unitFile
	enabled := map[string]bool{}
	walked := map[string]bool{}
	for _, d := range s.glob(unitDirs...) {
		_, err := s.env.Root.Walk(d, func(p string, de fs.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable subtrees are skipped, not fatal
			}
			if de.IsDir() {
				if walked[p] {
					return fs.SkipDir
				}
				walked[p] = true
				return nil
			}
			name := de.Name()
			parent := path.Base(path.Dir(p))
			if strings.HasSuffix(parent, ".wants") || strings.HasSuffix(parent, ".requires") {
				enabled[name] = true
				return nil
			}
			if de.Type()&fs.ModeSymlink != 0 || !unitSuffixes[path.Ext(name)] {
				return nil // aliases and masks (links to /dev/null) are not new code
			}
			units = append(units, unitFile{p, name})
			return nil
		})
		if err != nil {
			s.out.Warnf("walk %s: %v", d, err)
		}
	}
	sort.Slice(units, func(i, j int) bool { return units[i].path < units[j].path })
	for _, uf := range units {
		f, ok := s.read(uf.path)
		if !ok {
			continue
		}
		u := ParseUnit(string(f.data))
		trig := append([]string{}, u.WantedBy...)
		trig = append(trig, u.Timers...)
		if enabled[uf.name] {
			trig = append(trig, "enabled")
		}
		cmd := strings.Join(u.Exec, " ; ")
		user := u.User
		if user == "" {
			user = scopeUser(uf.path)
		}
		s.add(Entry{
			Mechanism: MechSystemd, Location: uf.path, Name: uf.name,
			Command: cmd, User: user, Trigger: strings.Join(trig, " "),
			FileSHA256: f.sha, Notes: Assess(cmd),
		})
	}
}

// scopeUser infers the account a user-scope unit or file belongs to from its
// path (/home/<u>/..., /Users/<u>/..., /root/...); system scope is root.
func scopeUser(p string) string {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	switch {
	case len(parts) > 1 && (parts[0] == "home" || parts[0] == "Users"):
		return parts[1]
	default:
		return "root"
	}
}
