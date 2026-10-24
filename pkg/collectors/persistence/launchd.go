package persistence

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

var launchdDirs = []string{
	"/Library/LaunchAgents/*.plist",
	"/Library/LaunchDaemons/*.plist",
	"/System/Library/LaunchAgents/*.plist",
	"/System/Library/LaunchDaemons/*.plist",
	"/Users/*/Library/LaunchAgents/*.plist",
}

// LaunchJob is the persistence-relevant subset of a launchd.plist(5).
type LaunchJob struct {
	Label    string
	Program  []string
	UserName string
	Triggers []string
}

// ParseLaunchJob extracts a LaunchJob from a decoded plist.
func ParseLaunchJob(v any) (LaunchJob, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return LaunchJob{}, errors.New("launchd plist root is not a dict")
	}
	var j LaunchJob
	j.Label, _ = m["Label"].(string)
	if p, ok := m["Program"].(string); ok {
		j.Program = append(j.Program, p)
	}
	if args, ok := m["ProgramArguments"].([]any); ok {
		for i, a := range args {
			s, _ := a.(string)
			if i == 0 && len(j.Program) == 1 && s == j.Program[0] {
				continue
			}
			j.Program = append(j.Program, s)
		}
	}
	j.UserName, _ = m["UserName"].(string)
	for _, k := range []string{"RunAtLoad", "KeepAlive"} {
		switch t := m[k].(type) {
		case bool:
			if t {
				j.Triggers = append(j.Triggers, k)
			}
		case map[string]any:
			j.Triggers = append(j.Triggers, k+"(conditional)")
		}
	}
	if n, ok := m["StartInterval"].(int64); ok {
		j.Triggers = append(j.Triggers, fmt.Sprintf("StartInterval=%d", n))
	}
	for _, k := range []string{"StartCalendarInterval", "WatchPaths", "QueueDirectories", "StartOnMount"} {
		if _, ok := m[k]; ok {
			j.Triggers = append(j.Triggers, k)
		}
	}
	sort.Strings(j.Triggers)
	if j.Label == "" {
		return j, errors.New("launchd plist has no Label")
	}
	return j, nil
}

func scanLaunchd(s *scan) {
	for _, p := range s.glob(launchdDirs...) {
		f, ok := s.read(p)
		if !ok {
			continue
		}
		e := Entry{Mechanism: MechLaunchd, Location: p, User: scopeUser(p), FileSHA256: f.sha}
		if strings.Contains(p, "/LaunchDaemons/") {
			e.User = "root"
		}
		v, err := ParsePlist(f.data)
		if err == nil {
			var j LaunchJob
			j, err = ParseLaunchJob(v)
			e.Name, e.Command, e.Trigger = j.Label, strings.Join(j.Program, " "), strings.Join(j.Triggers, " ")
			if j.UserName != "" {
				e.User = j.UserName
			}
		}
		e.Notes = Assess(e.Command)
		if err != nil {
			e.Notes = append(e.Notes, "unparsed: "+err.Error())
		}
		s.add(e)
	}
}
