// Package accounts collects local accounts from /etc/passwd and their
// membership of privileged groups from /etc/group. It deliberately never
// reads /etc/shadow: password hashes are credential material and out of
// scope for a triage collector.
package accounts

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/SlateGitOrg/evidencelocker/pkg/collector"
)

// PrivilegedGroups are groups whose members can usually become root.
var PrivilegedGroups = []string{"root", "sudo", "wheel", "admin", "adm", "docker", "lxd"}

// Account is one /etc/passwd entry.
type Account struct {
	Name       string   `json:"name"`
	UID        int      `json:"uid"`
	GID        int      `json:"gid"`
	Gecos      string   `json:"gecos,omitempty"`
	Home       string   `json:"home"`
	Shell      string   `json:"shell"`
	LoginShell bool     `json:"login_shell"`
	PrivGroups []string `json:"privileged_groups"`
}

// Key is the account name.
func (a Account) Key() string { return a.Name }

// Digest covers every security-relevant attribute.
func (a Account) Digest() string {
	return collector.DigestOf(struct {
		UID, GID    int
		Home, Shell string
		Groups      []string
	}{a.UID, a.GID, a.Home, a.Shell, a.PrivGroups})
}

// Collector implements collector.Collector.
type Collector struct{}

// New returns the accounts collector.
func New() *Collector { return &Collector{} }

// Name implements collector.Collector.
func (*Collector) Name() string { return "accounts" }

// Version implements collector.Collector.
func (*Collector) Version() string { return "1.0.0" }

// Description implements collector.Collector.
func (*Collector) Description() string {
	return "local accounts from /etc/passwd with privileged group membership (never reads shadow)"
}

// Collect implements collector.Collector.
func (c *Collector) Collect(_ context.Context, env *collector.Env) (*collector.Output, error) {
	out := &collector.Output{}
	pw, err := env.Root.ReadFile("/etc/passwd", 16<<20)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return out, fmt.Errorf("no /etc/passwd under root: %w", collector.ErrNotApplicable)
		}
		return out, err
	}
	out.Captures = append(out.Captures, collector.Capture{Path: "/etc/passwd", Data: pw})
	members := map[string][]string{}
	if gr, err := env.Root.ReadFile("/etc/group", 16<<20); err == nil {
		out.Captures = append(out.Captures, collector.Capture{Path: "/etc/group", Data: gr})
		members = ParseGroup(string(gr))
	} else if !errors.Is(err, fs.ErrNotExist) {
		out.Warnf("read /etc/group: %v", err)
		out.Partial = true
	}
	accts, bad := ParsePasswd(string(pw))
	for _, l := range bad {
		out.Warnf("/etc/passwd: malformed line %q", l)
		out.Partial = true
	}
	for _, a := range accts {
		a.PrivGroups = []string{}
		for _, g := range PrivilegedGroups {
			for _, m := range members[g] {
				if m == a.Name {
					a.PrivGroups = append(a.PrivGroups, g)
				}
			}
		}
		out.Records = append(out.Records, a)
	}
	return out, nil
}

// nologin shells cannot start an interactive session.
var nologin = map[string]bool{
	"/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/false": true,
	"/usr/bin/false": true, "/usr/bin/nologin": true, "": true,
}

// ParsePasswd parses passwd(5) lines, returning malformed lines separately.
func ParsePasswd(text string) ([]Account, []string) {
	var accts []Account
	var bad []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 7 {
			bad = append(bad, line)
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil || f[0] == "" {
			bad = append(bad, line)
			continue
		}
		accts = append(accts, Account{
			Name: f[0], UID: uid, GID: gid, Gecos: f[4], Home: f[5], Shell: f[6],
			LoginShell: !nologin[f[6]],
		})
	}
	return accts, bad
}

// ParseGroup returns group name -> member list from group(5) text.
func ParseGroup(text string) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), ":")
		if len(f) != 4 || f[0] == "" {
			continue
		}
		var ms []string
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				ms = append(ms, m)
			}
		}
		sort.Strings(ms)
		out[f[0]] = ms
	}
	return out
}
