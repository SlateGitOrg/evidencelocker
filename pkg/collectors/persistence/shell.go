package persistence

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

var systemRC = []string{
	"/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/bashrc",
	"/etc/zshrc", "/etc/zsh/zshrc", "/etc/zprofile", "/etc/zsh/zprofile",
	"/etc/zshenv", "/etc/zsh/zshenv", "/etc/environment",
}

var userRCNames = []string{
	".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
	".zshrc", ".zprofile", ".zshenv", ".zlogin",
}

// homeGlobs covers Linux, macOS and root home directories.
var homeGlobs = []string{"/root", "/home/*", "/Users/*"}

func homePatterns(names ...string) []string {
	var out []string
	for _, h := range homeGlobs {
		for _, n := range names {
			out = append(out, h+"/"+n)
		}
	}
	return out
}

func scanShell(s *scan, extra []string) {
	pats := append(append(append([]string{}, systemRC...), homePatterns(userRCNames...)...), extra...)
	for _, p := range s.glob(pats...) {
		f, ok := s.read(p)
		if !ok {
			continue
		}
		s.add(Entry{
			Mechanism: MechShellRC, Location: p, User: scopeUser(p),
			Trigger: "shell startup", FileSHA256: f.sha, Notes: scriptNotes(string(f.data)),
		})
	}
	if f, ok := s.read("/etc/rc.local"); ok {
		s.add(Entry{
			Mechanism: MechRCLocal, Location: f.path, User: "root", Trigger: "boot",
			FileSHA256: f.sha, Notes: scriptNotes(string(f.data)),
		})
	}
}

func scanPreload(s *scan) {
	f, ok := s.read("/etc/ld.so.preload")
	if !ok {
		return
	}
	for i, line := range strings.Split(string(f.data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		for _, lib := range strings.Fields(t) {
			s.add(Entry{
				Mechanism: MechLDPreload, Location: f.path, Line: i + 1, Name: lib,
				Command: lib, User: "*", Trigger: "every dynamically linked exec",
				FileSHA256: f.sha, Notes: append([]string{"global-preload"}, Assess(lib)...),
			})
		}
	}
}

func scanSSHKeys(s *scan) {
	for _, p := range s.glob(homePatterns(".ssh/authorized_keys", ".ssh/authorized_keys2")...) {
		f, ok := s.read(p)
		if !ok {
			continue
		}
		user := scopeUser(p)
		for i, line := range strings.Split(string(f.data), "\n") {
			k, err := ParseAuthorizedKey(line)
			if err != nil {
				if !errors.Is(err, errSkipLine) {
					s.out.Warnf("%s:%d: %v", p, i+1, err)
				}
				continue
			}
			notes := []string{}
			if k.Command != "" {
				notes = append(notes, "forced-command")
				notes = append(notes, Assess(k.Command)...)
			}
			cmd := k.Type + " " + k.Comment
			if k.Command != "" {
				cmd = "command=" + k.Command
			}
			s.add(Entry{
				Mechanism: MechSSHKey, Location: p, Line: i + 1, Name: k.Fingerprint,
				Command: strings.TrimSpace(cmd), User: user, Trigger: "ssh login",
				FileSHA256: f.sha, Notes: notes,
			})
		}
	}
}

// AuthorizedKey is one parsed authorized_keys line (public material only).
type AuthorizedKey struct {
	Options     string
	Command     string
	Type        string
	Fingerprint string // OpenSSH style "SHA256:<unpadded base64>"
	Comment     string
}

var errSkipLine = errors.New("comment or blank")

var keyTypes = map[string]bool{
	"ssh-rsa": true, "ssh-dss": true, "ssh-ed25519": true, "ecdsa-sha2-nistp256": true,
	"ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true,
	"sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// ParseAuthorizedKey parses sshd(8) AUTHORIZED_KEYS format:
// [options] keytype base64-key [comment].
func ParseAuthorizedKey(line string) (AuthorizedKey, error) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return AuthorizedKey{}, errSkipLine
	}
	var k AuthorizedKey
	f := strings.Fields(t)
	if !keyTypes[f[0]] {
		opts, rest := splitOptions(t)
		k.Options = opts
		k.Command = optionValue(opts, "command")
		f = strings.Fields(rest)
	}
	if len(f) < 2 || !keyTypes[f[0]] {
		return AuthorizedKey{}, errors.New("unrecognised key line")
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return AuthorizedKey{}, errors.New("key blob is not base64")
	}
	sum := sha256.Sum256(blob)
	k.Type = f[0]
	k.Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	k.Comment = strings.Join(f[2:], " ")
	return k, nil
}

// splitOptions splits the leading option list (which may contain quoted
// spaces) from the rest of the line.
func splitOptions(s string) (string, string) {
	inQuote := false
	for i, r := range s {
		switch {
		case r == '"' && (i == 0 || s[i-1] != '\\'):
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			return s[:i], strings.TrimSpace(s[i:])
		}
	}
	return s, ""
}

// optionValue returns the unquoted value of name="value" in an option list.
func optionValue(opts, name string) string {
	key := name + `="`
	i := -1
	for off := 0; off < len(opts); {
		j := strings.Index(opts[off:], key)
		if j < 0 {
			return ""
		}
		if off+j == 0 || opts[off+j-1] == ',' {
			i = off + j
			break
		}
		off += j + 1
	}
	if i < 0 {
		return ""
	}
	rest := opts[i+len(key):]
	var sb strings.Builder
	for j := 0; j < len(rest); j++ {
		if rest[j] == '\\' && j+1 < len(rest) && rest[j+1] == '"' {
			sb.WriteByte('"')
			j++
			continue
		}
		if rest[j] == '"' {
			break
		}
		sb.WriteByte(rest[j])
	}
	return sb.String()
}
