package sockets

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/SlateGitOrg/evidencelocker/internal/testutil"
	"github.com/SlateGitOrg/evidencelocker/pkg/collector"
)

func keys(out *collector.Output) []string {
	var ks []string
	for _, r := range out.Records {
		ks = append(ks, r.Key())
	}
	sort.Strings(ks)
	return ks
}

func TestCompromisedFixture(t *testing.T) {
	out, err := New().Collect(context.Background(), testutil.Env(t, testutil.Fixture(t, "compromised")))
	if err != nil {
		t.Fatal(err)
	}
	want := "tcp/0.0.0.0:22,tcp/0.0.0.0:4444,tcp/0.0.0.0:80,tcp6/[::]:22,udp/127.0.0.53:53"
	if got := strings.Join(keys(out), ","); got != want {
		t.Fatalf("keys %s", got)
	}
	for _, r := range out.Records {
		s := r.(Socket)
		switch s.Port {
		case 4444:
			if s.PID != 4242 || s.Exe != "/tmp/.cache/kworkerd" || s.Process != "kworkerd" || s.UID != 33 {
				t.Fatalf("4444 owner: %+v", s)
			}
		case 53:
			if s.Exe != "/usr/lib/systemd/systemd-resolved" || s.State != "CLOSE" {
				t.Fatalf("53: %+v", s)
			}
		}
	}
}

func TestIncludeEstablished(t *testing.T) {
	c := New()
	if err := c.Configure(json.RawMessage(`{"include_established":true}`)); err != nil {
		t.Fatal(err)
	}
	out, err := c.Collect(context.Background(), testutil.Env(t, testutil.Fixture(t, "baseline")))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(keys(out), ","), "tcp/10.0.0.2:22") {
		t.Fatalf("established connection missing: %v", keys(out))
	}
	if err := c.Configure(json.RawMessage(`{"bogus":1}`)); err == nil {
		t.Fatal("unknown option accepted")
	}
}

func TestParseAddr(t *testing.T) {
	cases := map[string]string{
		"0100007F:0050":                         "127.0.0.1:80",
		"00000000:0016":                         "0.0.0.0:22",
		"00000000000000000000000001000000:0277": "[::1]:631",
		"0000000000000000FFFF00000100007F:1F90": "127.0.0.1:8080", // v4-mapped is unmapped
		"B80D0120000000000000000001000000:01BB": "[2001:db8::1]:443",
	}
	for in, want := range cases {
		a, p, err := ParseAddr(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		got := a.String() + ":" + strconv.Itoa(p)
		if a.Is6() {
			got = "[" + a.String() + "]:" + strconv.Itoa(p)
		}
		if got != want {
			t.Errorf("ParseAddr(%s) = %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"0100007F", "zz00007F:0050", "0100007F:zz", "01007F:0050"} {
		if _, _, err := ParseAddr(bad); err == nil {
			t.Errorf("ParseAddr(%q) accepted", bad)
		}
	}
}

func TestMalformedTableAndMissingProc(t *testing.T) {
	if _, err := New().Collect(context.Background(), testutil.Env(t, t.TempDir())); !errors.Is(err, collector.ErrNotApplicable) {
		t.Fatalf("want not applicable, got %v", err)
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "proc", "net"), 0o755)
	os.WriteFile(filepath.Join(dir, "proc", "net", "tcp"), []byte("header\n 0: garbage line\n 1: 00000000:0016 00000000:0000 ZZ 0:0 0:0 0 0 0 1\n"), 0o644)
	out, err := New().Collect(context.Background(), testutil.Env(t, dir))
	if err != nil || !out.Partial || len(out.Warnings) != 2 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	socks, bad := ParseTable("tcp", "h\n 0: 00000000:0016 00000000:0000 0A 0:0 0:0 0 x 0 1\n 1: 00000000:0016 00000000:0000 0A 0:0 0:0 0 0 0 y\n")
	if len(socks) != 0 || len(bad) != 2 {
		t.Fatalf("bad uid/inode accepted: %v %v", socks, bad)
	}
}

func TestSocketInodeAndMeta(t *testing.T) {
	for in, want := range map[string]bool{"socket:[123]": true, "pipe:[1]": false, "socket:[x]": false, "socket:[1": false} {
		if _, ok := socketInode(in); ok != want {
			t.Errorf("socketInode(%q)=%v", in, ok)
		}
	}
	s := Socket{Proto: "tcp", Address: "0.0.0.0", Port: 22, Exe: "/a"}
	s2 := s
	s2.Exe = "/b"
	if s.Key() != s2.Key() || s.Digest() == s2.Digest() {
		t.Fatal("owner change must keep key and change digest")
	}
	c := New()
	if c.Name() != "sockets" || c.Version() == "" || c.Description() == "" {
		t.Fatal("metadata")
	}
}
