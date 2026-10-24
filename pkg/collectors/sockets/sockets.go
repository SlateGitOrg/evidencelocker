// Package sockets collects listening TCP sockets and bound UDP sockets from
// procfs (<root>/proc/net/{tcp,tcp6,udp,udp6}) and attributes each to its
// owning process by matching socket inodes against /proc/<pid>/fd links.
package sockets

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"strconv"
	"strings"

	"github.com/archit2501/evidencelocker/pkg/collector"
)

// Socket is one listening/bound socket.
type Socket struct {
	Proto   string `json:"proto"` // tcp, tcp6, udp, udp6
	Address string `json:"address"`
	Port    int    `json:"port"`
	State   string `json:"state"`
	UID     int    `json:"uid"`
	Inode   uint64 `json:"inode"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
	Exe     string `json:"exe,omitempty"`
}

// Key is proto/address:port — what a firewall rule or an analyst would name.
func (s Socket) Key() string {
	return fmt.Sprintf("%s/%s", s.Proto, netip.AddrPortFrom(netip.MustParseAddr(s.Address), uint16(s.Port)))
}

// Digest changes when a different program owns the endpoint.
func (s Socket) Digest() string {
	return collector.DigestOf(struct {
		Key, Exe string
		UID      int
	}{s.Key(), s.Exe, s.UID})
}

// Options configure the collector.
type Options struct {
	// IncludeEstablished also records connected TCP sockets.
	IncludeEstablished bool `json:"include_established"`
}

// Collector implements collector.Collector.
type Collector struct{ opts Options }

// New returns the sockets collector with default options.
func New() *Collector { return &Collector{} }

// Name implements collector.Collector.
func (*Collector) Name() string { return "sockets" }

// Version implements collector.Collector.
func (*Collector) Version() string { return "1.0.0" }

// Description implements collector.Collector.
func (*Collector) Description() string {
	return "listening TCP and bound UDP sockets from procfs, attributed to processes"
}

// Configure implements collector.Configurable.
func (c *Collector) Configure(raw json.RawMessage) error {
	return collector.DecodeOptions(raw, &c.opts)
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

// Collect implements collector.Collector.
func (c *Collector) Collect(ctx context.Context, env *collector.Env) (*collector.Output, error) {
	out := &collector.Output{}
	if !env.Root.Exists("/proc/net") {
		return out, fmt.Errorf("no /proc/net under root: %w", collector.ErrNotApplicable)
	}
	owners, err := inodeOwners(ctx, env, out)
	if err != nil {
		return out, err
	}
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, err := env.Root.ReadFile("/proc/net/"+proto, 64<<20)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				out.Warnf("read /proc/net/%s: %v", proto, err)
				out.Partial = true
			}
			continue
		}
		socks, bad := ParseTable(proto, string(b))
		for _, line := range bad {
			out.Warnf("/proc/net/%s: unparsable line %q", proto, line)
			out.Partial = true
		}
		for _, s := range socks {
			if !c.wanted(s) {
				continue
			}
			if o, ok := owners[s.Inode]; ok {
				s.PID, s.Process, s.Exe = o.pid, o.name, o.exe
			}
			out.Records = append(out.Records, s)
		}
	}
	return out, nil
}

func (c *Collector) wanted(s Socket) bool {
	if strings.HasPrefix(s.Proto, "udp") {
		// Unconnected UDP sockets report state 07 (CLOSE); those are the
		// "listening" ones.
		return s.State == "CLOSE"
	}
	return s.State == "LISTEN" || (c.opts.IncludeEstablished && s.State == "ESTABLISHED")
}

type owner struct {
	pid       int
	name, exe string
}

// inodeOwners maps socket inode -> owning process by reading fd symlinks.
func inodeOwners(ctx context.Context, env *collector.Env, out *collector.Output) (map[uint64]owner, error) {
	owners := map[uint64]owner{}
	ents, err := env.Root.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("list /proc: %w", err)
	}
	denied := 0
	for _, e := range ents {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		base := "/proc/" + e.Name()
		fds, err := env.Root.ReadDir(base + "/fd")
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				denied++
			}
			continue
		}
		var o *owner
		for _, fd := range fds {
			target, err := env.Root.Readlink(base + "/fd/" + fd.Name())
			if err != nil {
				continue
			}
			ino, ok := socketInode(target)
			if !ok {
				continue
			}
			if o == nil {
				o = &owner{pid: pid, name: procName(env, base)}
				if exe, err := env.Root.Readlink(base + "/exe"); err == nil {
					o.exe = strings.TrimSuffix(exe, " (deleted)")
				}
			}
			if _, dup := owners[ino]; !dup {
				owners[ino] = *o
			}
		}
	}
	if denied > 0 {
		out.Warnf("permission denied reading fd tables of %d processes; run as root for full attribution", denied)
		out.Partial = true
	}
	return owners, nil
}

func procName(env *collector.Env, base string) string {
	b, err := env.Root.ReadFile(base+"/comm", 4096)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func socketInode(link string) (uint64, bool) {
	s, ok := strings.CutPrefix(link, "socket:[")
	if !ok {
		return 0, false
	}
	s, ok = strings.CutSuffix(s, "]")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

// ParseTable parses a /proc/net/{tcp,udp}[6] table. It returns every parsed
// socket regardless of state, plus the raw text of lines it could not parse.
func ParseTable(proto, text string) ([]Socket, []string) {
	var socks []Socket
	var bad []string
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // header
		}
		s, err := parseLine(proto, line)
		if err != nil {
			bad = append(bad, strings.TrimSpace(line))
			continue
		}
		socks = append(socks, s)
	}
	return socks, bad
}

func parseLine(proto, line string) (Socket, error) {
	f := strings.Fields(line)
	if len(f) < 10 {
		return Socket{}, errors.New("short line")
	}
	addr, port, err := ParseAddr(f[1])
	if err != nil {
		return Socket{}, err
	}
	st := strings.ToUpper(f[3])
	state, ok := tcpStates[st]
	if !ok {
		return Socket{}, fmt.Errorf("unknown state %q", f[3])
	}
	uid, err := strconv.Atoi(f[7])
	if err != nil {
		return Socket{}, err
	}
	ino, err := strconv.ParseUint(f[9], 10, 64)
	if err != nil {
		return Socket{}, err
	}
	return Socket{Proto: proto, Address: addr.String(), Port: port, State: state, UID: uid, Inode: ino}, nil
}

// ParseAddr decodes procfs "HEXADDR:HEXPORT". Addresses are stored as
// 32-bit words in host (little-endian on every Linux arch we target) order;
// the port is big-endian hex.
func ParseAddr(s string) (netip.Addr, int, error) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("address %q: missing port", s)
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("address %q: port: %w", s, err)
	}
	raw, err := hex.DecodeString(a)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, 0, fmt.Errorf("address %q: bad hex address", s)
	}
	for w := 0; w < len(raw); w += 4 {
		raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	ip, _ := netip.AddrFromSlice(raw)
	return ip.Unmap(), int(port), nil
}
