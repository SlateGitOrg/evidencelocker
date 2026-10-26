// Package users collects logged-in sessions from the Linux utmp database
// (glibc 64-bit layout) under the configured root.
package users

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"time"

	"github.com/SlateGitOrg/evidencelocker/pkg/collector"
	"github.com/SlateGitOrg/evidencelocker/pkg/fsroot"
)

// RecordSize is sizeof(struct utmp) for glibc on 64-bit Linux
// (x86_64 and aarch64 share the layout).
const RecordSize = 384

// utmp ut_type values.
const (
	TypeEmpty        = 0
	TypeRunLevel     = 1
	TypeBootTime     = 2
	TypeInitProcess  = 5
	TypeLoginProcess = 6
	TypeUserProcess  = 7
	TypeDeadProcess  = 8
)

// Field offsets within a utmp record.
const (
	offType    = 0
	offPID     = 4
	offLine    = 8
	offID      = 40
	offUser    = 44
	offHost    = 76
	offSession = 336
	offTvSec   = 340
	offAddr    = 348
	lenLine    = 32
	lenUser    = 32
	lenHost    = 256
)

// Utmp is a decoded utmp record.
type Utmp struct {
	Type    int16
	PID     int32
	Line    string
	ID      string
	User    string
	Host    string
	Session int32
	Time    time.Time
	Addr    netip.Addr
}

// Session is a logged-in user.
type Session struct {
	User      string    `json:"user"`
	Line      string    `json:"line"`
	Host      string    `json:"host,omitempty"`
	Addr      string    `json:"addr,omitempty"`
	PID       int       `json:"pid"`
	LoginTime time.Time `json:"login_time"`
}

// Key is user@line — one terminal can host one session at a time.
func (s Session) Key() string { return s.User + "@" + s.Line }

// Digest covers where the session came from.
func (s Session) Digest() string {
	return collector.DigestOf(struct{ User, Line, Host, Addr string }{s.User, s.Line, s.Host, s.Addr})
}

// utmpPaths are tried in order; modern distros use /run, older /var/run.
var utmpPaths = []string{"/run/utmp", "/var/run/utmp"}

// Collector implements collector.Collector.
type Collector struct{}

// New returns the users collector.
func New() *Collector { return &Collector{} }

// Name implements collector.Collector.
func (*Collector) Name() string { return "users" }

// Version implements collector.Collector.
func (*Collector) Version() string { return "1.0.0" }

// Description implements collector.Collector.
func (*Collector) Description() string {
	return "logged-in user sessions from utmp (glibc 64-bit layout)"
}

// Collect implements collector.Collector.
func (c *Collector) Collect(_ context.Context, env *collector.Env) (*collector.Output, error) {
	out := &collector.Output{}
	var data []byte
	var src string
	for _, p := range utmpPaths {
		b, err := env.Root.ReadFile(p, 64<<20)
		if err == nil {
			data, src = b, p
			break
		}
		if errors.Is(err, fsroot.ErrNotRegular) {
			return out, err // already names the path and file type
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return out, fmt.Errorf("read %s: %w", p, err)
		}
	}
	if src == "" {
		return out, fmt.Errorf("no utmp database under root: %w", collector.ErrNotApplicable)
	}
	recs, err := ParseUtmp(data)
	if err != nil {
		out.Warnf("%s: %v", src, err)
		out.Partial = true
	}
	for _, u := range recs {
		if u.Type != TypeUserProcess || u.User == "" {
			continue
		}
		s := Session{User: u.User, Line: u.Line, Host: u.Host, PID: int(u.PID), LoginTime: u.Time}
		if u.Addr.IsValid() && !u.Addr.IsUnspecified() {
			s.Addr = u.Addr.String()
		}
		out.Records = append(out.Records, s)
	}
	return out, nil
}

// ParseUtmp decodes whole records; a trailing partial record is reported
// as an error alongside the records that did decode.
func ParseUtmp(b []byte) ([]Utmp, error) {
	n := len(b) / RecordSize
	out := make([]Utmp, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, decode(b[i*RecordSize:(i+1)*RecordSize]))
	}
	if rem := len(b) % RecordSize; rem != 0 {
		return out, fmt.Errorf("trailing %d bytes are not a whole utmp record", rem)
	}
	return out, nil
}

func decode(r []byte) Utmp {
	le := binary.LittleEndian
	u := Utmp{
		Type:    int16(le.Uint16(r[offType:])),
		PID:     int32(le.Uint32(r[offPID:])),
		Line:    cstr(r[offLine : offLine+lenLine]),
		ID:      cstr(r[offID : offID+4]),
		User:    cstr(r[offUser : offUser+lenUser]),
		Host:    cstr(r[offHost : offHost+lenHost]),
		Session: int32(le.Uint32(r[offSession:])),
		Time:    time.Unix(int64(int32(le.Uint32(r[offTvSec:]))), 0).UTC(),
	}
	a := r[offAddr : offAddr+16]
	if bytes.Equal(a[4:], make([]byte, 12)) {
		u.Addr = netip.AddrFrom4([4]byte(a[:4]))
	} else {
		u.Addr = netip.AddrFrom16([16]byte(a))
	}
	return u
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// EncodeUtmp is the inverse of ParseUtmp. It exists so tests and fixture
// generation can build utmp files without a Linux host.
func EncodeUtmp(recs []Utmp) []byte {
	le := binary.LittleEndian
	out := make([]byte, 0, len(recs)*RecordSize)
	for _, u := range recs {
		r := make([]byte, RecordSize)
		le.PutUint16(r[offType:], uint16(u.Type))
		le.PutUint32(r[offPID:], uint32(u.PID))
		copy(r[offLine:offLine+lenLine], u.Line)
		copy(r[offID:offID+4], u.ID)
		copy(r[offUser:offUser+lenUser], u.User)
		copy(r[offHost:offHost+lenHost], u.Host)
		le.PutUint32(r[offSession:], uint32(u.Session))
		le.PutUint32(r[offTvSec:], uint32(u.Time.Unix()))
		if u.Addr.Is4() {
			a := u.Addr.As4()
			copy(r[offAddr:], a[:])
		} else if u.Addr.IsValid() {
			a := u.Addr.As16()
			copy(r[offAddr:], a[:])
		}
		out = append(out, r...)
	}
	return out
}
