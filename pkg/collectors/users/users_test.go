package users

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/SlateGitOrg/evidencelocker/internal/testutil"
	"github.com/SlateGitOrg/evidencelocker/pkg/collector"
)

func TestCompromisedFixture(t *testing.T) {
	out, err := New().Collect(context.Background(), testutil.Env(t, testutil.Fixture(t, "compromised")))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Records) != 2 {
		t.Fatalf("sessions: %+v", out.Records)
	}
	s := out.Records[1].(Session)
	if s.User != "sysupd" || s.Line != "pts/1" || s.Host != "203.0.113.50" || s.Addr != "203.0.113.50" || s.PID != 4100 {
		t.Fatalf("session: %+v", s)
	}
	if s.Key() != "sysupd@pts/1" || s.Digest() == out.Records[0].Digest() {
		t.Fatal("key/digest")
	}
}

func TestRoundTripProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	str := func(n int) string {
		b := make([]byte, r.IntN(n+1))
		for i := range b {
			b[i] = byte('a' + r.IntN(26))
		}
		return string(b)
	}
	for trial := 0; trial < 200; trial++ {
		var in []Utmp
		for i := 0; i < r.IntN(6); i++ {
			u := Utmp{
				Type: int16(r.IntN(9)), PID: int32(r.IntN(1 << 20)), Line: str(31), ID: str(4), User: str(31),
				Host: str(200), Session: int32(r.IntN(1000)), Time: time.Unix(int64(r.IntN(1<<31)), 0).UTC(),
			}
			if r.IntN(2) == 0 {
				u.Addr = netip.AddrFrom4([4]byte{byte(r.IntN(256)), 1, 2, 3})
			} else {
				u.Addr = netip.MustParseAddr("2001:db8::7")
			}
			in = append(in, u)
		}
		out, err := ParseUtmp(EncodeUtmp(in))
		if err != nil || len(out) != len(in) {
			t.Fatalf("round trip: %v", err)
		}
		for i := range in {
			if !reflect.DeepEqual(in[i], out[i]) {
				t.Fatalf("record %d: %+v != %+v", i, in[i], out[i])
			}
		}
	}
}

func TestTruncatedAndMissing(t *testing.T) {
	b := EncodeUtmp([]Utmp{{Type: TypeUserProcess, User: "u", Line: "pts/9", Time: time.Unix(0, 0).UTC()}})
	recs, err := ParseUtmp(append(b, 1, 2, 3))
	if err == nil || len(recs) != 1 {
		t.Fatalf("trailing bytes: %v", err)
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	os.WriteFile(filepath.Join(dir, "run", "utmp"), append(b, 9), 0o644)
	out, err := New().Collect(context.Background(), testutil.Env(t, dir))
	if err != nil || !out.Partial || len(out.Records) != 1 {
		t.Fatalf("partial utmp: %+v %v", out, err)
	}
	if _, err := New().Collect(context.Background(), testutil.Env(t, t.TempDir())); !errors.Is(err, collector.ErrNotApplicable) {
		t.Fatal("missing utmp must be not-applicable")
	}
	c := New()
	if c.Name() != "users" || c.Version() == "" || c.Description() == "" {
		t.Fatal("metadata")
	}
}

func FuzzParseUtmp(f *testing.F) {
	f.Add(EncodeUtmp([]Utmp{{Type: 7, User: "root"}}))
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, b []byte) {
		recs, _ := ParseUtmp(b)
		if len(recs) != len(b)/RecordSize {
			t.Fatal("record count")
		}
	})
}
