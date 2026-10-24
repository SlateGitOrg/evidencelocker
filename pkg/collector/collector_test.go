package collector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/archit2501/evidencelocker/pkg/fsroot"
)

type rec struct{ K, V string }

func (r rec) Key() string    { return r.K }
func (r rec) Digest() string { return DigestOf(r.V) }

type fake struct {
	name string
	fn   func(ctx context.Context) (*Output, error)
	opts struct {
		Level int `json:"level"`
	}
}

func (f *fake) Name() string        { return f.name }
func (f *fake) Version() string     { return "0.0.1" }
func (f *fake) Description() string { return "fake " + f.name }
func (f *fake) Collect(ctx context.Context, _ *Env) (*Output, error) {
	return f.fn(ctx)
}
func (f *fake) Configure(raw json.RawMessage) error { return DecodeOptions(raw, &f.opts) }

type plain struct{ fake }

func (p *plain) Configure() {} // not the Configurable signature

func env(t *testing.T) *Env {
	r, err := fsroot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return &Env{Root: r, Clock: SystemClock{}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	ok := &fake{name: "alpha"}
	if err := r.Register(ok); err != nil {
		t.Fatal(err)
	}
	r.MustRegister(&fake{name: "beta"})
	if err := r.Register(&fake{name: "alpha"}); err == nil {
		t.Fatal("duplicate accepted")
	}
	for _, bad := range []string{"", "Upper", "has space", "-lead", strings.Repeat("a", 64)} {
		if err := r.Register(&fake{name: bad}); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	if got := r.Names(); strings.Join(got, ",") != "alpha,beta" {
		t.Fatalf("Names %v", got)
	}
	sel, err := r.Select([]string{"beta", "alpha", "beta"})
	if err != nil || len(sel) != 2 || sel[0].Name() != "alpha" {
		t.Fatalf("Select: %v %v", sel, err)
	}
	if all, _ := r.Select(nil); len(all) != 2 {
		t.Fatal("Select all")
	}
	if _, err := r.Select([]string{"gamma"}); err == nil {
		t.Fatal("unknown selected")
	}
	if _, ok := r.Get("alpha"); !ok {
		t.Fatal("Get")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustRegister duplicate did not panic")
		}
	}()
	r.MustRegister(&fake{name: "beta"})
}

func TestConfigure(t *testing.T) {
	r := NewRegistry()
	f := &fake{name: "alpha"}
	r.MustRegister(f)
	r.MustRegister(&plain{fake{name: "plain"}})
	if err := r.Configure(map[string]json.RawMessage{"alpha": json.RawMessage(`{"level":3}`)}); err != nil || f.opts.Level != 3 {
		t.Fatalf("configure: %v level=%d", err, f.opts.Level)
	}
	for _, bad := range []map[string]json.RawMessage{
		{"alpha": json.RawMessage(`{"lvl":3}`)},
		{"nope": json.RawMessage(`{}`)},
		{"plain": json.RawMessage(`{}`)},
	} {
		if err := r.Configure(bad); err == nil {
			t.Errorf("Configure(%v) accepted", bad)
		}
	}
	if err := DecodeOptions(nil, &f.opts); err != nil {
		t.Fatal("empty options must be a no-op")
	}
}

func TestRunStatusesAndIsolation(t *testing.T) {
	cs := []Collector{
		&fake{name: "ok", fn: func(context.Context) (*Output, error) {
			return &Output{Records: []Record{rec{"b", "2"}, rec{"a", "1"}}}, nil
		}},
		&fake{name: "partial", fn: func(context.Context) (*Output, error) {
			o := &Output{Partial: true}
			o.Warnf("hit limit %d", 5)
			return o, nil
		}},
		&fake{name: "skipped", fn: func(context.Context) (*Output, error) {
			return nil, ErrNotApplicable
		}},
		&fake{name: "failed", fn: func(context.Context) (*Output, error) {
			return &Output{}, errors.New("boom")
		}},
		&fake{name: "panics", fn: func(context.Context) (*Output, error) { panic("kaboom") }},
		&fake{name: "slow", fn: func(ctx context.Context) (*Output, error) {
			<-ctx.Done()
			return &Output{}, nil
		}},
	}
	res := Run(context.Background(), env(t), cs, RunOptions{Parallelism: 3, Timeout: 50 * time.Millisecond})
	got := map[string]Status{}
	for _, r := range res {
		got[r.Name] = r.Status
		if r.Output == nil {
			t.Fatalf("%s: nil output", r.Name)
		}
	}
	want := map[string]Status{"ok": StatusOK, "partial": StatusPartial, "skipped": StatusSkipped, "failed": StatusError, "panics": StatusError, "slow": StatusError}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: status %s, want %s", k, got[k], v)
		}
	}
	if res[0].Name != "failed" {
		t.Fatalf("results not sorted: %s", res[0].Name)
	}
}

// TestRunAbandonsCollectorIgnoringContext: a collector stuck in a call that
// never looks at ctx (e.g. a blocking open of a FIFO on a hostile host) must
// not stall the run past Timeout + AbandonGrace, and must not hold up the
// collectors queued behind it.
func TestRunAbandonsCollectorIgnoringContext(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	cs := []Collector{
		&fake{name: "stuck", fn: func(context.Context) (*Output, error) {
			<-release
			return &Output{Records: []Record{rec{"late", "x"}}}, nil
		}},
		&fake{name: "after", fn: func(context.Context) (*Output, error) {
			return &Output{Records: []Record{rec{"a", "1"}}}, nil
		}},
		&fake{name: "cooperative", fn: func(ctx context.Context) (*Output, error) {
			<-ctx.Done()
			return &Output{Records: []Record{rec{"partial", "1"}}}, nil
		}},
	}
	start := time.Now()
	res := Run(context.Background(), env(t), cs, RunOptions{Parallelism: 1, Timeout: 30 * time.Millisecond, AbandonGrace: 30 * time.Millisecond})
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("run took %s; stuck collector was not abandoned", el)
	}
	got := map[string]Result{}
	for _, r := range res {
		got[r.Name] = r
	}
	if r := got["stuck"]; r.Status != StatusError || !strings.Contains(r.Err, "abandoned") ||
		len(r.Output.Records) != 0 || len(r.Output.Warnings) != 1 {
		t.Fatalf("stuck: %+v", r)
	}
	if r := got["after"]; r.Status != StatusOK || len(r.Output.Records) != 1 {
		t.Fatalf("after: %+v", r)
	}
	// A collector that returns within the grace keeps its partial output.
	if r := got["cooperative"]; r.Status != StatusError || len(r.Output.Records) != 1 ||
		!strings.Contains(r.Err, "deadline") || strings.Contains(r.Err, "abandoned") {
		t.Fatalf("cooperative: %+v", r)
	}
}

// TestRunAbandonsOnParentCancel: cancelling the run (e.g. Ctrl-C) also bounds
// a stuck collector when no per-collector timeout is set.
func TestRunAbandonsOnParentCancel(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	ctx, cancel := context.WithCancel(context.Background())
	cs := []Collector{&fake{name: "stuck", fn: func(context.Context) (*Output, error) {
		cancel()
		<-release
		return nil, nil
	}}}
	res := Run(ctx, env(t), cs, RunOptions{AbandonGrace: 10 * time.Millisecond})
	if res[0].Status != StatusError || !strings.Contains(res[0].Err, "canceled") {
		t.Fatalf("%+v", res[0])
	}
}

func TestEncodeDeterministicAndDecode(t *testing.T) {
	r := Result{Name: "x", Version: "1", Status: StatusOK, Output: &Output{Records: []Record{rec{"b", "2"}, rec{"a", "1"}, rec{"a", "0"}}}}
	b1, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	r.Output.Records[0], r.Output.Records[2] = r.Output.Records[2], r.Output.Records[0]
	b2, _ := r.Encode()
	if string(b1) != string(b2) {
		t.Fatal("encoding depends on record order")
	}
	rf, err := DecodeRecordFile(b1)
	if err != nil || len(rf.Records) != 3 || rf.Records[0].Key != "a" || rf.Warnings == nil {
		t.Fatalf("decode: %+v %v", rf, err)
	}
	if _, err := DecodeRecordFile([]byte(`{"format":"other"}`)); err == nil {
		t.Fatal("wrong format accepted")
	}
	if _, err := DecodeRecordFile([]byte(`{"format":"evidencelocker/records/v1","extra":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	bad := Result{Name: "x", Output: &Output{Records: []Record{badRec{}}}}
	if _, err := bad.Encode(); err == nil {
		t.Fatal("unencodable record accepted")
	}
}

type badRec struct{ C chan int }

func (badRec) Key() string    { return "k" }
func (badRec) Digest() string { return "d" }

func TestDigestOfPanicsOnUnencodable(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	DigestOf(make(chan int))
}

func TestClocks(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if (FixedClock{ts}).Now() != ts {
		t.Fatal("fixed clock")
	}
	if (SystemClock{}).Now().Location() != time.UTC {
		t.Fatal("system clock must be UTC")
	}
}
