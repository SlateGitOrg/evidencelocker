package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"sync"
	"time"
)

// Status is the outcome of one collector run.
type Status string

// Collector run outcomes.
const (
	StatusOK      Status = "ok"
	StatusPartial Status = "partial"
	StatusSkipped Status = "skipped"
	StatusError   Status = "error"
)

// Result records one collector's run.
type Result struct {
	Name      string
	Version   string
	Status    Status
	StartedAt time.Time
	Duration  time.Duration
	Output    *Output // never nil
	Err       string
}

// RunOptions control Run.
type RunOptions struct {
	// Parallelism bounds concurrently running collectors (default 1).
	Parallelism int
	// Timeout bounds each collector (0 = none). Collectors should honour ctx;
	// one that does not is abandoned AbandonGrace after its deadline.
	Timeout time.Duration
	// AbandonGrace is how long the runner waits, once a collector's context
	// is done, for the collector to return its partial output on its own
	// before abandoning it (default DefaultAbandonGrace).
	AbandonGrace time.Duration
}

// DefaultAbandonGrace is the default RunOptions.AbandonGrace.
const DefaultAbandonGrace = 2 * time.Second

// Run executes collectors and returns their results in name order. A
// collector that panics, errors or times out yields StatusError without
// affecting the others: a triage run must salvage everything it can.
//
// The timeout is a hard bound. A collector stuck in a call that ignores its
// context (for example a blocking read on a hostile host) is abandoned once
// the grace period after its deadline has passed: its result is StatusError,
// its partial output is discarded (the goroutine may still be writing to it),
// and its goroutine is left to finish or die with the process. An abandoned
// collector no longer counts against Parallelism.
func Run(ctx context.Context, env *Env, cs []Collector, opts RunOptions) []Result {
	par := opts.Parallelism
	if par < 1 {
		par = 1
	}
	if opts.AbandonGrace <= 0 {
		opts.AbandonGrace = DefaultAbandonGrace
	}
	results := make([]Result, len(cs))
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	for i, c := range cs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = runOne(ctx, env, c, opts.Timeout, opts.AbandonGrace)
		}()
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	return results
}

// outcome is what a collector goroutine hands back to runOne.
type outcome struct {
	out      *Output
	err      error
	panicked any
	stack    []byte
}

func runOne(ctx context.Context, env *Env, c Collector, timeout, grace time.Duration) (res Result) {
	res = Result{Name: c.Name(), Version: c.Version(), StartedAt: env.Clock.Now()}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	log := env.Logger.With("collector", res.Name)
	log.Debug("collector start")
	defer func() {
		res.Duration = env.Clock.Now().Sub(res.StartedAt)
		log.Info("collector done", "status", res.Status, "records", len(res.Output.Records),
			"captures", len(res.Output.Captures), "warnings", len(res.Output.Warnings))
	}()

	// Buffered so an abandoned collector's goroutine can still finish.
	done := make(chan outcome, 1)
	go func() {
		var o outcome
		defer func() {
			if p := recover(); p != nil {
				o = outcome{panicked: p, stack: debug.Stack()}
			}
			done <- o
		}()
		o.out, o.err = c.Collect(ctx, env)
	}()

	var o outcome
	select {
	case o = <-done:
	case <-ctx.Done():
		// Give a collector that honours ctx the chance to return what it has.
		t := time.NewTimer(grace)
		select {
		case o = <-done:
			t.Stop()
		case <-t.C:
			res.Status = StatusError
			res.Err = fmt.Sprintf("%v; collector abandoned after a further %s without returning", ctx.Err(), grace)
			res.Output = &Output{}
			res.Output.Warnf("collector did not return after its deadline and was abandoned; any partial output is discarded")
			log.Error("collector abandoned", "err", ctx.Err(), "grace", grace)
			return res
		}
	}

	if o.panicked != nil {
		res.Status = StatusError
		res.Err = fmt.Sprintf("panic: %v", o.panicked)
		res.Output = &Output{}
		log.Error("collector panicked", "panic", o.panicked, "stack", string(o.stack))
		return res
	}
	out, err := o.out, o.err
	if out == nil {
		out = &Output{}
	}
	res.Output = out
	switch {
	case errors.Is(err, ErrNotApplicable):
		res.Status = StatusSkipped
		res.Err = err.Error()
	case err != nil:
		res.Status = StatusError
		res.Err = err.Error()
	case ctx.Err() != nil:
		res.Status = StatusError
		res.Err = ctx.Err().Error()
	case out.Partial:
		res.Status = StatusPartial
	default:
		res.Status = StatusOK
	}
	return res
}

// RecordsFormat identifies the per-collector JSON payload.
const RecordsFormat = "evidencelocker/records/v1"

// RecordFile is the on-disk form of one collector's records
// (collectors/<name>.json inside a bundle).
type RecordFile struct {
	Format    string         `json:"format"`
	Collector string         `json:"collector"`
	Version   string         `json:"version"`
	Status    Status         `json:"status"`
	Error     string         `json:"error,omitempty"`
	Warnings  []string       `json:"warnings"`
	Records   []StoredRecord `json:"records"`
}

// StoredRecord is a Record as serialised: identity, digest and the typed
// payload. Diff rules decode Data into the collector's record type.
type StoredRecord struct {
	Key    string          `json:"key"`
	Digest string          `json:"digest"`
	Data   json.RawMessage `json:"data"`
}

// Encode serialises a result's records deterministically: records are
// sorted by (key, digest, data) so two identical collections produce
// byte-identical files.
func (r *Result) Encode() ([]byte, error) {
	rf := RecordFile{
		Format:    RecordsFormat,
		Collector: r.Name,
		Version:   r.Version,
		Status:    r.Status,
		Error:     r.Err,
		Warnings:  r.Output.Warnings,
		Records:   make([]StoredRecord, 0, len(r.Output.Records)),
	}
	if rf.Warnings == nil {
		rf.Warnings = []string{}
	}
	for _, rec := range r.Output.Records {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, fmt.Errorf("encode %s record %q: %w", r.Name, rec.Key(), err)
		}
		rf.Records = append(rf.Records, StoredRecord{Key: rec.Key(), Digest: rec.Digest(), Data: data})
	}
	sort.Slice(rf.Records, func(i, j int) bool {
		a, b := rf.Records[i], rf.Records[j]
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		if a.Digest != b.Digest {
			return a.Digest < b.Digest
		}
		return bytes.Compare(a.Data, b.Data) < 0
	})
	return marshalIndent(rf)
}

// DecodeRecordFile parses a collectors/<name>.json payload.
func DecodeRecordFile(b []byte) (*RecordFile, error) {
	var rf RecordFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rf); err != nil {
		return nil, fmt.Errorf("decode record file: %w", err)
	}
	if rf.Format != RecordsFormat {
		return nil, fmt.Errorf("decode record file: unsupported format %q", rf.Format)
	}
	return &rf, nil
}

func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
