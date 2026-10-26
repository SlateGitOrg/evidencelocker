// Command tampereval measures tamper detection on a realistic bundle: it
// seals a fixture host, then flips every byte (XOR mask) of (a) the
// uncompressed tar stream and (b) the compressed .tar.zst file, verifies
// each mutant, and reports how many were detected and, for the tar stream,
// how many were localised (some finding's byte span contains the flip).
//
//	go run ./tools/tampereval -fixture compromised -mask 0xff
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/SlateGitOrg/evidencelocker/pkg/bundle"
	"github.com/SlateGitOrg/evidencelocker/pkg/collector"
	"github.com/SlateGitOrg/evidencelocker/pkg/collectors/builtin"
	"github.com/SlateGitOrg/evidencelocker/pkg/triage"
)

func main() {
	fixture := flag.String("fixture", "compromised", "fixture host under testdata/hosts")
	mask := flag.Uint("mask", 0xff, "XOR mask applied to each byte")
	stride := flag.Int("stride", 1, "test every Nth offset")
	flag.Parse()
	if err := run(*fixture, byte(*mask), *stride); err != nil {
		fmt.Fprintln(os.Stderr, "tampereval:", err)
		os.Exit(1)
	}
}

func run(fixture string, mask byte, stride int) error {
	if mask == 0 || stride < 1 {
		return fmt.Errorf("mask must be non-zero and stride >= 1")
	}
	work, err := os.MkdirTemp("", "tampereval-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	opts := bundle.VerifyOptions{TrustedKeys: []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}}
	out := filepath.Join(work, "b.tar.zst")
	res, err := triage.Run(context.Background(), triage.Options{
		Root: filepath.Join("testdata", "hosts", fixture), Registry: builtin.Registry(), CaseID: "EVAL",
		Examiner: "eval", Signer: key, Out: out, ToolVersion: "eval",
		Clock: collector.FixedClock{T: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)},
	})
	if err != nil {
		return err
	}
	z, err := os.ReadFile(out)
	if err != nil {
		return err
	}
	dec, err := zstd.NewReader(bytes.NewReader(z))
	if err != nil {
		return err
	}
	tarb, err := io.ReadAll(dec)
	dec.Close()
	if err != nil {
		return err
	}
	fmt.Printf("bundle: fixture %q, %d entries, %d bytes tar, %d bytes compressed, mask %#02x, stride %d\n",
		fixture, len(res.Sealed.Manifest.Entries), len(tarb), len(z), mask, stride)

	start := time.Now()
	var n, detected, localized int
	codes := map[bundle.Code]int{}
	for off := 0; off < len(tarb); off += stride {
		mut := append([]byte(nil), tarb...)
		mut[off] ^= mask
		rep := bundle.VerifyTar(mut, opts)
		n++
		if rep.OK {
			continue
		}
		detected++
		codes[rep.Findings[0].Code]++
		if located(rep, int64(off)) {
			localized++
		}
	}
	fmt.Printf("tar stream:  %d/%d flips detected (%.2f%%), %d/%d localised to the flipped byte's region (%.2f%%) in %s\n",
		detected, n, pct(detected, n), localized, n, pct(localized, n), time.Since(start).Round(time.Millisecond))
	printCodes(codes)

	start = time.Now()
	n, detected = 0, 0
	codes = map[bundle.Code]int{}
	p := filepath.Join(work, "m.tar.zst")
	for off := 0; off < len(z); off += stride {
		mut := append([]byte(nil), z...)
		mut[off] ^= mask
		if err := os.WriteFile(p, mut, 0o600); err != nil { //nolint:gosec // G703: p is inside our own MkdirTemp dir
			return err
		}
		rep, err := bundle.VerifyFile(p, opts)
		if err != nil {
			return err
		}
		n++
		if !rep.OK {
			detected++
			codes[rep.Findings[0].Code]++
		}
	}
	fmt.Printf("compressed:  %d/%d flips detected (%.2f%%) without any external digest in %s\n",
		detected, n, pct(detected, n), time.Since(start).Round(time.Millisecond))
	printCodes(codes)
	return nil
}

func located(rep *bundle.Report, off int64) bool {
	for _, f := range rep.Findings {
		for _, s := range f.Spans {
			if s.Contains(off) {
				return true
			}
		}
	}
	return false
}

func pct(a, b int) float64 { return 100 * float64(a) / float64(b) }

func printCodes(codes map[bundle.Code]int) {
	keys := make([]string, 0, len(codes))
	for k := range codes {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("    first finding %-26s %6d\n", k, codes[bundle.Code(k)])
	}
}
