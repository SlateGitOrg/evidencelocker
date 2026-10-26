package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/SlateGitOrg/evidencelocker/pkg/bundle"
	"github.com/SlateGitOrg/evidencelocker/pkg/custody"
	"github.com/SlateGitOrg/evidencelocker/pkg/keys"
)

func (a *App) cmdKeygen(_ context.Context, args []string) int {
	fs := a.newFlags("keygen", "--out BASE   (writes BASE.key and BASE.pub)")
	out := fs.String("out", "", "output path prefix")
	if _, code, ok := a.parse(fs, args, 0, 0); !ok {
		return code
	}
	if *out == "" {
		fs.Usage()
		return ExitUsage
	}
	pub, priv, err := keys.Generate(nil)
	if err != nil {
		return a.fail(err)
	}
	if err := keys.WritePair(*out, pub, priv); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Stdout, "private key  %s.key (mode 0600, keep offline)\n", *out)
	fmt.Fprintf(a.Stdout, "public key   %s.pub\n", *out)
	fmt.Fprintf(a.Stdout, "key id       %s\n", keys.KeyID(pub))
	return ExitOK
}

// verifyResult is the JSON shape of `verify --json`.
type verifyResult struct {
	OK      bool            `json:"ok"`
	Bundle  *bundle.Report  `json:"bundle"`
	Custody *custody.Report `json:"custody,omitempty"`
}

func (a *App) cmdVerify(_ context.Context, args []string) int {
	fs := a.newFlags("verify", "[--trusted-key PUB]... [--custody LOG] [--expect-head HASH] [--json] BUNDLE")
	var trustedPaths listFlag
	fs.Var(&trustedPaths, "trusted-key", "pin an acceptable signer public key (repeatable)")
	logPath := fs.String("custody", "", "custody log to verify and bind to this bundle")
	expectHead := fs.String("expect-head", "", "custody head hash previously recorded out of band")
	asJSON := fs.Bool("json", false, "emit a JSON report")
	pos, code, ok := a.parse(fs, args, 1, 1)
	if !ok {
		return code
	}
	trustedKeys, err := bundle.LoadTrustedKeys(trustedPaths)
	if err != nil {
		return a.fail(err)
	}
	opts := bundle.VerifyOptions{TrustedKeys: trustedKeys}
	var seal *custody.Entry
	if *logPath != "" {
		pre, err := custody.VerifyFile(*logPath, custody.VerifyOptions{})
		if err != nil {
			return a.fail(err)
		}
		if len(pre.Entries) > 0 {
			seal = &pre.Entries[0]
			opts.ExpectFileSHA256 = seal.BundleSHA256
		}
	}
	rep, err := bundle.VerifyFile(pos[0], opts)
	if err != nil {
		return a.fail(err)
	}
	res := verifyResult{OK: rep.OK, Bundle: rep}
	if *logPath != "" {
		copts := custody.VerifyOptions{
			Bundle:     &custody.Bundle{FileSHA256: rep.FileSHA256, MerkleRoot: rep.MerkleRoot},
			SealKeys:   trustedKeys,
			ExpectHead: *expectHead,
		}
		if rep.Head != nil {
			copts.Bundle.CaseID = rep.Head.CaseID
		}
		crep, err := custody.VerifyFile(*logPath, copts)
		if err != nil {
			return a.fail(err)
		}
		res.Custody = crep
		res.OK = res.OK && crep.OK
	}
	if *asJSON {
		if c := a.printJSON(res); c != ExitOK {
			return c
		}
	} else {
		a.printVerify(pos[0], rep)
		if res.Custody != nil {
			a.printCustody(*logPath, res.Custody)
		}
	}
	if !res.OK {
		return ExitFindings
	}
	return ExitOK
}

func (a *App) printVerify(path string, rep *bundle.Report) {
	w := a.Stdout
	fmt.Fprintf(w, "bundle   %s\n", path)
	fmt.Fprintf(w, "sha256   %s (%d bytes)\n", rep.FileSHA256, rep.FileSize)
	if rep.KeyID != "" {
		trust := "NOT PINNED"
		if rep.Trusted {
			trust = "trusted"
		}
		fmt.Fprintf(w, "signer   %s (%s)\n", rep.KeyID, trust)
	}
	if rep.Head != nil {
		fmt.Fprintf(w, "merkle   %s over %d entries\n", rep.Head.MerkleRoot, rep.Head.TreeSize)
	}
	if rep.OK {
		fmt.Fprintf(w, "result   OK: %d entries, signature, Merkle root, layout and compression all verified\n", rep.Entries)
	} else {
		fmt.Fprintf(w, "result   FAILED: %d finding(s)\n", len(rep.Findings))
		for _, f := range rep.Findings {
			fmt.Fprintf(w, "  - %s\n", f)
		}
	}
	for _, n := range rep.Notes {
		fmt.Fprintf(w, "note     %s\n", n)
	}
}

func (a *App) printCustody(path string, rep *custody.Report) {
	w := a.Stdout
	status := "OK"
	if !rep.OK {
		status = fmt.Sprintf("FAILED: %d finding(s)", len(rep.Findings))
	}
	noun := "entries"
	if len(rep.Entries) == 1 {
		noun = "entry"
	}
	fmt.Fprintf(w, "custody  %s: %d %s, current custodian %s, head %s: %s\n",
		path, len(rep.Entries), noun, rep.Custodian, rep.Head, status)
	for _, f := range rep.Findings {
		fmt.Fprintf(w, "  - %s\n", f)
	}
}

func (a *App) cmdInspect(_ context.Context, args []string) int {
	fs := a.newFlags("inspect", "[--trusted-key PUB]... [--json] BUNDLE")
	var trustedPaths listFlag
	fs.Var(&trustedPaths, "trusted-key", "pin an acceptable signer public key (repeatable)")
	asJSON := fs.Bool("json", false, "print the verified manifest as JSON")
	pos, code, ok := a.parse(fs, args, 1, 1)
	if !ok {
		return code
	}
	b, code, ok := a.open(pos[0], trustedPaths)
	if !ok {
		return code
	}
	m := b.Manifest
	if *asJSON {
		return a.printJSON(m)
	}
	w := a.Stdout
	fmt.Fprintf(w, "case       %s (examiner %s)\n", m.CaseID, m.Examiner)
	fmt.Fprintf(w, "collected  %s by %s %s\n", m.CreatedAt.Format("2006-01-02T15:04:05Z"), m.Tool.Name, m.Tool.Version)
	fmt.Fprintf(w, "host       %s (%s) root=%s live=%v\n", m.Host.Hostname, m.Host.OS, m.Host.Root, m.Host.Live)
	fmt.Fprintf(w, "signer     %s\n", b.Head.KeyID)
	fmt.Fprintf(w, "merkle     %s (%d leaves)\n", m.Merkle.Root, m.Merkle.TreeSize)
	fmt.Fprintln(w, "collectors")
	for _, c := range m.Collectors {
		line := fmt.Sprintf("  %-12s %-6s %-8s %5d records %4d captures %6dms", c.Name, c.Version, c.Status, c.Records, c.Captures, c.DurationMS)
		if c.Error != "" {
			line += "  (" + c.Error + ")"
		}
		fmt.Fprintln(w, line)
	}
	var total int64
	for _, e := range m.Entries {
		total += e.Size
	}
	fmt.Fprintf(w, "entries    %d (%d bytes uncompressed)\n", len(m.Entries), total)
	for _, e := range m.Entries {
		fmt.Fprintf(w, "  %8d  %s  %s\n", e.Size, e.SHA256[:16], e.Path)
	}
	return ExitOK
}

// open verifies and opens a bundle, printing findings on failure.
func (a *App) open(path string, trustedPaths []string) (*bundle.Bundle, int, bool) {
	trustedKeys, err := bundle.LoadTrustedKeys(trustedPaths)
	if err != nil {
		return nil, a.fail(err), false
	}
	b, err := bundle.Open(path, bundle.VerifyOptions{TrustedKeys: trustedKeys})
	var ve *bundle.VerificationError
	if errors.As(err, &ve) {
		a.printVerify(path, ve.Report)
		return nil, ExitFindings, false
	}
	if err != nil {
		return nil, a.fail(err), false
	}
	return b, ExitOK, true
}

func (a *App) cmdExtract(_ context.Context, args []string) int {
	fs := a.newFlags("extract", "--path ENTRY [-o FILE] [--trusted-key PUB]... BUNDLE")
	entry := fs.String("path", "", "entry path inside the bundle (e.g. files/etc/crontab)")
	out := fs.String("o", "", "write to FILE (must not exist) instead of stdout")
	var trustedPaths listFlag
	fs.Var(&trustedPaths, "trusted-key", "pin an acceptable signer public key (repeatable)")
	pos, code, ok := a.parse(fs, args, 1, 1)
	if !ok {
		return code
	}
	if *entry == "" {
		fs.Usage()
		return ExitUsage
	}
	b, code, ok := a.open(pos[0], trustedPaths)
	if !ok {
		return code
	}
	data, err := b.ReadEntry(*entry)
	if err != nil {
		return a.fail(err)
	}
	if *out == "" {
		_, err = a.Stdout.Write(data)
	} else {
		err = writeNew(*out, data)
	}
	if err != nil {
		return a.fail(err)
	}
	return ExitOK
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // extracted evidence copies are analyst files
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (a *App) cmdProve(_ context.Context, args []string) int {
	fs := a.newFlags("prove", "--path ENTRY [-o PROOF.json] [--trusted-key PUB]... BUNDLE")
	entry := fs.String("path", "", "entry path to prove")
	out := fs.String("o", "", "write proof to FILE (must not exist) instead of stdout")
	var trustedPaths listFlag
	fs.Var(&trustedPaths, "trusted-key", "pin an acceptable signer public key (repeatable)")
	pos, code, ok := a.parse(fs, args, 1, 1)
	if !ok {
		return code
	}
	if *entry == "" {
		fs.Usage()
		return ExitUsage
	}
	b, code, ok := a.open(pos[0], trustedPaths)
	if !ok {
		return code
	}
	p, err := b.Prove(*entry)
	if err != nil {
		return a.fail(err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return a.fail(err)
	}
	data = append(data, '\n')
	if *out == "" {
		_, err = a.Stdout.Write(data)
	} else {
		err = writeNew(*out, data)
	}
	if err != nil {
		return a.fail(err)
	}
	return ExitOK
}

func (a *App) cmdVerifyProof(_ context.Context, args []string) int {
	fs := a.newFlags("verify-proof", "[--trusted-key PUB]... [--content FILE] PROOF.json")
	var trustedPaths listFlag
	fs.Var(&trustedPaths, "trusted-key", "pin an acceptable signer public key (repeatable)")
	contentPath := fs.String("content", "", "file whose bytes must match the proven entry")
	pos, code, ok := a.parse(fs, args, 1, 1)
	if !ok {
		return code
	}
	raw, err := os.ReadFile(pos[0])
	if err != nil {
		return a.fail(err)
	}
	var p bundle.Proof
	dec := json.NewDecoder(bufio.NewReader(bytes.NewReader(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return a.fail(fmt.Errorf("proof: %w", err))
	}
	var trustedKeys []ed25519.PublicKey
	if trustedKeys, err = bundle.LoadTrustedKeys(trustedPaths); err != nil {
		return a.fail(err)
	}
	var content []byte
	if *contentPath != "" {
		if content, err = os.ReadFile(*contentPath); err != nil {
			return a.fail(err)
		}
	}
	res, err := bundle.VerifyProof(&p, trustedKeys, content)
	if err != nil {
		fmt.Fprintf(a.Stdout, "proof    INVALID: %v\n", err)
		return ExitFindings
	}
	trust := "signer NOT PINNED"
	if res.Trusted {
		trust = "trusted signer"
	}
	fmt.Fprintf(a.Stdout, "proof    OK: %s (%d bytes, sha256 %s)\n", p.Entry.Path, p.Entry.Size, p.Entry.SHA256)
	fmt.Fprintf(a.Stdout, "         leaf %d of %d under root %s, case %s, %s %s\n",
		p.Index, res.Head.TreeSize, res.Head.MerkleRoot, res.Head.CaseID, trust, res.KeyID)
	if content != nil {
		fmt.Fprintf(a.Stdout, "content  matches the proven entry\n")
	}
	return ExitOK
}
