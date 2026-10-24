package cli

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/archit2501/evidencelocker/pkg/baseline"
	"github.com/archit2501/evidencelocker/pkg/bundle"
	"github.com/archit2501/evidencelocker/pkg/custody"
	"github.com/archit2501/evidencelocker/pkg/keys"
)

func (a *App) cmdDiff(_ context.Context, args []string) int {
	fs := a.newFlags("diff", "[--trusted-key PUB]... [--fail-on SEV] [--show SEV] [--json] BASELINE CURRENT")
	var trustedPaths listFlag
	fs.Var(&trustedPaths, "trusted-key", "pin an acceptable signer public key (repeatable)")
	failOn := fs.String("fail-on", "medium", "exit 1 if any finding is at least this severity (info|low|medium|high|critical)")
	show := fs.String("show", "low", "minimum severity to print in text output")
	asJSON := fs.Bool("json", false, "emit the full report as JSON")
	pos, code, ok := a.parse(fs, args, 2, 2)
	if !ok {
		return code
	}
	threshold, err := baseline.ParseSeverity(*failOn)
	if err != nil {
		return a.fail(err)
	}
	minShow, err := baseline.ParseSeverity(*show)
	if err != nil {
		return a.fail(err)
	}
	trustedKeys, err := bundle.LoadTrustedKeys(trustedPaths)
	if err != nil {
		return a.fail(err)
	}
	var snaps [2]*baseline.Snapshot
	for i, p := range pos {
		s, err := baseline.LoadSnapshot(p, bundle.VerifyOptions{TrustedKeys: trustedKeys})
		if err != nil {
			return a.fail(fmt.Errorf("%s: %w", p, err))
		}
		snaps[i] = s
	}
	rep := baseline.Compare(snaps[0], snaps[1])
	if *asJSON {
		if c := a.printJSON(rep); c != ExitOK {
			return c
		}
	} else if err := rep.WriteText(a.Stdout, minShow); err != nil {
		return a.fail(err)
	}
	if rep.AtLeast(threshold) > 0 {
		return ExitFindings
	}
	return ExitOK
}

func (a *App) cmdCustody(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" {
		fmt.Fprintln(a.Stderr, "usage: evidencelocker custody <append|verify|show> [flags]")
		fmt.Fprintln(a.Stderr, "  append  --log L --key K --actor NAME --action transfer|access|verify|note [--to NAME --to-key PUB] [--note TEXT]")
		fmt.Fprintln(a.Stderr, "  verify  --log L [--bundle B] [--trusted-key PUB]... [--expect-head HASH] [--json]")
		fmt.Fprintln(a.Stderr, "  show    --log L")
		if len(args) == 0 {
			return ExitUsage
		}
		return ExitOK
	}
	switch args[0] {
	case "append":
		return a.custodyAppend(ctx, args[1:])
	case "verify":
		return a.custodyVerify(ctx, args[1:])
	case "show":
		return a.custodyShow(ctx, args[1:])
	}
	return a.fail(fmt.Errorf("unknown custody subcommand %q", args[0]))
}

func (a *App) custodyAppend(_ context.Context, args []string) int {
	fs := a.newFlags("custody append", "--log L --key K --actor NAME --action ACTION [flags]")
	logPath := fs.String("log", "", "custody log")
	keyPath := fs.String("key", "", "current custodian's private key")
	actor := fs.String("actor", "", "current custodian's name")
	action := fs.String("action", "", "transfer, access, verify or note")
	to := fs.String("to", "", "recipient name (transfer)")
	toKey := fs.String("to-key", "", "recipient public key file (transfer)")
	note := fs.String("note", "", "free-text note")
	if _, code, ok := a.parse(fs, args, 0, 0); !ok {
		return code
	}
	if *logPath == "" || *keyPath == "" || *actor == "" || *action == "" {
		fs.Usage()
		return ExitUsage
	}
	priv, err := keys.LoadPrivate(*keyPath)
	if err != nil {
		return a.fail(err)
	}
	req := custody.AppendRequest{
		Action: custody.Action(*action), Signer: custody.Signer{Name: *actor, Key: priv},
		Recipient: *to, Note: *note, Now: a.Clock.Now(),
	}
	if *toKey != "" {
		var pub ed25519.PublicKey
		if pub, err = keys.LoadPublic(*toKey); err != nil {
			return a.fail(err)
		}
		req.RecipientKey = pub
	}
	e, err := custody.Append(*logPath, req)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Stdout, "appended seq %d (%s by %s)\nhead %s\n", e.Seq, e.Action, e.Actor, e.Hash)
	return ExitOK
}

func (a *App) custodyVerify(_ context.Context, args []string) int {
	fs := a.newFlags("custody verify", "--log L [--bundle B] [--trusted-key PUB]... [--expect-head HASH] [--json]")
	logPath := fs.String("log", "", "custody log")
	bundlePath := fs.String("bundle", "", "bundle the log must be bound to")
	var trustedPaths listFlag
	fs.Var(&trustedPaths, "trusted-key", "keys allowed to have sealed the log (repeatable)")
	expectHead := fs.String("expect-head", "", "head hash recorded out of band (detects truncation)")
	asJSON := fs.Bool("json", false, "emit a JSON report")
	if _, code, ok := a.parse(fs, args, 0, 0); !ok {
		return code
	}
	if *logPath == "" {
		fs.Usage()
		return ExitUsage
	}
	trustedKeys, err := bundle.LoadTrustedKeys(trustedPaths)
	if err != nil {
		return a.fail(err)
	}
	opts := custody.VerifyOptions{SealKeys: trustedKeys, ExpectHead: *expectHead}
	if *bundlePath != "" {
		brep, err := bundle.VerifyFile(*bundlePath, bundle.VerifyOptions{TrustedKeys: trustedKeys})
		if err != nil {
			return a.fail(err)
		}
		opts.Bundle = &custody.Bundle{FileSHA256: brep.FileSHA256, MerkleRoot: brep.MerkleRoot}
	}
	rep, err := custody.VerifyFile(*logPath, opts)
	if err != nil {
		return a.fail(err)
	}
	if *asJSON {
		if c := a.printJSON(rep); c != ExitOK {
			return c
		}
	} else {
		a.printCustody(*logPath, rep)
	}
	if !rep.OK {
		return ExitFindings
	}
	return ExitOK
}

func (a *App) custodyShow(_ context.Context, args []string) int {
	fs := a.newFlags("custody show", "--log L")
	logPath := fs.String("log", "", "custody log")
	if _, code, ok := a.parse(fs, args, 0, 0); !ok {
		return code
	}
	if *logPath == "" {
		fs.Usage()
		return ExitUsage
	}
	rep, err := custody.VerifyFile(*logPath, custody.VerifyOptions{})
	if err != nil {
		return a.fail(err)
	}
	w := a.Stdout
	for _, e := range rep.Entries {
		key, _ := keys.DecodePublic(e.ActorKey)
		who := e.Actor
		if key != nil {
			who += " [" + keys.KeyID(key) + "]"
		}
		line := fmt.Sprintf("%3d  %s  %-8s  %s", e.Seq, e.Time, e.Action, who)
		if e.Action == custody.ActionTransfer {
			line += " -> " + e.Recipient
		}
		if e.Note != "" {
			line += "  \"" + strings.ReplaceAll(e.Note, "\n", " ") + "\""
		}
		fmt.Fprintln(w, line)
	}
	a.printCustody(*logPath, rep)
	if !rep.OK {
		return ExitFindings
	}
	return ExitOK
}
