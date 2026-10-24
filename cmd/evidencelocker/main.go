// Command evidencelocker is a live-response triage collector that seals
// what it collects into signed, Merkle-verified evidence bundles with a
// hash-chained chain-of-custody log. Run "evidencelocker help" for usage.
package main

import (
	"os"

	"github.com/archit2501/evidencelocker/pkg/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
