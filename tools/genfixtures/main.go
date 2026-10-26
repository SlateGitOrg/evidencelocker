// Command genfixtures regenerates the synthetic host trees in
// testdata/hosts (regular files plus a symlinks.txt manifest; symlinks are
// recreated at test time). Run via "make fixtures".
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/SlateGitOrg/evidencelocker/internal/fixtree"
	"github.com/SlateGitOrg/evidencelocker/internal/fixtures"
)

func main() {
	out := flag.String("out", "testdata/hosts", "output directory (must not exist)")
	from := flag.String("materialize", "", "instead of generating, copy this committed tree (testdata/hosts) to -out and recreate its symlinks")
	flag.Parse()
	var err error
	if *from != "" {
		err = fixtree.Materialize(*from, *out)
	} else {
		err = fixtures.Export(*out)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "genfixtures:", err)
		os.Exit(1)
	}
}
