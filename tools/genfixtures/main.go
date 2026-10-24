// Command genfixtures regenerates the synthetic host trees in
// testdata/hosts. Run via "make fixtures".
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/archit2501/evidencelocker/internal/fixtures"
)

func main() {
	out := flag.String("out", "testdata/hosts", "output directory (must not exist)")
	flag.Parse()
	if err := os.Mkdir(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "genfixtures:", err)
		os.Exit(1)
	}
	for _, h := range fixtures.Hosts {
		if err := fixtures.Build(filepath.Join(*out, h), h); err != nil {
			fmt.Fprintln(os.Stderr, "genfixtures:", err)
			os.Exit(1)
		}
	}
}
