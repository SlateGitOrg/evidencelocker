package fixtures

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/SlateGitOrg/evidencelocker/internal/fixtree"
)

// Export builds every fixture into dir (which must not exist) the way they are
// committed: regular files plus the fixtree.ManifestName manifest, no symlinks.
func Export(dir string) error {
	if err := os.Mkdir(dir, 0o750); err != nil {
		return err
	}
	var lines []string
	for _, h := range Hosts {
		root := filepath.Join(dir, h)
		if err := Build(root, h); err != nil {
			return err
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.Type()&fs.ModeSymlink == 0 {
				return err
			}
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(dir, p)
			lines = append(lines, filepath.ToSlash(rel)+fixtree.LinkSep+target)
			return os.Remove(p)
		})
		if err != nil {
			return err
		}
	}
	sort.Strings(lines)
	return os.WriteFile(filepath.Join(dir, fixtree.ManifestName), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}
