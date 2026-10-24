package filehash

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/archit2501/evidencelocker/internal/testutil"
)

// BenchmarkCollect2000Files hashes a synthetic /usr/bin of 2,000 files of
// 16 KiB (31 MiB) with the default worker count.
func BenchmarkCollect2000Files(b *testing.B) {
	dir := b.TempDir()
	bin := filepath.Join(dir, "usr", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 16<<10)
	for i := 0; i < 2000; i++ {
		data[0] = byte(i)
		if err := os.WriteFile(filepath.Join(bin, fmt.Sprintf("tool%04d", i)), data, 0o755); err != nil {
			b.Fatal(err)
		}
	}
	env := testutil.Env(b, dir)
	b.SetBytes(2000 * 16 << 10)
	b.ResetTimer()
	for range b.N {
		out, err := New().Collect(context.Background(), env)
		if err != nil || len(out.Records) != 2000 {
			b.Fatalf("%v %d", err, len(out.Records))
		}
	}
}
