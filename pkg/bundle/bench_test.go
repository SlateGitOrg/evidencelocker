package bundle

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
)

// benchItems returns n incompressible items of size bytes each, so the
// benchmark measures hashing/encoding rather than compression wins.
func benchItems(n, size int) []Item {
	r := rand.New(rand.NewPCG(1, 1))
	items := make([]Item, n)
	for i := range items {
		b := make([]byte, size)
		for j := 0; j+8 <= size; j += 8 {
			v := r.Uint64()
			for k := 0; k < 8; k++ {
				b[j+k] = byte(v >> (8 * k))
			}
		}
		items[i] = Item{Path: fmt.Sprintf("files/data/%05d.bin", i), Data: b}
	}
	return items
}

const benchN, benchSize = 256, 128 << 10 // 32 MiB of payload

func BenchmarkSeal32MiB(b *testing.B) {
	items := benchItems(benchN, benchSize)
	b.SetBytes(benchN * benchSize)
	b.ResetTimer()
	for range b.N {
		var buf bytes.Buffer
		if _, err := Seal(&buf, items, testOpts()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify32MiB(b *testing.B) {
	var buf bytes.Buffer
	if _, err := Seal(&buf, benchItems(benchN, benchSize), testOpts()); err != nil {
		b.Fatal(err)
	}
	p := filepath.Join(b.TempDir(), "bench.tar.zst")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(benchN * benchSize)
	b.ResetTimer()
	for range b.N {
		rep, err := VerifyFile(p, trusted1())
		if err != nil || !rep.OK {
			b.Fatalf("%v %v", err, rep.Findings)
		}
	}
}
