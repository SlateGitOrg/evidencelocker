package bundle

import (
	"bytes"
	"testing"
)

// FuzzVerifyTar mutates a valid archive arbitrarily: the verifier must never
// panic, and must never accept anything but the exact sealed bytes.
func FuzzVerifyTar(f *testing.F) {
	z, _ := sealBytes(f, testItems()[:2], testOpts())
	tarb := decompress(f, z)
	f.Add(uint16(100), byte(1), []byte{})
	f.Add(uint16(2000), byte(0x80), []byte("x"))
	f.Fuzz(func(t *testing.T, off uint16, mask byte, insert []byte) {
		mut := append([]byte(nil), tarb...)
		i := int(off) % len(mut)
		mut[i] ^= mask
		if len(insert) > 0 {
			mut = append(mut[:i], append(append([]byte(nil), insert...), mut[i:]...)...)
		}
		rep := VerifyTar(mut, trusted1())
		if rep.OK != bytes.Equal(mut, tarb) {
			t.Fatalf("OK=%v for mutation off=%d mask=%#x insert=%d", rep.OK, i, mask, len(insert))
		}
	})
}
