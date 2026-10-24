package merkle

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"testing"
)

// Reference implementation transcribed directly from RFC 9162 2.1.1 and
// 2.1.3.1 (recursive MTH and PATH), used as the oracle for the iterative
// implementation.
func refMTH(d []Hash) Hash {
	switch len(d) {
	case 0:
		return EmptyRoot
	case 1:
		return d[0]
	}
	k := largestPow2Below(len(d))
	return NodeHash(refMTH(d[:k]), refMTH(d[k:]))
}

func refPath(m int, d []Hash) []Hash {
	n := len(d)
	if n == 1 {
		return nil
	}
	k := largestPow2Below(n)
	if m < k {
		return append(refPath(m, d[:k]), refMTH(d[k:]))
	}
	return append(refPath(m-k, d[k:]), refMTH(d[:k]))
}

func largestPow2Below(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func leaves(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(i))
		out[i] = LeafHash(b[:])
	}
	return out
}

func TestMatchesRFCReference(t *testing.T) {
	for n := 0; n <= 130; n++ {
		ls := leaves(n)
		tr := New(ls)
		if got, want := tr.Root(), refMTH(ls); got != want {
			t.Fatalf("n=%d: root %s, reference %s", n, got, want)
		}
		for i := 0; i < n; i++ {
			p, err := tr.Proof(i)
			if err != nil {
				t.Fatal(err)
			}
			ref := refPath(i, ls)
			if len(p) != len(ref) {
				t.Fatalf("n=%d i=%d: proof len %d, reference %d", n, i, len(p), len(ref))
			}
			for k := range p {
				if p[k] != ref[k] {
					t.Fatalf("n=%d i=%d: proof[%d] differs from reference", n, i, k)
				}
			}
			if err := VerifyInclusion(ls[i], i, n, p, tr.Root()); err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
		}
	}
}

// Known-answer test: RFC 6962 reference vectors for the 8 leaves used by
// the certificate-transparency test suites ("" , 0x00, 0x10, ...).
func TestKnownAnswer(t *testing.T) {
	inputs := [][]byte{
		{}, {0x00}, {0x10}, {0x20, 0x21}, {0x30, 0x31},
		{0x40, 0x41, 0x42, 0x43}, {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57},
		{0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f},
	}
	want := []string{
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
		"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
		"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
		"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	}
	var ls []Hash
	for i, in := range inputs {
		ls = append(ls, LeafHash(in))
		if got := New(ls).Root().String(); got != want[i] {
			t.Errorf("tree of %d leaves: root %s, want %s", i+1, got, want[i])
		}
	}
	if New(nil).Root().String() != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Error("empty root must be SHA-256 of the empty string")
	}
}

// Property: altering any proof element, the leaf, the index or the size
// makes verification fail.
func TestProofTamperProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for trial := 0; trial < 300; trial++ {
		n := 2 + r.IntN(200)
		ls := leaves(n)
		tr := New(ls)
		i := r.IntN(n)
		p, _ := tr.Proof(i)
		root := tr.Root()
		if len(p) > 0 {
			k := r.IntN(len(p))
			bad := append([]Hash(nil), p...)
			bad[k][r.IntN(32)] ^= 1 << r.IntN(8)
			if VerifyInclusion(ls[i], i, n, bad, root) == nil {
				t.Fatalf("n=%d i=%d: tampered proof element accepted", n, i)
			}
			if VerifyInclusion(ls[i], i, n, p[:len(p)-1], root) == nil {
				t.Fatalf("n=%d i=%d: truncated proof accepted", n, i)
			}
		}
		if VerifyInclusion(ls[i], i, n, append(p, root), root) == nil {
			t.Fatalf("n=%d i=%d: extended proof accepted", n, i)
		}
		other := LeafHash([]byte("not a leaf"))
		if VerifyInclusion(other, i, n, p, root) == nil {
			t.Fatalf("n=%d i=%d: wrong leaf accepted", n, i)
		}
		if j := (i + 1) % n; VerifyInclusion(ls[i], j, n, p, root) == nil && ls[i] != ls[j] {
			t.Fatalf("n=%d i=%d: wrong index %d accepted", n, i, j)
		}
	}
}

func TestDomainSeparation(t *testing.T) {
	a, b := LeafHash([]byte("a")), LeafHash([]byte("b"))
	node := NodeHash(a, b)
	// An interior node presented as a leaf must not collide.
	if LeafHash(append(a[:], b[:]...)) == node {
		t.Fatal("leaf and node hashes collide")
	}
	plain := sha256.Sum256([]byte("a"))
	if Hash(plain) == a {
		t.Fatal("leaf hash is not domain separated")
	}
}

func TestErrorsAndParse(t *testing.T) {
	tr := New(leaves(3))
	if _, err := tr.Proof(3); !errors.Is(err, ErrIndex) {
		t.Fatalf("want ErrIndex, got %v", err)
	}
	if _, err := tr.Proof(-1); !errors.Is(err, ErrIndex) {
		t.Fatal("negative index")
	}
	if err := VerifyInclusion(tr.Leaf(0), 5, 3, nil, tr.Root()); !errors.Is(err, ErrIndex) {
		t.Fatal("verify out of range index")
	}
	if err := VerifyInclusion(tr.Leaf(0), 0, 1, []Hash{tr.Leaf(1)}, tr.Leaf(0)); !errors.Is(err, ErrProof) {
		t.Fatal("proof longer than height must fail")
	}
	h := tr.Root()
	back, err := ParseHash(h.String())
	if err != nil || back != h {
		t.Fatal("parse round trip")
	}
	for _, bad := range []string{"", "zz", h.String()[:63] + "G", "ABCDEF" + h.String()[6:]} {
		if _, err := ParseHash(bad); err == nil {
			t.Errorf("ParseHash(%q) accepted", bad)
		}
	}
}

func FuzzVerifyInclusion(f *testing.F) {
	f.Add(uint16(5), uint16(2), []byte{1, 2, 3})
	f.Add(uint16(1), uint16(0), []byte{})
	f.Fuzz(func(t *testing.T, size, index uint16, noise []byte) {
		n := int(size%300) + 1
		i := int(index) % n
		ls := leaves(n)
		tr := New(ls)
		p, err := tr.Proof(i)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyInclusion(ls[i], i, n, p, tr.Root()); err != nil {
			t.Fatalf("valid proof rejected: %v", err)
		}
		// Arbitrary noise applied to the proof must never verify (and never panic).
		if len(noise) > 0 && len(p) > 0 {
			k := int(noise[0]) % len(p)
			changed := false
			for j, b := range noise[1:] {
				if b != 0 {
					p[k][j%32] ^= b
					changed = true
				}
			}
			if changed && p[k] != tr.Root() && VerifyInclusion(ls[i], i, n, p, tr.Root()) == nil {
				t.Fatal("mutated proof verified")
			}
		}
	})
}

func BenchmarkBuild100k(b *testing.B) {
	ls := leaves(100_000)
	b.ResetTimer()
	for range b.N {
		New(ls)
	}
}

func BenchmarkProofVerify100k(b *testing.B) {
	ls := leaves(100_000)
	tr := New(ls)
	root := tr.Root()
	b.ResetTimer()
	for i := range b.N {
		idx := i % len(ls)
		p, _ := tr.Proof(idx)
		if err := VerifyInclusion(ls[idx], idx, len(ls), p, root); err != nil {
			b.Fatal(err)
		}
	}
}
