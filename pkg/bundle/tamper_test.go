package bundle

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

var testKeySeed = bytes.Repeat([]byte{7}, ed25519.SeedSize)

func testKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(testKeySeed) }

func testItems() []Item {
	return []Item{
		{Path: "collectors/persistence.json", Data: []byte(`{"records":[{"key":"cron|/etc/crontab"}]}` + "\n")},
		{Path: "files/etc/crontab", Data: []byte("* * * * * root /usr/local/bin/backup\n")},
		{Path: "files/etc/passwd", Data: []byte("root:x:0:0:root:/root:/bin/bash\n")},
		{Path: "collectors/empty.json", Data: []byte{}},
		{Path: "files/" + strings.Repeat("long-directory-name/", 7) + "deep-file", Data: []byte("pax header path\n")},
	}
}

func testOpts() SealOptions {
	return SealOptions{
		CaseID: "CASE-1", Examiner: "examiner", CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Host: Host{Hostname: "fixture", OS: "test", Root: "/fixture"}, Tool: Tool{Name: "evidencelocker", Version: "test"},
		Signer: testKey(),
	}
}

func sealBytes(t testing.TB, items []Item, opts SealOptions) ([]byte, *Sealed) {
	t.Helper()
	var buf bytes.Buffer
	s, err := Seal(&buf, items, opts)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), s
}

func decompress(t testing.TB, b []byte) []byte {
	t.Helper()
	d, err := zstd.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	out, err := io.ReadAll(d)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func trusted1() VerifyOptions {
	return VerifyOptions{TrustedKeys: []ed25519.PublicKey{testKey().Public().(ed25519.PublicKey)}}
}

// TestFlipEveryTarByte flips every byte of the uncompressed archive with
// several masks and requires (a) verification fails and (b) some finding's
// span contains the flipped offset - i.e. the failure is located precisely.
func TestFlipEveryTarByte(t *testing.T) {
	z, _ := sealBytes(t, testItems(), testOpts())
	tarb := decompress(t, z)
	if rep := VerifyTar(tarb, trusted1()); !rep.OK {
		t.Fatalf("pristine archive failed: %v", rep.Findings)
	}
	masks := []byte{0xff, 0x01, 0x20}
	stride := 1
	if testing.Short() {
		stride = 7
	}
	codes := map[Code]int{}
	for _, mask := range masks {
		for off := 0; off < len(tarb); off += stride {
			mut := append([]byte(nil), tarb...)
			mut[off] ^= mask
			rep := VerifyTar(mut, trusted1())
			if rep.OK {
				t.Fatalf("mask %#x offset %d: tampering not detected", mask, off)
			}
			if !located(rep, int64(off)) {
				t.Fatalf("mask %#x offset %d: no finding spans the flipped byte: %v", mask, off, rep.Findings)
			}
			codes[rep.Findings[0].Code]++
		}
	}
	for _, want := range []Code{CodeEntryHash, CodeContainer, CodeLayout, CodeManifestDigest, CodeSignature} {
		if codes[want] == 0 {
			t.Errorf("expected some flips to yield %s; got %v", want, codes)
		}
	}
	t.Logf("tar size %d, first-finding code histogram: %v", len(tarb), codes)
}

func located(rep *Report, off int64) bool {
	for _, f := range rep.Findings {
		for _, s := range f.Spans {
			if s.Contains(off) {
				return true
			}
		}
	}
	return false
}

// TestFlipEveryCompressedByte flips every byte of the .tar.zst file. Every
// flip must fail verification, even ones that leave the decoded archive
// intact (caught by the canonical re-encoding check).
func TestFlipEveryCompressedByte(t *testing.T) {
	z, sealed := sealBytes(t, testItems(), testOpts())
	dir := t.TempDir()
	stride := 1
	if testing.Short() {
		stride = 5
	}
	codes := map[Code]int{}
	for off := 0; off < len(z); off += stride {
		mut := append([]byte(nil), z...)
		mut[off] ^= 0xff
		p := filepath.Join(dir, "b.tar.zst")
		if err := os.WriteFile(p, mut, 0o600); err != nil {
			t.Fatal(err)
		}
		opts := trusted1()
		opts.ExpectFileSHA256 = sealed.FileSHA256
		rep, err := VerifyFile(p, opts)
		if err != nil {
			t.Fatal(err)
		}
		if rep.OK {
			t.Fatalf("offset %d: tampering not detected", off)
		}
		for _, f := range rep.Findings {
			if f.Code != CodeFileDigest {
				codes[f.Code]++
				break
			}
		}
		if rep.Findings[0].Code != CodeFileDigest {
			t.Fatalf("offset %d: whole-file digest mismatch not reported first: %v", off, rep.Findings)
		}
	}
	// Without the external digest, the bundle alone must still fail.
	for off := 0; off < len(z); off += stride {
		mut := append([]byte(nil), z...)
		mut[off] ^= 0x01
		p := filepath.Join(dir, "c.tar.zst")
		if err := os.WriteFile(p, mut, 0o600); err != nil {
			t.Fatal(err)
		}
		rep, err := VerifyFile(p, trusted1())
		if err != nil {
			t.Fatal(err)
		}
		if rep.OK {
			t.Fatalf("offset %d: self-contained verification missed tampering", off)
		}
	}
	t.Logf("compressed size %d, secondary code histogram: %v", len(z), codes)
}
