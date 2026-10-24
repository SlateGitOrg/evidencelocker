package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func writeFile(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "case.tar.zst")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSealVerifyRoundTrip(t *testing.T) {
	z, sealed := sealBytes(t, testItems(), testOpts())
	p := writeFile(t, z)
	opts := trusted1()
	opts.ExpectFileSHA256 = sealed.FileSHA256
	rep, err := VerifyFile(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("findings: %v", rep.Findings)
	}
	if !rep.Trusted || rep.Entries != len(testItems()) || rep.MerkleRoot != sealed.Head.MerkleRoot {
		t.Fatalf("unexpected report %+v", rep)
	}
	if rep.FileSHA256 != sealed.FileSHA256 || rep.FileSize != int64(len(z)) {
		t.Fatalf("file digest/size mismatch")
	}
}

func TestSealDeterministic(t *testing.T) {
	a, _ := sealBytes(t, testItems(), testOpts())
	items := testItems()
	// Input order must not matter.
	items[0], items[4] = items[4], items[0]
	b, _ := sealBytes(t, items, testOpts())
	if !bytes.Equal(a, b) {
		t.Fatal("sealing the same items twice produced different bytes")
	}
}

func TestUnpinnedSignerIsNoted(t *testing.T) {
	z, _ := sealBytes(t, testItems(), testOpts())
	rep, err := VerifyFile(writeFile(t, z), VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Trusted || len(rep.Notes) == 0 {
		t.Fatalf("want OK, untrusted, with a note; got %+v", rep)
	}
}

// An attacker who edits content and re-seals with their own key produces
// a perfectly consistent bundle; only key pinning detects it.
func TestResignedByAttackerKey(t *testing.T) {
	items := testItems()
	items[1].Data = []byte("* * * * * root /tmp/.x/implant\n")
	opts := testOpts()
	opts.Signer = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	z, _ := sealBytes(t, items, opts)
	rep, err := VerifyFile(writeFile(t, z), trusted1())
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || rep.Findings[0].Code != CodeUntrustedKey {
		t.Fatalf("want UNTRUSTED_KEY, got %v", rep.Findings)
	}
}

func TestNoncanonicalCompressionDetected(t *testing.T) {
	z, _ := sealBytes(t, testItems(), testOpts())
	tarb := decompress(t, z)
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		t.Fatal(err)
	}
	enc.Write(tarb)
	enc.Close()
	if bytes.Equal(buf.Bytes(), z) {
		t.Skip("encoder levels produced identical output")
	}
	rep, err := VerifyFile(writeFile(t, buf.Bytes()), trusted1())
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || len(rep.Findings) != 1 || rep.Findings[0].Code != CodeContainerNoncan {
		t.Fatalf("want only CONTAINER_NONCANONICAL, got %v", rep.Findings)
	}
}

// rebuild re-serialises an archive member list with arbitrary edits, so
// tests can model structural attacks (removal, insertion, reordering).
func rebuild(t *testing.T, tarb []byte, edit func([]memb) []memb) []byte {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(tarb))
	var ms []memb
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		var b bytes.Buffer
		b.ReadFrom(tr)
		ms = append(ms, memb{h.Name, b.Bytes()})
	}
	ms = edit(ms)
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for _, m := range ms {
		tw.WriteHeader(canonicalHeader(m.name, int64(len(m.data))))
		tw.Write(m.data)
	}
	tw.Close()
	return out.Bytes()
}

type memb struct {
	name string
	data []byte
}

func hasCode(rep *Report, c Code, path string) bool {
	for _, f := range rep.Findings {
		if f.Code == c && (path == "" || f.Path == path) {
			return true
		}
	}
	return false
}

func TestStructuralTampering(t *testing.T) {
	z, _ := sealBytes(t, testItems(), testOpts())
	tarb := decompress(t, z)
	cases := []struct {
		name string
		edit func([]memb) []memb
		code Code
		path string
	}{
		{"remove entry", func(ms []memb) []memb { return append(ms[:1], ms[2:]...) }, CodeEntryMissing, "collectors/persistence.json"},
		{"insert entry", func(ms []memb) []memb {
			return append([]memb{{"files/tmp/dropper", []byte("x")}}, ms...)
		}, CodeEntryUnexpected, "files/tmp/dropper"},
		{"duplicate entry", func(ms []memb) []memb {
			return append([]memb{ms[2]}, ms...)
		}, CodeEntryDuplicate, ms2name(tarb, 2)},
		{"truncate entry", func(ms []memb) []memb {
			ms[2].data = ms[2].data[:3]
			return ms
		}, CodeEntrySize, ms2name(tarb, 2)},
		{"drop signature", func(ms []memb) []memb { return ms[:len(ms)-1] }, CodeMetaMissing, SigName},
		{"reorder metadata", func(ms []memb) []memb {
			n := len(ms)
			ms[n-1], ms[n-2] = ms[n-2], ms[n-1]
			return ms
		}, CodeMetaMissing, HeadName},
		{"drop manifest", func(ms []memb) []memb {
			n := len(ms)
			return append(ms[:n-3], ms[n-2:]...)
		}, CodeMetaMissing, ManifestName},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := VerifyTar(rebuild(t, tarb, tc.edit), trusted1())
			if rep.OK || !hasCode(rep, tc.code, tc.path) {
				t.Fatalf("want %s on %q, got %v", tc.code, tc.path, rep.Findings)
			}
		})
	}
}

func ms2name(tarb []byte, i int) string {
	tr := tar.NewReader(bytes.NewReader(tarb))
	for k := 0; ; k++ {
		h, err := tr.Next()
		if err != nil {
			return ""
		}
		if k == i {
			return h.Name
		}
	}
}

func TestTrailingGarbageDetected(t *testing.T) {
	z, _ := sealBytes(t, testItems(), testOpts())
	tarb := append(decompress(t, z), make([]byte, 512)...)
	tarb[len(tarb)-1] = 1
	rep := VerifyTar(tarb, trusted1())
	if rep.OK || !hasCode(rep, CodeLayout, "") {
		t.Fatalf("want LAYOUT finding, got %v", rep.Findings)
	}
}

func TestEmptyAndGarbageInput(t *testing.T) {
	for name, b := range map[string][]byte{"empty": {}, "garbage": []byte(strings.Repeat("not a tar ", 100))} {
		rep := VerifyTar(b, VerifyOptions{})
		if rep.OK {
			t.Fatalf("%s: verified", name)
		}
	}
	if _, err := VerifyFile(filepath.Join(t.TempDir(), "missing"), VerifyOptions{}); err == nil {
		t.Fatal("missing file: want error")
	}
	rep, err := VerifyFile(writeFile(t, []byte("definitely not zstd")), VerifyOptions{})
	if err != nil || rep.OK || rep.Findings[0].Code != CodeContainer {
		t.Fatalf("garbage file: %v %v", err, rep)
	}
}

func TestSealRejectsBadInput(t *testing.T) {
	var buf bytes.Buffer
	bad := [][]Item{
		{{Path: "/abs"}},
		{{Path: "a/../b"}},
		{{Path: "manifest.json"}},
		{{Path: "a"}, {Path: "a"}},
		{{Path: "bad\xffutf8"}},
		{{Path: ""}},
		{{Path: "nul\x00"}},
	}
	for _, items := range bad {
		if _, err := Seal(&buf, items, testOpts()); err == nil {
			t.Errorf("Seal(%q) succeeded", items[0].Path)
		}
	}
	o := testOpts()
	o.Signer = nil
	if _, err := Seal(&buf, nil, o); err == nil {
		t.Error("Seal without signer succeeded")
	}
	o = testOpts()
	o.CaseID = ""
	if _, err := Seal(&buf, nil, o); err == nil {
		t.Error("Seal without case id succeeded")
	}
}

func TestSealFileAtomicNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "b.tar.zst")
	if _, err := SealFile(p, testItems(), testOpts()); err != nil {
		t.Fatal(err)
	}
	if _, err := SealFile(p, testItems(), testOpts()); err == nil {
		t.Fatal("overwrote existing bundle")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temp files left behind: %v", ents)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o400 {
		t.Fatalf("mode %v, want read-only", fi.Mode())
	}
}

func TestEmptyBundle(t *testing.T) {
	z, sealed := sealBytes(t, nil, testOpts())
	if sealed.Head.TreeSize != 0 {
		t.Fatal("tree size")
	}
	rep, err := VerifyFile(writeFile(t, z), trusted1())
	if err != nil || !rep.OK {
		t.Fatalf("%v %v", err, rep.Findings)
	}
}

func TestOpenReadAndProve(t *testing.T) {
	z, _ := sealBytes(t, testItems(), testOpts())
	p := writeFile(t, z)
	b, err := Open(p, trusted1())
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.ReadEntry("files/etc/crontab")
	if err != nil || string(got) != "* * * * * root /usr/local/bin/backup\n" {
		t.Fatalf("ReadEntry: %q %v", got, err)
	}
	if _, err := b.ReadEntry("nope"); err == nil {
		t.Fatal("ReadEntry of absent path succeeded")
	}
	if ps := b.Paths("files/"); len(ps) != 3 {
		t.Fatalf("Paths: %v", ps)
	}
	all, err := b.ReadEntries(func(string) bool { return true })
	if err != nil || len(all) != len(testItems()) {
		t.Fatalf("ReadEntries: %d %v", len(all), err)
	}

	pubs := trusted1().TrustedKeys
	for _, it := range testItems() {
		proof, err := b.Prove(it.Path)
		if err != nil {
			t.Fatal(err)
		}
		// Round-trip through JSON as a user would.
		raw, _ := json.Marshal(proof)
		var back Proof
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatal(err)
		}
		res, err := VerifyProof(&back, pubs, it.Data)
		if err != nil || !res.Trusted {
			t.Fatalf("proof for %s: %v", it.Path, err)
		}
		if _, err := VerifyProof(&back, pubs, append([]byte("x"), it.Data...)); err == nil {
			t.Fatalf("proof accepted wrong content for %s", it.Path)
		}
		forged := back
		forged.Entry.Size++
		if _, err := VerifyProof(&forged, pubs, nil); err == nil {
			t.Fatalf("forged entry accepted for %s", it.Path)
		}
		forged = back
		forged.Index = (back.Index + 1) % len(testItems())
		if _, err := VerifyProof(&forged, pubs, nil); err == nil {
			t.Fatalf("wrong index accepted for %s", it.Path)
		}
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)).Public().(ed25519.PublicKey)
	proof, _ := b.Prove("files/etc/passwd")
	if _, err := VerifyProof(proof, []ed25519.PublicKey{other}, nil); err == nil {
		t.Fatal("proof accepted for untrusted signer")
	}
	if _, err := b.Prove("absent"); err == nil {
		t.Fatal("proof for absent path")
	}
}

func TestOpenRejectsTampered(t *testing.T) {
	z, _ := sealBytes(t, testItems(), testOpts())
	tarb := decompress(t, z)
	i := bytes.Index(tarb, []byte("/usr/local/bin/backup"))
	tarb[i] = 'X'
	var buf bytes.Buffer
	enc, _ := newEncoder(&buf)
	enc.Write(tarb)
	enc.Close()
	_, err := Open(writeFile(t, buf.Bytes()), trusted1())
	var ve *VerificationError
	if !errors.As(err, &ve) || !errors.Is(err, ErrNotVerified) {
		t.Fatalf("want VerificationError, got %v", err)
	}
	if !hasCode(ve.Report, CodeEntryHash, "files/etc/crontab") || !strings.Contains(err.Error(), "files/etc/crontab") {
		t.Fatalf("imprecise error: %v", err)
	}
}

func TestEncoderIDMatchesGoMod(t *testing.T) {
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mod), "github.com/klauspost/compress v1.20.1") ||
		!strings.Contains(EncoderID, "@v1.20.1;") {
		t.Fatal("EncoderID must name the klauspost/compress version pinned in go.mod")
	}
}
