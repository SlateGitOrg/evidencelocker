package custody

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func key(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

var (
	collectorKey = key(1)
	analystKey   = key(2)
	labKey       = key(3)
	t0           = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	testBundle   = Bundle{CaseID: "CASE-7", FileSHA256: strings.Repeat("ab", 32), MerkleRoot: strings.Repeat("cd", 32)}
)

// buildLog returns a 4-entry log: seal -> transfer(analyst) -> access -> transfer(lab).
func buildLog(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "case.custody.jsonl")
	if _, err := Create(p, testBundle, Signer{"collector", collectorKey}, t0, "sealed on scene"); err != nil {
		t.Fatal(err)
	}
	steps := []AppendRequest{
		{Action: ActionTransfer, Signer: Signer{"collector", collectorKey}, Recipient: "analyst", RecipientKey: pub(analystKey), Note: "courier bag 17", Now: t0.Add(time.Hour)},
		{Action: ActionAccess, Signer: Signer{"analyst", analystKey}, Note: "imaged to lab share", Now: t0.Add(2*time.Hour + 500*time.Millisecond)},
		{Action: ActionTransfer, Signer: Signer{"analyst", analystKey}, Recipient: "lab", RecipientKey: pub(labKey), Now: t0.Add(3 * time.Hour)},
	}
	for _, s := range steps {
		if _, err := Append(p, s); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func TestHappyPath(t *testing.T) {
	p := buildLog(t)
	rep, err := VerifyFile(p, VerifyOptions{Bundle: &testBundle, SealKeys: []ed25519.PublicKey{pub(collectorKey)}})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("findings: %v", rep.Findings)
	}
	if len(rep.Entries) != 4 || rep.Custodian != "lab" || rep.Head != rep.Entries[3].Hash {
		t.Fatalf("unexpected report: custodian=%s entries=%d", rep.Custodian, len(rep.Entries))
	}
	rep2, _ := VerifyFile(p, VerifyOptions{ExpectHead: rep.Head})
	if !rep2.OK || rep2.HeadIndex != 3 {
		t.Fatalf("expect-head: %v %d", rep2.Findings, rep2.HeadIndex)
	}
}

func TestOnlyCustodianMayAppend(t *testing.T) {
	p := buildLog(t)
	for _, k := range []ed25519.PrivateKey{collectorKey, analystKey} {
		_, err := Append(p, AppendRequest{Action: ActionNote, Signer: Signer{"x", k}, Now: t0.Add(4 * time.Hour)})
		if err == nil || !strings.Contains(err.Error(), "not the current custodian") {
			t.Fatalf("former custodian appended: %v", err)
		}
	}
	if _, err := Append(p, AppendRequest{Action: ActionVerify, Signer: Signer{"lab", labKey}, Now: t0.Add(4 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

func TestAppendValidation(t *testing.T) {
	p := buildLog(t)
	lab := Signer{"lab", labKey}
	bad := []AppendRequest{
		{Action: ActionSeal, Signer: lab, Now: t0.Add(5 * time.Hour)},
		{Action: "delete", Signer: lab, Now: t0.Add(5 * time.Hour)},
		{Action: ActionNote, Signer: Signer{"", labKey}, Now: t0.Add(5 * time.Hour)},
		{Action: ActionTransfer, Signer: lab, Recipient: "nobody", Now: t0.Add(5 * time.Hour)},
		{Action: ActionNote, Signer: lab, Recipient: "x", Now: t0.Add(5 * time.Hour)},
		{Action: ActionNote, Signer: lab, Now: t0}, // clock went backwards
	}
	for i, r := range bad {
		if _, err := Append(p, r); err == nil {
			t.Errorf("case %d: append accepted", i)
		}
	}
	if _, err := Append(filepath.Join(t.TempDir(), "missing"), bad[1]); err == nil {
		t.Error("append to missing log succeeded")
	}
	if _, err := Create(p, testBundle, Signer{"collector", collectorKey}, t0, ""); err == nil {
		t.Error("Create overwrote an existing log")
	}
}

func TestConcurrentAppendsStayLinear(t *testing.T) {
	p := buildLog(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = Append(p, AppendRequest{Action: ActionNote, Signer: Signer{"lab", labKey}, Note: "n", Now: t0.Add(10 * time.Hour)})
		}(i)
	}
	wg.Wait()
	rep, _ := VerifyFile(p, VerifyOptions{})
	if !rep.OK || len(rep.Entries) != 12 {
		t.Fatalf("concurrent appends broke the chain: %d entries, %v", len(rep.Entries), rep.Findings)
	}
}

func lineOf(b []byte, off int) int { return bytes.Count(b[:off], []byte("\n")) + 1 }

// TestFlipEveryLogByte: any byte flip must fail verification with a finding
// on the line that contains the byte (or the whole-log head check).
func TestFlipEveryLogByte(t *testing.T) {
	orig, err := os.ReadFile(buildLog(t))
	if err != nil {
		t.Fatal(err)
	}
	head := Verify(bytes.NewReader(orig), VerifyOptions{}).Head
	opts := VerifyOptions{Bundle: &testBundle, SealKeys: []ed25519.PublicKey{pub(collectorKey)}, ExpectHead: head}
	for _, mask := range []byte{0xff, 0x01, 0x20} {
		for off := range orig {
			mut := append([]byte(nil), orig...)
			mut[off] ^= mask
			rep := Verify(bytes.NewReader(mut), opts)
			if rep.OK {
				t.Fatalf("mask %#x offset %d: not detected", mask, off)
			}
			want := lineOf(orig, off)
			ok := false
			for _, f := range rep.Findings {
				if f.Line == want {
					ok = true
				}
			}
			if !ok {
				t.Fatalf("mask %#x offset %d (line %d): imprecise findings %v", mask, off, want, rep.Findings)
			}
		}
	}
}

func lines(t *testing.T, p string) []string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.SplitAfter(strings.TrimSuffix(string(b), "\n"), "\n")
}

func verifyLines(ls []string, opts VerifyOptions) *Report {
	return Verify(strings.NewReader(strings.Join(ls, "")), opts)
}

func hasFinding(rep *Report, line int, code string) bool {
	for _, f := range rep.Findings {
		if f.Line == line && f.Code == code {
			return true
		}
	}
	return false
}

func TestStructuralAttacks(t *testing.T) {
	ls := lines(t, buildLog(t))
	ls[len(ls)-1] += "\n"
	full := verifyLines(ls, VerifyOptions{})
	head := full.Head

	// Delete a middle entry.
	del := append(append([]string{}, ls[:1]...), ls[2:]...)
	if rep := verifyLines(del, VerifyOptions{}); !hasFinding(rep, 2, CodeChain) || !hasFinding(rep, 2, CodeSeq) {
		t.Fatalf("deletion: %v", rep.Findings)
	}
	// Swap two entries.
	sw := append([]string{}, ls...)
	sw[1], sw[2] = sw[2], sw[1]
	if rep := verifyLines(sw, VerifyOptions{}); !hasFinding(rep, 2, CodeChain) {
		t.Fatalf("reorder: %v", rep.Findings)
	}
	// Truncate the newest entry: undetectable without an anchor...
	tr := ls[:len(ls)-1]
	if rep := verifyLines(tr, VerifyOptions{}); !rep.OK {
		t.Fatalf("truncated log should be internally consistent: %v", rep.Findings)
	}
	// ...and detected with one.
	if rep := verifyLines(tr, VerifyOptions{ExpectHead: head}); !hasFinding(rep, 0, CodeHead) {
		t.Fatalf("truncation with anchor: %v", rep.Findings)
	}
	// Replay the seal line at the end.
	rp := append(append([]string{}, ls...), ls[0])
	if rep := verifyLines(rp, VerifyOptions{}); !hasFinding(rep, 5, CodeSeq) {
		t.Fatalf("replayed seal: %v", rep.Findings)
	}
	// Empty log.
	if rep := verifyLines(nil, VerifyOptions{}); rep.OK || rep.Findings[0].Code != CodeEmpty {
		t.Fatalf("empty: %v", rep.Findings)
	}
}

// A former custodian holding a valid key forges a correctly chained,
// correctly signed entry. Only custody tracking catches it.
func TestForgedEntryByFormerCustodian(t *testing.T) {
	p := buildLog(t)
	rep, _ := VerifyFile(p, VerifyOptions{})
	forged, err := next(&Report{Entries: rep.Entries, CustodianKey: rep.Entries[1].RecipientKey, Custodian: "analyst"},
		AppendRequest{Action: ActionNote, Signer: Signer{"analyst", analystKey}, Note: "backdated", Now: t0.Add(5 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := canonical(forged)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.Write(append(b, '\n'))
	f.Close()
	rep, _ = VerifyFile(p, VerifyOptions{})
	if !hasFinding(rep, 5, CodeCustodian) {
		t.Fatalf("forged entry not attributed: %v", rep.Findings)
	}
	if _, err := Append(p, AppendRequest{Action: ActionNote, Signer: Signer{"lab", labKey}, Now: t0.Add(6 * time.Hour)}); err == nil {
		t.Fatal("appended to a broken log")
	}
}

func TestBindingAndSealer(t *testing.T) {
	p := buildLog(t)
	other := testBundle
	other.FileSHA256 = strings.Repeat("00", 32)
	other.MerkleRoot = strings.Repeat("11", 32)
	other.CaseID = "OTHER"
	rep, _ := VerifyFile(p, VerifyOptions{Bundle: &other, SealKeys: []ed25519.PublicKey{pub(labKey)}})
	n := 0
	for _, f := range rep.Findings {
		if f.Line == 1 && (f.Code == CodeBinding || f.Code == CodeSealer) {
			n++
		}
	}
	if n != 4 {
		t.Fatalf("want 3 binding + 1 sealer findings on line 1, got %v", rep.Findings)
	}
	if _, err := VerifyFile(filepath.Join(t.TempDir(), "nope"), VerifyOptions{}); err == nil {
		t.Fatal("missing file verified")
	}
}

func TestInvalidSealName(t *testing.T) {
	if _, err := NewSeal(testBundle, Signer{"bad\nname", collectorKey}, t0, ""); err == nil {
		t.Fatal("accepted newline in actor name")
	}
}

func TestTimestampsOrderAsStrings(t *testing.T) {
	a := formatTime(t0.Add(500 * time.Millisecond))
	b := formatTime(t0.Add(time.Second))
	if !(a < b) || len(a) != len(b) {
		t.Fatalf("%s !< %s", a, b)
	}
}
