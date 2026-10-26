// Package custody implements a hash-chained, signed chain-of-custody log.
//
// The log is a JSON Lines file kept next to a bundle. Entry 0 ("seal") is
// written by the collector and binds the log to the bundle's file digest and
// Merkle root. Each later entry records an action (transfer, access, verify,
// note) and is signed by whoever holds custody at that point; a transfer
// names the recipient's public key, which becomes the only key allowed to
// sign the next entry. Every entry also commits to the previous entry's
// hash, so editing, deleting, inserting or reordering entries breaks the
// chain at a precisely reportable line.
//
// What the log cannot do on its own (truncation of the newest entries,
// trusted time, real-world identity) is documented in docs/CUSTODY.md.
package custody

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/SlateGitOrg/evidencelocker/pkg/keys"
)

// Action is what a custody entry records.
type Action string

// Custody actions.
const (
	ActionSeal     Action = "seal"     // bundle created; first entry only
	ActionTransfer Action = "transfer" // custody handed to Recipient
	ActionAccess   Action = "access"   // custodian opened/examined the evidence
	ActionVerify   Action = "verify"   // custodian verified the bundle
	ActionNote     Action = "note"     // free-form annotation
)

var validActions = map[Action]bool{ActionSeal: true, ActionTransfer: true, ActionAccess: true, ActionVerify: true, ActionNote: true}

// FormatEntry identifies the entry schema.
const FormatEntry = "evidencelocker/custody/v1"

// sigDomain separates custody signatures from bundle head signatures.
const sigDomain = "evidencelocker/custody-signature/v1\x00"

// GenesisPrev is the prev hash of entry 0.
var GenesisPrev = strings.Repeat("0", 64)

// Entry is one line of the log. Field order is the canonical encoding.
type Entry struct {
	Format       string `json:"format"`
	Seq          int    `json:"seq"`
	Prev         string `json:"prev"`
	Time         string `json:"time"` // fixed-width RFC 3339 UTC, as asserted by the signer
	Action       Action `json:"action"`
	CaseID       string `json:"case_id"`
	BundleSHA256 string `json:"bundle_sha256"`
	MerkleRoot   string `json:"merkle_root"`
	Actor        string `json:"actor"`
	ActorKey     string `json:"actor_key"`
	Recipient    string `json:"recipient,omitempty"`
	RecipientKey string `json:"recipient_key,omitempty"`
	Note         string `json:"note,omitempty"`
	Sig          string `json:"sig"`
	Hash         string `json:"hash"`
}

// signingBytes is the canonical encoding with Sig and Hash cleared.
func (e Entry) signingBytes() []byte {
	e.Sig, e.Hash = "", ""
	return mustCanonical(e)
}

// computeHash is SHA-256 of the canonical encoding with Hash cleared (so
// the signature is inside the hash chain).
func (e Entry) computeHash() string {
	e.Hash = ""
	sum := sha256.Sum256(mustCanonical(e))
	return hex.EncodeToString(sum[:])
}

func mustCanonical(v any) []byte {
	b, err := canonical(v)
	if err != nil {
		panic(fmt.Sprintf("custody: encode: %v", err))
	}
	return b
}

func canonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Clock supplies entry timestamps.
type Clock func() time.Time

// Signer is a custodian identity: a display name and a private key.
type Signer struct {
	Name string
	Key  ed25519.PrivateKey
}

// Bundle identifies the evidence a log is bound to.
type Bundle struct {
	CaseID     string
	FileSHA256 string
	MerkleRoot string
}

var actorRE = regexp.MustCompile(`^[\pL\pN][\pL\pN ._@'-]{0,127}$`)

func validName(s string) bool { return actorRE.MatchString(s) }

func sign(e *Entry, key ed25519.PrivateKey) {
	e.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(sigDomain), e.signingBytes()...)))
	e.Hash = e.computeHash()
}

// NewSeal builds the genesis entry for a freshly sealed bundle.
func NewSeal(b Bundle, s Signer, now time.Time, note string) (*Entry, error) {
	if !validName(s.Name) {
		return nil, fmt.Errorf("custody: invalid actor name %q", s.Name)
	}
	e := &Entry{
		Format: FormatEntry, Seq: 0, Prev: GenesisPrev, Time: formatTime(now), Action: ActionSeal,
		CaseID: b.CaseID, BundleSHA256: b.FileSHA256, MerkleRoot: b.MerkleRoot,
		Actor: s.Name, ActorKey: keys.EncodePublic(s.Key.Public().(ed25519.PublicKey)), Note: note,
	}
	sign(e, s.Key)
	return e, nil
}

// timeLayout is fixed-width so timestamps order correctly as strings.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// Create writes a new log containing only the seal entry. It fails if the
// file exists.
func Create(path string, b Bundle, s Signer, now time.Time, note string) (*Entry, error) {
	e, err := NewSeal(b, s, now, note)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // custody logs are shared records
	if err != nil {
		return nil, fmt.Errorf("custody: %w", err)
	}
	if err := writeLine(f, e); err != nil {
		_ = f.Close()
		return nil, err
	}
	return e, f.Close()
}

func writeLine(f *os.File, e *Entry) error {
	b, err := canonical(e)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("custody: write: %w", err)
	}
	return f.Sync()
}

// AppendRequest describes a new entry.
type AppendRequest struct {
	Action       Action
	Signer       Signer
	Recipient    string
	RecipientKey ed25519.PublicKey
	Note         string
	Now          time.Time
}

// Append verifies the whole log, checks that the signer is the current
// custodian, and appends a signed entry. The file is locked for the
// duration so concurrent appends cannot fork the chain.
func Append(path string, req AppendRequest) (*Entry, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("custody: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("custody: lock: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:errcheck // released on close anyway

	rep := Verify(f, VerifyOptions{})
	if !rep.OK {
		return nil, fmt.Errorf("custody: refusing to append to a log that fails verification: %s", rep.Findings[0])
	}
	e, err := next(rep, req)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return nil, err
	}
	return e, writeLine(f, e)
}

// next builds the entry that follows a verified log.
func next(rep *Report, req AppendRequest) (*Entry, error) {
	last := rep.Entries[len(rep.Entries)-1]
	if !validActions[req.Action] || req.Action == ActionSeal {
		return nil, fmt.Errorf("custody: invalid action %q", req.Action)
	}
	if !validName(req.Signer.Name) {
		return nil, fmt.Errorf("custody: invalid actor name %q", req.Signer.Name)
	}
	pub := req.Signer.Key.Public().(ed25519.PublicKey)
	if keys.EncodePublic(pub) != rep.CustodianKey {
		return nil, fmt.Errorf("custody: signer %s is not the current custodian (%s holds custody)",
			keys.KeyID(pub), rep.Custodian)
	}
	now := formatTime(req.Now)
	if now < last.Time {
		return nil, fmt.Errorf("custody: clock %s is earlier than last entry %s", now, last.Time)
	}
	e := &Entry{
		Format: FormatEntry, Seq: last.Seq + 1, Prev: last.Hash, Time: now, Action: req.Action,
		CaseID: last.CaseID, BundleSHA256: last.BundleSHA256, MerkleRoot: last.MerkleRoot,
		Actor: req.Signer.Name, ActorKey: rep.CustodianKey, Note: req.Note,
	}
	if req.Action == ActionTransfer {
		if !validName(req.Recipient) || len(req.RecipientKey) != ed25519.PublicKeySize {
			return nil, errors.New("custody: transfer needs a valid recipient name and public key")
		}
		e.Recipient, e.RecipientKey = req.Recipient, keys.EncodePublic(req.RecipientKey)
	} else if req.Recipient != "" || req.RecipientKey != nil {
		return nil, fmt.Errorf("custody: %s entries take no recipient", req.Action)
	}
	sign(e, req.Signer.Key)
	return e, nil
}

// Finding is one custody-log verification failure.
type Finding struct {
	Line   int    `json:"line"` // 1-based line in the file (0 = whole log)
	Seq    int    `json:"seq"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func (f Finding) String() string {
	where := "log"
	switch {
	case f.Line > 0 && f.Seq >= 0:
		where = fmt.Sprintf("line %d (seq %d)", f.Line, f.Seq)
	case f.Line > 0:
		where = fmt.Sprintf("line %d", f.Line)
	}
	return fmt.Sprintf("%s %s: %s", where, f.Code, f.Detail)
}

// Finding codes.
const (
	CodeParse     = "ENTRY_UNPARSABLE"
	CodeHash      = "HASH_MISMATCH"
	CodeChain     = "CHAIN_BROKEN"
	CodeSeq       = "SEQUENCE_INVALID"
	CodeSig       = "SIGNATURE_INVALID"
	CodeCustodian = "NOT_CUSTODIAN"
	CodeTime      = "TIME_REGRESSION"
	CodeBinding   = "BUNDLE_BINDING"
	CodeField     = "FIELD_INVALID"
	CodeEmpty     = "LOG_EMPTY"
	CodeHead      = "HEAD_MISMATCH"
	CodeSealer    = "SEALER_UNTRUSTED"
)

// VerifyOptions bind verification to external facts.
type VerifyOptions struct {
	// Bundle, when set, must match the digests the seal entry recorded.
	Bundle *Bundle
	// SealKeys, when non-empty, must contain the seal entry's signer
	// (normally the same collector key that signed the bundle head).
	SealKeys []ed25519.PublicKey
	// ExpectHead is a previously published head hash (e.g. emailed or
	// written in a case file). The log must contain it; if it is the last
	// entry's hash, nothing has been appended since. This is the only
	// defence against truncation of the newest entries.
	ExpectHead string
}

// Report is the verification outcome.
type Report struct {
	OK           bool      `json:"ok"`
	Findings     []Finding `json:"findings"`
	Entries      []Entry   `json:"entries"`
	Head         string    `json:"head"`
	Custodian    string    `json:"custodian"`
	CustodianKey string    `json:"custodian_key"`
	HeadIndex    int       `json:"expect_head_index"` // -1 if ExpectHead unset or absent
}

// Verify checks a log. It never stops at the first problem in a way that
// hides a later one it can still evaluate, but entries after a broken link
// are only checked for internal consistency.
func Verify(r io.Reader, opts VerifyOptions) *Report {
	rep := &Report{Findings: []Finding{}, Entries: []Entry{}, HeadIndex: -1}
	add := func(line, seq int, code, format string, args ...any) {
		rep.Findings = append(rep.Findings, Finding{Line: line, Seq: seq, Code: code, Detail: fmt.Sprintf(format, args...)})
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	var prev *Entry
	var custodianKey, custodian string
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		var e Entry
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			add(line, -1, CodeParse, "%v", err)
			prev = nil
			continue
		}
		seq := e.Seq
		if c, err := canonical(e); err != nil || !bytes.Equal(c, raw) {
			add(line, seq, CodeParse, "entry is not in canonical encoding")
		}
		if e.Format != FormatEntry {
			add(line, seq, CodeField, "unsupported format %q", e.Format)
		}
		if got := e.computeHash(); got != e.Hash {
			add(line, seq, CodeHash, "entry hash %s, recorded %s (entry content altered)", got, e.Hash)
		}
		pub, kerr := keys.DecodePublic(e.ActorKey)
		if kerr != nil {
			add(line, seq, CodeSig, "actor key: %v", kerr)
		} else if sig, err := base64.StdEncoding.Strict().DecodeString(e.Sig); err != nil ||
			!ed25519.Verify(pub, append([]byte(sigDomain), e.signingBytes()...), sig) {
			add(line, seq, CodeSig, "signature by %s does not verify", e.Actor)
		}
		if !validActions[e.Action] {
			add(line, seq, CodeField, "unknown action %q", e.Action)
		}
		if !validName(e.Actor) {
			add(line, seq, CodeField, "invalid actor %q", e.Actor)
		}
		if t, err := time.Parse(timeLayout, e.Time); err != nil || formatTime(t) != e.Time {
			add(line, seq, CodeField, "time %q is not canonical fixed-width RFC 3339 UTC", e.Time)
		}
		if line == 1 {
			if e.Seq != 0 || e.Prev != GenesisPrev || e.Action != ActionSeal {
				add(line, seq, CodeSeq, "first entry must be seq 0 seal with genesis prev")
			}
			if len(opts.SealKeys) > 0 && (kerr != nil || !keyIn(pub, opts.SealKeys)) {
				add(line, seq, CodeSealer, "seal entry signed by %s, which is not a trusted sealing key", e.Actor)
			}
			if b := opts.Bundle; b != nil {
				if e.BundleSHA256 != b.FileSHA256 {
					add(line, seq, CodeBinding, "sealed bundle SHA-256 %s, bundle file is %s", e.BundleSHA256, b.FileSHA256)
				}
				if b.MerkleRoot != "" && e.MerkleRoot != b.MerkleRoot {
					add(line, seq, CodeBinding, "sealed Merkle root %s, bundle head states %s", e.MerkleRoot, b.MerkleRoot)
				}
				if b.CaseID != "" && e.CaseID != b.CaseID {
					add(line, seq, CodeBinding, "sealed case %q, bundle says %q", e.CaseID, b.CaseID)
				}
			}
			custodian, custodianKey = e.Actor, e.ActorKey
		} else {
			if e.Action == ActionSeal {
				add(line, seq, CodeSeq, "seal is only valid as the first entry")
			}
			if prev != nil {
				if e.Seq != prev.Seq+1 {
					add(line, seq, CodeSeq, "seq %d follows %d", e.Seq, prev.Seq)
				}
				if e.Prev != prev.Hash {
					add(line, seq, CodeChain, "prev %s does not match hash of line %d (%s): entries removed, inserted or reordered", short(e.Prev), line-1, short(prev.Hash))
				}
				if e.Time < prev.Time {
					add(line, seq, CodeTime, "time %s is earlier than previous entry %s", e.Time, prev.Time)
				}
				if e.CaseID != prev.CaseID || e.BundleSHA256 != prev.BundleSHA256 || e.MerkleRoot != prev.MerkleRoot {
					add(line, seq, CodeBinding, "bundle binding differs from previous entry")
				}
			} else {
				add(line, seq, CodeChain, "cannot link to previous line, which was unparsable")
			}
			if e.ActorKey != custodianKey {
				add(line, seq, CodeCustodian, "signed by %s but custody is held by %s", e.Actor, custodian)
			}
		}
		switch {
		case e.Action == ActionTransfer:
			if _, err := keys.DecodePublic(e.RecipientKey); err != nil || !validName(e.Recipient) {
				add(line, seq, CodeField, "transfer has invalid recipient")
			} else {
				custodian, custodianKey = e.Recipient, e.RecipientKey
			}
		case e.Recipient != "" || e.RecipientKey != "":
			add(line, seq, CodeField, "%s entry must not name a recipient", e.Action)
		}
		if opts.ExpectHead != "" && e.Hash == opts.ExpectHead {
			rep.HeadIndex = len(rep.Entries)
		}
		rep.Entries = append(rep.Entries, e)
		ec := e
		prev = &ec
	}
	if err := sc.Err(); err != nil {
		add(line+1, -1, CodeParse, "read: %v", err)
	}
	if len(rep.Entries) == 0 && len(rep.Findings) == 0 {
		add(0, -1, CodeEmpty, "log has no entries")
	}
	if n := len(rep.Entries); n > 0 {
		rep.Head = rep.Entries[n-1].Hash
	}
	if opts.ExpectHead != "" && rep.HeadIndex < 0 {
		add(0, -1, CodeHead, "expected head %s not found: log was truncated or rewritten", short(opts.ExpectHead))
	}
	rep.Custodian, rep.CustodianKey = custodian, custodianKey
	rep.OK = len(rep.Findings) == 0
	return rep
}

// VerifyFile opens and verifies a log file.
func VerifyFile(path string, opts VerifyOptions) (*Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return Verify(f, opts), nil
}

func keyIn(k ed25519.PublicKey, set []ed25519.PublicKey) bool {
	for _, s := range set {
		if s.Equal(k) {
			return true
		}
	}
	return false
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	return h
}
