package bundle

import (
	"archive/tar"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/SlateGitOrg/evidencelocker/pkg/merkle"
)

// ErrNotVerified is wrapped by Open when verification found problems.
var ErrNotVerified = errors.New("bundle failed verification")

// VerificationError carries the failing report.
type VerificationError struct{ Report *Report }

func (e *VerificationError) Error() string {
	var parts []string
	for i, f := range e.Report.Findings {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("... and %d more", len(e.Report.Findings)-3))
			break
		}
		parts = append(parts, f.String())
	}
	return ErrNotVerified.Error() + ": " + strings.Join(parts, "; ")
}

func (e *VerificationError) Unwrap() error { return ErrNotVerified }

// Bundle is a verified, opened bundle. Content reads re-check every entry
// against the manifest, so a file swapped after Open is still caught.
type Bundle struct {
	Path     string
	Manifest *Manifest
	Head     *Head
	Report   *Report
	index    map[string]int
}

// Open verifies the bundle and, if it is intact, returns a handle to it.
func Open(path string, opts VerifyOptions) (*Bundle, error) {
	rep, err := VerifyFile(path, opts)
	if err != nil {
		return nil, err
	}
	if !rep.OK {
		return nil, &VerificationError{Report: rep}
	}
	b := &Bundle{Path: path, Manifest: rep.Manifest, Head: rep.Head, Report: rep, index: map[string]int{}}
	for i, e := range rep.Manifest.Entries {
		b.index[e.Path] = i
	}
	return b, nil
}

// Has reports whether the manifest lists path.
func (b *Bundle) Has(path string) bool {
	_, ok := b.index[path]
	return ok
}

// ReadEntries returns the content of every entry whose path satisfies
// want, in one pass, checking each against the manifest digest.
func (b *Bundle) ReadEntries(want func(path string) bool) (map[string][]byte, error) {
	f, err := os.Open(b.Path)
	if err != nil {
		return nil, err
	}
	ds, err := newDecodeStream(f)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ds.Close() }()
	tr := tar.NewReader(ds)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read bundle: %w", err)
		}
		i, listed := b.index[h.Name]
		if !listed || !want(h.Name) {
			continue
		}
		e := b.Manifest.Entries[i]
		data, err := io.ReadAll(io.LimitReader(tr, e.Size+1))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", h.Name, err)
		}
		sum := sha256.Sum256(data)
		if int64(len(data)) != e.Size || hex.EncodeToString(sum[:]) != e.SHA256 {
			return nil, fmt.Errorf("read %s: content no longer matches manifest: %w", h.Name, ErrNotVerified)
		}
		out[h.Name] = data
	}
	return out, nil
}

// ReadEntry returns one entry's verified content.
func (b *Bundle) ReadEntry(path string) ([]byte, error) {
	if !b.Has(path) {
		return nil, fmt.Errorf("%s: not in bundle", path)
	}
	m, err := b.ReadEntries(func(p string) bool { return p == path })
	if err != nil {
		return nil, err
	}
	d, ok := m[path]
	if !ok {
		return nil, fmt.Errorf("%s: listed but not found in archive: %w", path, ErrNotVerified)
	}
	return d, nil
}

// Paths returns all entry paths with the given prefix, sorted.
func (b *Bundle) Paths(prefix string) []string {
	var out []string
	for _, e := range b.Manifest.Entries {
		if strings.HasPrefix(e.Path, prefix) {
			out = append(out, e.Path)
		}
	}
	sort.Strings(out)
	return out
}

// Proof is a self-contained inclusion proof for one entry: anyone holding
// it (and the signer's public key) can check that the entry with this
// path, size and digest was sealed in the bundle, without the bundle.
type Proof struct {
	Format    string    `json:"format"`
	Head      string    `json:"head"` // exact head.json bytes, base64
	Signature Signature `json:"signature"`
	Entry     Entry     `json:"entry"`
	Index     int       `json:"index"`
	AuditPath []string  `json:"audit_path"`
}

// Prove builds an inclusion proof for path.
func (b *Bundle) Prove(path string) (*Proof, error) {
	i, ok := b.index[path]
	if !ok {
		return nil, fmt.Errorf("%s: not in bundle", path)
	}
	tree, err := BuildTree(b.Manifest.Entries)
	if err != nil {
		return nil, err
	}
	hashes, err := tree.Proof(i)
	if err != nil {
		return nil, err
	}
	var sig Signature
	if err := decodeCanonical(b.Report.SigBytes, &sig); err != nil {
		return nil, err
	}
	p := &Proof{
		Format: FormatProof, Head: base64.StdEncoding.EncodeToString(b.Report.HeadBytes),
		Signature: sig, Entry: b.Manifest.Entries[i], Index: i, AuditPath: make([]string, len(hashes)),
	}
	for k, h := range hashes {
		p.AuditPath[k] = h.String()
	}
	return p, nil
}

// ProofResult describes a verified proof.
type ProofResult struct {
	Head    *Head
	KeyID   string
	Trusted bool
}

// VerifyProof checks a proof's signature, its audit path to the signed
// root, and (when content is non-nil) that content matches the entry.
func VerifyProof(p *Proof, trustedKeys []ed25519.PublicKey, content []byte) (*ProofResult, error) {
	if p.Format != FormatProof {
		return nil, fmt.Errorf("proof: unsupported format %q", p.Format)
	}
	hb, err := base64.StdEncoding.Strict().DecodeString(p.Head)
	if err != nil {
		return nil, fmt.Errorf("proof: head: %w", err)
	}
	pub, err := verifyHeadSignature(hb, &p.Signature)
	if err != nil {
		return nil, fmt.Errorf("proof: %w", err)
	}
	res := &ProofResult{KeyID: p.Signature.KeyID, Trusted: trusted(pub, trustedKeys)}
	if len(trustedKeys) > 0 && !res.Trusted {
		return nil, fmt.Errorf("proof: signer %s is not trusted", p.Signature.KeyID)
	}
	var h Head
	if err := decodeCanonical(hb, &h); err != nil {
		return nil, fmt.Errorf("proof: head: %w", err)
	}
	res.Head = &h
	root, err := merkle.ParseHash(h.MerkleRoot)
	if err != nil {
		return nil, fmt.Errorf("proof: %w", err)
	}
	path := make([]merkle.Hash, len(p.AuditPath))
	for i, s := range p.AuditPath {
		if path[i], err = merkle.ParseHash(s); err != nil {
			return nil, fmt.Errorf("proof: audit path: %w", err)
		}
	}
	ld, err := LeafData(p.Entry)
	if err != nil {
		return nil, fmt.Errorf("proof: %w", err)
	}
	if err := merkle.VerifyInclusion(merkle.LeafHash(ld), p.Index, h.TreeSize, path, root); err != nil {
		return nil, fmt.Errorf("proof: %w", err)
	}
	if content != nil {
		sum := sha256.Sum256(content)
		if int64(len(content)) != p.Entry.Size || hex.EncodeToString(sum[:]) != p.Entry.SHA256 {
			return nil, fmt.Errorf("proof: supplied content does not match entry %s", p.Entry.Path)
		}
	}
	return res, nil
}
