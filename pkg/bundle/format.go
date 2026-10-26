// Package bundle reads, writes and verifies evidence bundles.
//
// A bundle is a zstd-compressed tar archive with a canonical layout:
//
//	<payload entries, sorted by path>   collectors/*.json, files/...
//	manifest.json                       every payload entry's path, size, SHA-256
//	head.json                           signed tree head: Merkle root + manifest digest
//	head.sig                            ed25519 signature over head.json
//
// The payload entries are the leaves of an RFC 9162 Merkle tree whose root
// is in head.json; head.json also pins the SHA-256 of manifest.json, and the
// signature pins head.json. Every byte of the archive is therefore either
// covered by a hash chain up to the signature, or fixed by the canonical
// layout (tar header fields, padding, trailer), which the verifier
// re-derives and compares byte-for-byte. See docs/BUNDLE_FORMAT.md.
package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/SlateGitOrg/evidencelocker/pkg/keys"
	"github.com/SlateGitOrg/evidencelocker/pkg/merkle"
)

// Format identifiers.
const (
	FormatManifest = "evidencelocker/manifest/v1"
	FormatHead     = "evidencelocker/head/v1"
	FormatSig      = "evidencelocker/sig/v1"
	FormatProof    = "evidencelocker/proof/v1"
	LeafEncoding   = "evidencelocker/leaf/v1"
)

// Reserved entry names, always the final three entries in this order.
const (
	ManifestName = "manifest.json"
	HeadName     = "head.json"
	SigName      = "head.sig"
)

// sigDomain prefixes the signed message so a head signature can never be
// replayed as any other kind of signature made with the same key.
const sigDomain = "evidencelocker/head-signature/v1\x00"

// maxMetaSize bounds how much of manifest/head/sig a verifier buffers.
const maxMetaSize = 256 << 20

// Entry is one payload file as listed in the manifest. Its position in
// Manifest.Entries is its Merkle leaf index.
type Entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Host describes the collection source.
type Host struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Root     string `json:"root"`
	Live     bool   `json:"live"`
}

// Tool identifies the producing software.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Compression records how the container was compressed, so a verifier with
// the same encoder can check the compressed bytes are canonical too.
type Compression struct {
	Codec   string `json:"codec"`
	Encoder string `json:"encoder"`
}

// CollectorRun summarises one collector's execution.
type CollectorRun struct {
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	Status     string    `json:"status"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	Records    int       `json:"records"`
	Captures   int       `json:"captures"`
	Warnings   int       `json:"warnings"`
	Error      string    `json:"error,omitempty"`
}

// MerkleInfo describes the tree over Entries.
type MerkleInfo struct {
	LeafEncoding string `json:"leaf_encoding"`
	TreeSize     int    `json:"tree_size"`
	Root         string `json:"root"`
}

// Manifest is manifest.json.
type Manifest struct {
	Format      string         `json:"format"`
	CaseID      string         `json:"case_id"`
	Examiner    string         `json:"examiner"`
	CreatedAt   time.Time      `json:"created_at"`
	Host        Host           `json:"host"`
	Tool        Tool           `json:"tool"`
	Compression Compression    `json:"compression"`
	Collectors  []CollectorRun `json:"collectors"`
	Merkle      MerkleInfo     `json:"merkle"`
	Entries     []Entry        `json:"entries"`
}

// Head is head.json, the signed tree head.
type Head struct {
	Format         string    `json:"format"`
	CaseID         string    `json:"case_id"`
	CreatedAt      time.Time `json:"created_at"`
	TreeSize       int       `json:"tree_size"`
	MerkleRoot     string    `json:"merkle_root"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	KeyID          string    `json:"key_id"`
}

// Signature is head.sig.
type Signature struct {
	Format    string `json:"format"`
	Alg       string `json:"alg"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// LeafData is the byte string hashed as a Merkle leaf for an entry:
// LeafEncoding || 0x00 || u32be(len(path)) || path || u64be(size) || sha256.
func LeafData(e Entry) ([]byte, error) {
	sum, err := hex.DecodeString(e.SHA256)
	if err != nil || len(sum) != sha256.Size {
		return nil, fmt.Errorf("entry %q: bad sha256 %q", e.Path, e.SHA256)
	}
	var b bytes.Buffer
	b.WriteString(LeafEncoding)
	b.WriteByte(0)
	_ = binary.Write(&b, binary.BigEndian, uint32(len(e.Path)))
	b.WriteString(e.Path)
	_ = binary.Write(&b, binary.BigEndian, uint64(e.Size))
	b.Write(sum)
	return b.Bytes(), nil
}

// BuildTree returns the Merkle tree over entries.
func BuildTree(entries []Entry) (*merkle.Tree, error) {
	leaves := make([]merkle.Hash, len(entries))
	for i, e := range entries {
		d, err := LeafData(e)
		if err != nil {
			return nil, err
		}
		leaves[i] = merkle.LeafHash(d)
	}
	return merkle.New(leaves), nil
}

// ValidatePath enforces the payload naming rules: valid UTF-8, relative,
// already clean, no NUL, no "." or ".." components, not reserved.
func ValidatePath(p string) error {
	switch {
	case p == "":
		return errors.New("empty path")
	case len(p) > 4096:
		return errors.New("path longer than 4096 bytes")
	case !utf8.ValidString(p):
		return fmt.Errorf("path %q is not valid UTF-8", p)
	case strings.ContainsRune(p, 0):
		return fmt.Errorf("path %q contains NUL", p)
	case strings.HasPrefix(p, "/"):
		return fmt.Errorf("path %q is absolute", p)
	case path.Clean(p) != p || p == "." || p == ".." || strings.HasPrefix(p, "../"):
		return fmt.Errorf("path %q is not clean and relative", p)
	case p == ManifestName || p == HeadName || p == SigName:
		return fmt.Errorf("path %q is reserved", p)
	}
	return nil
}

// canonicalHeader is the only tar header form a bundle may contain. All
// metadata other than name and size is fixed, so archives are reproducible
// and every header byte is predictable by the verifier.
func canonicalHeader(name string, size int64) *tar.Header {
	return &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Size:     size,
		Mode:     0o644,
		ModTime:  time.Unix(0, 0),
	}
}

// blockPad returns the tar padding after size bytes of content.
func blockPad(size int64) int64 { return (512 - size%512) % 512 }

// canonicalJSON is the single encoding used for head.json and head.sig:
// compact, no HTML escaping, trailing newline.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func indentJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeStrict decodes exactly one JSON value, rejecting unknown fields and
// trailing data.
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after JSON value")
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err == nil {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

// decodeCanonical is decodeStrict plus a byte-exact round-trip check, so a
// file has exactly one acceptable encoding (no case-folded hex, no extra
// whitespace, no reordered keys).
func decodeCanonical(b []byte, v any) error {
	if err := decodeStrict(b, v); err != nil {
		return err
	}
	re, err := canonicalJSON(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(re, b) {
		return errors.New("not in canonical encoding")
	}
	return nil
}

// signedMessage is what the head signature covers.
func signedMessage(head []byte) []byte {
	return append([]byte(sigDomain), head...)
}

// verifyHeadSignature checks sig over headBytes and returns the public key.
func verifyHeadSignature(headBytes []byte, sig *Signature) (ed25519.PublicKey, error) {
	if sig.Format != FormatSig || sig.Alg != "ed25519" {
		return nil, fmt.Errorf("unsupported signature format %q alg %q", sig.Format, sig.Alg)
	}
	pub, err := keys.DecodePublic(sig.PublicKey)
	if err != nil {
		return nil, err
	}
	if keys.KeyID(pub) != sig.KeyID {
		return nil, fmt.Errorf("key_id %q does not match public key (%s)", sig.KeyID, keys.KeyID(pub))
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(sig.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(raw) != sig.Signature {
		return nil, errors.New("signature is not 64 bytes of canonical base64")
	}
	if !ed25519.Verify(pub, signedMessage(headBytes), raw) {
		return nil, errors.New("ed25519 signature does not verify over head.json")
	}
	return pub, nil
}
