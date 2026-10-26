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
	"path/filepath"
	"sort"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/SlateGitOrg/evidencelocker/pkg/keys"
)

// EncoderID names the exact compressor configuration. A verifier whose
// encoder matches can prove the compressed bytes are canonical; one built
// against a different library version notes that it cannot.
const EncoderID = "github.com/klauspost/compress/zstd@v1.20.1;level=default;concurrency=1;crc=1"

func newEncoder(w io.Writer) (*zstd.Encoder, error) {
	return zstd.NewWriter(w,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderCRC(true),
	)
}

func newDecoder(r io.Reader) (*zstd.Decoder, error) {
	return zstd.NewReader(r,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxWindow(64<<20),
	)
}

// Item is one payload file to seal.
type Item struct {
	Path string
	Data []byte
}

// SealOptions carry the manifest metadata and the signing key.
type SealOptions struct {
	CaseID     string
	Examiner   string
	CreatedAt  time.Time
	Host       Host
	Tool       Tool
	Collectors []CollectorRun
	Signer     ed25519.PrivateKey
}

// Sealed describes a written bundle.
type Sealed struct {
	Manifest   *Manifest
	Head       *Head
	Signature  *Signature
	FileSHA256 string // SHA-256 of the compressed bundle file
	FileSize   int64
}

// Seal writes a complete bundle to w. Items are sorted by path; duplicate
// or invalid paths are rejected before anything is written.
func Seal(w io.Writer, items []Item, opts SealOptions) (*Sealed, error) {
	if len(opts.Signer) != ed25519.PrivateKeySize {
		return nil, errors.New("seal: signer key required")
	}
	if opts.CaseID == "" {
		return nil, errors.New("seal: case id required")
	}
	sorted := append([]Item(nil), items...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	for i, it := range sorted {
		if err := ValidatePath(it.Path); err != nil {
			return nil, fmt.Errorf("seal: %w", err)
		}
		if i > 0 && sorted[i-1].Path == it.Path {
			return nil, fmt.Errorf("seal: duplicate path %q", it.Path)
		}
	}

	fileHash := sha256.New()
	cw := &countWriter{w: io.MultiWriter(w, fileHash)}
	enc, err := newEncoder(cw)
	if err != nil {
		return nil, fmt.Errorf("seal: zstd: %w", err)
	}
	tw := tar.NewWriter(enc)

	entries := make([]Entry, 0, len(sorted))
	for _, it := range sorted {
		sum := sha256.Sum256(it.Data)
		if err := writeEntry(tw, it.Path, it.Data); err != nil {
			return nil, err
		}
		entries = append(entries, Entry{Path: it.Path, Size: int64(len(it.Data)), SHA256: hex.EncodeToString(sum[:])})
	}
	tree, err := BuildTree(entries)
	if err != nil {
		return nil, err
	}
	created := opts.CreatedAt.UTC()
	collectors := opts.Collectors
	if collectors == nil {
		collectors = []CollectorRun{}
	}
	m := &Manifest{
		Format: FormatManifest, CaseID: opts.CaseID, Examiner: opts.Examiner, CreatedAt: created,
		Host: opts.Host, Tool: opts.Tool, Collectors: collectors,
		Compression: Compression{Codec: "zstd", Encoder: EncoderID},
		Merkle:      MerkleInfo{LeafEncoding: LeafEncoding, TreeSize: tree.Size(), Root: tree.Root().String()},
		Entries:     entries,
	}
	mb, err := indentJSON(m)
	if err != nil {
		return nil, fmt.Errorf("seal: manifest: %w", err)
	}
	msum := sha256.Sum256(mb)
	pub := opts.Signer.Public().(ed25519.PublicKey)
	h := &Head{
		Format: FormatHead, CaseID: opts.CaseID, CreatedAt: created, TreeSize: tree.Size(),
		MerkleRoot: tree.Root().String(), ManifestSHA256: hex.EncodeToString(msum[:]), KeyID: keys.KeyID(pub),
	}
	hb, err := canonicalJSON(h)
	if err != nil {
		return nil, fmt.Errorf("seal: head: %w", err)
	}
	sig := &Signature{
		Format: FormatSig, Alg: "ed25519", KeyID: h.KeyID, PublicKey: keys.EncodePublic(pub),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(opts.Signer, signedMessage(hb))),
	}
	sb, err := canonicalJSON(sig)
	if err != nil {
		return nil, fmt.Errorf("seal: signature: %w", err)
	}
	for _, e := range []struct {
		name string
		data []byte
	}{{ManifestName, mb}, {HeadName, hb}, {SigName, sb}} {
		if err := writeEntry(tw, e.name, e.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("seal: tar: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("seal: zstd: %w", err)
	}
	return &Sealed{
		Manifest: m, Head: h, Signature: sig,
		FileSHA256: hex.EncodeToString(fileHash.Sum(nil)), FileSize: cw.n,
	}, nil
}

func writeEntry(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(canonicalHeader(name, int64(len(data)))); err != nil {
		return fmt.Errorf("seal: header %q: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("seal: write %q: %w", name, err)
	}
	return nil
}

// SealFile writes a bundle to path atomically: it writes a temporary file in
// the same directory, fsyncs it, and renames it into place. It refuses to
// replace an existing file, because overwriting evidence is never routine.
func SealFile(path string, items []Item, opts SealOptions) (*Sealed, error) {
	if _, err := os.Lstat(path); err == nil {
		return nil, fmt.Errorf("seal: %s already exists", path)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".evidencelocker-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	s, err := Seal(tmp, items, opts)
	if err != nil {
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		return nil, fmt.Errorf("seal: fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o400); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	// os.Link fails if path appeared meanwhile, unlike Rename.
	if err := os.Link(tmp.Name(), path); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	_ = os.Remove(tmp.Name())
	ok = true
	return s, nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
