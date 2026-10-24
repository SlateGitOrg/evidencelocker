package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"

	"github.com/klauspost/compress/zstd"

	"github.com/archit2501/evidencelocker/pkg/keys"
)

// Code classifies a verification finding.
type Code string

// Finding codes. Every code means the bundle is not what was sealed.
const (
	CodeContainer       Code = "CONTAINER_CORRUPT"        // zstd or tar framing broken
	CodeContainerNoncan Code = "CONTAINER_NONCANONICAL"   // decodes fine, but compressed bytes were altered
	CodeLayout          Code = "LAYOUT_NONCANONICAL"      // tar header/padding/trailer bytes differ from canonical
	CodeMetaMissing     Code = "METADATA_MISSING"         // manifest/head/sig absent or misplaced
	CodeSignature       Code = "SIGNATURE_INVALID"        // head.sig malformed or does not verify
	CodeUntrustedKey    Code = "UNTRUSTED_KEY"            // valid signature by a key not pinned by the caller
	CodeHead            Code = "HEAD_INVALID"             // head.json malformed or inconsistent
	CodeManifestDigest  Code = "MANIFEST_DIGEST_MISMATCH" // manifest.json bytes differ from signed digest
	CodeManifest        Code = "MANIFEST_INVALID"         // manifest.json malformed or inconsistent
	CodeMerkle          Code = "MERKLE_ROOT_MISMATCH"     // entries do not hash to the signed root
	CodeEntryMissing    Code = "ENTRY_MISSING"
	CodeEntryUnexpected Code = "ENTRY_UNEXPECTED"
	CodeEntryDuplicate  Code = "ENTRY_DUPLICATE"
	CodeEntrySize       Code = "ENTRY_SIZE_MISMATCH"
	CodeEntryHash       Code = "ENTRY_HASH_MISMATCH"
	CodeEntryType       Code = "ENTRY_TYPE_INVALID"
	CodeFileDigest      Code = "FILE_DIGEST_MISMATCH" // whole-file digest differs from the expected (custody) value
)

// Span is a byte range [Start, End) in the decompressed tar stream.
type Span struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

// Contains reports whether off lies in the span.
func (s Span) Contains(off int64) bool { return off >= s.Start && off < s.End }

// Finding is one verification failure, located as precisely as the format
// allows: the affected entry path and the tar-stream byte ranges involved.
type Finding struct {
	Code   Code   `json:"code"`
	Path   string `json:"path,omitempty"`
	Detail string `json:"detail"`
	Spans  []Span `json:"spans,omitempty"`
}

func (f Finding) String() string {
	s := string(f.Code)
	if f.Path != "" {
		s += " " + f.Path
	}
	s += ": " + f.Detail
	for _, sp := range f.Spans {
		s += fmt.Sprintf(" [tar bytes %d-%d]", sp.Start, sp.End)
	}
	return s
}

// Report is the outcome of a verification.
type Report struct {
	OK          bool      `json:"ok"`
	Findings    []Finding `json:"findings"`
	Notes       []string  `json:"notes"`
	FileSHA256  string    `json:"file_sha256,omitempty"`
	FileSize    int64     `json:"file_size,omitempty"`
	TarSize     int64     `json:"tar_size"`
	Entries     int       `json:"entries"`
	KeyID       string    `json:"key_id,omitempty"`
	Trusted     bool      `json:"trusted"`
	MerkleRoot  string    `json:"merkle_root,omitempty"`
	Manifest    *Manifest `json:"-"`
	Head        *Head     `json:"-"`
	HeadBytes   []byte    `json:"-"`
	SigBytes    []byte    `json:"-"`
	ManifestRaw []byte    `json:"-"`
}

func (r *Report) add(f Finding) { r.Findings = append(r.Findings, f) }

// VerifyOptions configure verification.
type VerifyOptions struct {
	// TrustedKeys pins acceptable signers. Empty means "any valid
	// signature", which proves integrity but not origin (noted in Notes).
	TrustedKeys []ed25519.PublicKey
	// ExpectFileSHA256 is the whole-file digest recorded elsewhere, e.g. in
	// the custody log's seal entry.
	ExpectFileSHA256 string
}

// opener returns a fresh decompressed tar stream on each call.
type opener func() (io.ReadCloser, error)

// VerifyFile verifies the bundle at path. The returned error is non-nil only
// when the file cannot be read at all; tampering is reported in the Report.
//
// The file is read four times: once for its whole-file digest, once for the
// scan pass, and twice (concurrently streamed) for the layout comparison.
// Memory use is bounded by the metadata entries, not the payload.
func VerifyFile(path string, opts VerifyOptions) (*Report, error) {
	digest, size, err := fileSHA256(path)
	if err != nil {
		return nil, err
	}
	open := func() (io.ReadCloser, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		return newDecodeStream(f)
	}
	rep := verify(open, opts, true, func() string { return digest })
	rep.FileSize = size
	rep.finish()
	return rep, nil
}

// fileSHA256 returns the hex SHA-256 and size of a file.
func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// VerifyTar verifies an uncompressed tar stream held in memory. It is the
// core of VerifyFile, exposed for tests and tools that already decompressed.
func VerifyTar(b []byte, opts VerifyOptions) *Report {
	open := func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	rep := verify(open, opts, false, nil)
	rep.finish()
	return rep
}

func (r *Report) finish() {
	r.OK = len(r.Findings) == 0
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	if r.Notes == nil {
		r.Notes = []string{}
	}
}

// decodeStream decompresses a bundle file, tagging decoder failures as
// container errors so they are reported as such.
type decodeStream struct {
	f   *os.File
	dec *zstd.Decoder
}

func newDecodeStream(f *os.File) (*decodeStream, error) {
	d, err := newDecoder(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &decodeStream{f: f, dec: d}, nil
}

func (d *decodeStream) Read(p []byte) (int, error) {
	n, err := d.dec.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		err = &containerError{err}
	}
	return n, err
}

func (d *decodeStream) Close() error {
	d.dec.Close()
	return d.f.Close()
}

// containerError marks failures of the compression layer.
type containerError struct{ err error }

func (e *containerError) Error() string { return "zstd: " + e.err.Error() }
func (e *containerError) Unwrap() error { return e.err }

// countReader counts bytes consumed from the tar stream.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// tarEntry is what the scan pass learns about one archive member.
type tarEntry struct {
	name     string
	typeflag byte
	size     int64
	hdr      Span
	data     Span
	sum      [32]byte
	body     []byte // retained for reserved metadata entries only
}

func (t *tarEntry) whole() Span { return Span{t.hdr.Start, t.data.End} }

func isMeta(name string) bool { return name == ManifestName || name == HeadName || name == SigName }

// scan reads every member once, hashing payload content and buffering the
// metadata entries. It also drains the stream so compression-layer
// checksums at the very end are always checked.
func scan(rc io.Reader) ([]*tarEntry, int64, *Finding) {
	cr := &countReader{r: rc}
	tr := tar.NewReader(cr)
	var ents []*tarEntry
	var next int64
	for {
		hdrStart := next
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ents, cr.n, containerFinding(err, "reading tar header", Span{hdrStart, max(cr.n, hdrStart+512)})
		}
		e := &tarEntry{name: h.Name, typeflag: h.Typeflag, size: h.Size, hdr: Span{hdrStart, cr.n}}
		e.data = Span{cr.n, cr.n + h.Size}
		hasher := sha256.New()
		var dst io.Writer = hasher
		var buf *bytes.Buffer
		if isMeta(h.Name) && h.Size <= maxMetaSize {
			buf = &bytes.Buffer{}
			dst = io.MultiWriter(hasher, buf)
		}
		if _, err := io.Copy(dst, tr); err != nil { //nolint:gosec // G110: streamed into a hash; only size-capped metadata is buffered
			return ents, cr.n, containerFinding(err, "reading "+h.Name, Span{e.data.Start, max(cr.n, e.data.Start+1)})
		}
		copy(e.sum[:], hasher.Sum(nil))
		if buf != nil {
			e.body = buf.Bytes()
		}
		ents = append(ents, e)
		next = e.data.End + blockPad(h.Size)
	}
	end := cr.n
	if _, err := io.Copy(io.Discard, cr); err != nil {
		return ents, cr.n, containerFinding(err, "reading past archive end", Span{end, max(cr.n, end+1)})
	}
	return ents, cr.n, nil
}

func containerFinding(err error, what string, sp Span) *Finding {
	var ce *containerError
	if errors.As(err, &ce) {
		// The fault is in the compressed domain; tar offsets would mislead.
		return &Finding{Code: CodeContainer, Detail: fmt.Sprintf("compressed stream corrupt (zstd: %v); decoding stopped while %s", ce.err, what)}
	}
	return &Finding{Code: CodeContainer, Detail: fmt.Sprintf("%s: %v", what, err), Spans: []Span{sp}}
}

// verify runs all checks. fileDigest, when non-nil, is called after the
// first full pass to obtain the compressed file's SHA-256.
func verify(open opener, opts VerifyOptions, checkContainer bool, fileDigest func() string) *Report {
	rep := &Report{}
	rc, err := open()
	if err != nil {
		rep.add(Finding{Code: CodeContainer, Detail: err.Error()})
		return rep
	}
	ents, tarSize, cf := scan(rc)
	_ = rc.Close()
	rep.TarSize = tarSize
	if fileDigest != nil {
		rep.FileSHA256 = fileDigest()
		if opts.ExpectFileSHA256 != "" && opts.ExpectFileSHA256 != rep.FileSHA256 {
			rep.add(Finding{Code: CodeFileDigest, Detail: fmt.Sprintf(
				"bundle file SHA-256 %s differs from expected %s", rep.FileSHA256, opts.ExpectFileSHA256)})
		}
	}
	if cf != nil {
		rep.add(*cf)
		return rep
	}
	payload, meta := splitMeta(rep, ents)
	rep.Entries = len(payload)
	man := checkMetadata(rep, meta, opts)
	if man != nil {
		checkEntries(rep, man, payload)
	}
	layoutOK := checkLayout(rep, open, ents, checkContainer && man != nil && man.Compression.Encoder == EncoderID)
	if checkContainer && man != nil && man.Compression.Encoder != EncoderID && layoutOK {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"compressed-byte canonicality not checked: bundle encoder %q differs from this build's %q",
			man.Compression.Encoder, EncoderID))
	}
	return rep
}

// splitMeta separates payload from the three trailing metadata entries,
// reporting misplaced or missing metadata.
func splitMeta(rep *Report, ents []*tarEntry) ([]*tarEntry, map[string]*tarEntry) {
	meta := map[string]*tarEntry{}
	var payload []*tarEntry
	want := []string{ManifestName, HeadName, SigName}
	n := len(ents)
	for i, e := range ents {
		if !isMeta(e.name) {
			payload = append(payload, e)
			continue
		}
		if _, dup := meta[e.name]; dup {
			rep.add(Finding{Code: CodeEntryDuplicate, Path: e.name, Detail: "metadata entry appears more than once", Spans: []Span{e.whole()}})
			continue
		}
		meta[e.name] = e
		pos := i - (n - 3)
		if pos < 0 || pos > 2 || want[pos] != e.name {
			rep.add(Finding{Code: CodeMetaMissing, Path: e.name,
				Detail: "metadata entry out of place (must be the final manifest.json, head.json, head.sig)", Spans: []Span{e.whole()}})
		}
	}
	for _, w := range want {
		if meta[w] == nil {
			rep.add(Finding{Code: CodeMetaMissing, Path: w, Detail: "required metadata entry missing"})
		}
	}
	return payload, meta
}

// checkMetadata verifies signature -> head -> manifest digest and returns
// the parsed manifest (nil if unusable).
func checkMetadata(rep *Report, meta map[string]*tarEntry, opts VerifyOptions) *Manifest {
	me, he, se := meta[ManifestName], meta[HeadName], meta[SigName]
	for _, e := range []*tarEntry{me, he, se} {
		if e != nil && e.body == nil {
			rep.add(Finding{Code: CodeMetaMissing, Path: e.name, Detail: "metadata entry exceeds size limit", Spans: []Span{e.data}})
			return nil
		}
	}
	var head *Head
	if he != nil {
		rep.HeadBytes = he.body
		var h Head
		if err := decodeCanonical(he.body, &h); err != nil {
			rep.add(Finding{Code: CodeHead, Path: HeadName, Detail: "head.json unparsable: " + err.Error(), Spans: []Span{he.data}})
		} else {
			head = &h
			rep.Head = head
			rep.MerkleRoot = h.MerkleRoot
		}
	}
	if se != nil && he != nil {
		rep.SigBytes = se.body
		var sig Signature
		if err := decodeCanonical(se.body, &sig); err != nil {
			rep.add(Finding{Code: CodeSignature, Path: SigName, Detail: "head.sig unparsable: " + err.Error(), Spans: []Span{se.data}})
		} else if pub, err := verifyHeadSignature(he.body, &sig); err != nil {
			rep.add(Finding{Code: CodeSignature, Path: SigName, Detail: err.Error() + " (head.json or head.sig altered)", Spans: []Span{he.data, se.data}})
		} else {
			rep.KeyID = sig.KeyID
			rep.Trusted = trusted(pub, opts.TrustedKeys)
			switch {
			case len(opts.TrustedKeys) == 0:
				rep.Notes = append(rep.Notes, "signature valid but signer not pinned: pass a trusted key to prove origin, not just integrity")
			case !rep.Trusted:
				rep.add(Finding{Code: CodeUntrustedKey, Path: SigName, Detail: fmt.Sprintf("signer %s is not a trusted key", sig.KeyID), Spans: []Span{se.data}})
			}
			if head != nil && head.KeyID != sig.KeyID {
				rep.add(Finding{Code: CodeHead, Path: HeadName, Detail: "head key_id differs from signature key_id", Spans: []Span{he.data}})
			}
		}
	}
	if head != nil && head.Format != FormatHead {
		rep.add(Finding{Code: CodeHead, Path: HeadName, Detail: fmt.Sprintf("unsupported head format %q", head.Format), Spans: []Span{he.data}})
	}
	if me == nil {
		return nil
	}
	rep.ManifestRaw = me.body
	if head != nil && hex.EncodeToString(me.sum[:]) != head.ManifestSHA256 {
		rep.add(Finding{Code: CodeManifestDigest, Path: ManifestName,
			Detail: fmt.Sprintf("manifest.json SHA-256 %x does not match signed digest %s", me.sum, head.ManifestSHA256), Spans: []Span{me.data}})
	}
	var m Manifest
	if err := decodeStrict(me.body, &m); err != nil {
		rep.add(Finding{Code: CodeManifest, Path: ManifestName, Detail: "manifest.json unparsable: " + err.Error(), Spans: []Span{me.data}})
		return nil
	}
	rep.Manifest = &m
	bad := func(format string, args ...any) {
		rep.add(Finding{Code: CodeManifest, Path: ManifestName, Detail: fmt.Sprintf(format, args...), Spans: []Span{me.data}})
	}
	if m.Format != FormatManifest {
		bad("unsupported manifest format %q", m.Format)
	}
	if head != nil && (m.CaseID != head.CaseID || !m.CreatedAt.Equal(head.CreatedAt)) {
		bad("case_id/created_at disagree with head.json")
	}
	if m.Merkle.LeafEncoding != LeafEncoding {
		bad("unsupported leaf encoding %q", m.Merkle.LeafEncoding)
	}
	for i := 1; i < len(m.Entries); i++ {
		if m.Entries[i-1].Path >= m.Entries[i].Path {
			bad("entries not strictly sorted at index %d (%q)", i, m.Entries[i].Path)
			break
		}
	}
	tree, err := BuildTree(m.Entries)
	if err != nil {
		bad("%v", err)
		return &m
	}
	root := tree.Root().String()
	if root != m.Merkle.Root || tree.Size() != m.Merkle.TreeSize {
		rep.add(Finding{Code: CodeMerkle, Path: ManifestName,
			Detail: fmt.Sprintf("entries hash to root %s (size %d) but manifest states %s (size %d)", root, tree.Size(), m.Merkle.Root, m.Merkle.TreeSize),
			Spans:  []Span{me.data}})
	}
	if head != nil && (root != head.MerkleRoot || tree.Size() != head.TreeSize) {
		rep.add(Finding{Code: CodeMerkle, Path: HeadName,
			Detail: fmt.Sprintf("entries hash to root %s (size %d) but signed head states %s (size %d)", root, tree.Size(), head.MerkleRoot, head.TreeSize),
			Spans:  []Span{me.data, he.data}})
	}
	return &m
}

func trusted(pub ed25519.PublicKey, set []ed25519.PublicKey) bool {
	for _, k := range set {
		if k.Equal(pub) {
			return true
		}
	}
	return false
}

// checkEntries compares the archive's payload members to the manifest.
func checkEntries(rep *Report, m *Manifest, payload []*tarEntry) {
	byName := map[string][]*tarEntry{}
	for _, e := range payload {
		byName[e.name] = append(byName[e.name], e)
	}
	listed := map[string]bool{}
	for _, want := range m.Entries {
		listed[want.Path] = true
		got := byName[want.Path]
		if len(got) == 0 {
			rep.add(Finding{Code: CodeEntryMissing, Path: want.Path, Detail: "listed in manifest but absent from archive"})
			continue
		}
		if len(got) > 1 {
			var sp []Span
			for _, g := range got[1:] {
				sp = append(sp, g.whole())
			}
			rep.add(Finding{Code: CodeEntryDuplicate, Path: want.Path, Detail: fmt.Sprintf("appears %d times in archive", len(got)), Spans: sp})
		}
		e := got[0]
		if e.typeflag != tar.TypeReg {
			rep.add(Finding{Code: CodeEntryType, Path: e.name, Detail: fmt.Sprintf("tar type %q, want regular file", e.typeflag), Spans: []Span{e.hdr}})
		}
		if e.size != want.Size {
			rep.add(Finding{Code: CodeEntrySize, Path: want.Path, Detail: fmt.Sprintf("size %d, manifest says %d", e.size, want.Size), Spans: []Span{e.whole()}})
			continue
		}
		if got := hex.EncodeToString(e.sum[:]); got != want.SHA256 {
			rep.add(Finding{Code: CodeEntryHash, Path: want.Path, Detail: fmt.Sprintf("content SHA-256 %s, manifest says %s", got, want.SHA256), Spans: []Span{e.data}})
		}
	}
	var extra []string
	for name := range byName {
		if !listed[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		for _, e := range byName[name] {
			rep.add(Finding{Code: CodeEntryUnexpected, Path: name, Detail: "archive member not listed in manifest", Spans: []Span{e.whole()}})
		}
	}
}

// region is a labelled range of the canonical stream, used to explain
// where a layout difference occurred.
type region struct {
	span  Span
	label string
	path  string
}

// checkLayout regenerates the canonical tar stream from the archive's own
// member names and contents and compares it byte-for-byte with the actual
// stream. Because content is taken from the archive itself, any difference
// is in bytes no hash covers: tar header fields, padding, the end-of-archive
// trailer, or trailing data. When recompress is set, the regenerated stream
// is also re-encoded with the sealing encoder and compared with the file
// digest, which catches edits to the compressed bytes that still decode to
// identical content. It returns whether the layout was canonical.
func checkLayout(rep *Report, open opener, ents []*tarEntry, recompress bool) bool {
	ra, err := open()
	if err != nil {
		rep.add(Finding{Code: CodeContainer, Detail: "reopen for layout check: " + err.Error()})
		return false
	}
	defer func() { _ = ra.Close() }()
	rb, err := open()
	if err != nil {
		rep.add(Finding{Code: CodeContainer, Detail: "reopen for layout check: " + err.Error()})
		return false
	}
	defer func() { _ = rb.Close() }()

	cmp := &comparer{ref: rb, diff: -1, buf: make([]byte, 32<<10)}
	var sink io.Writer = cmp
	var recHash hash.Hash
	var enc io.WriteCloser
	if recompress {
		recHash = sha256.New()
		e, err := newEncoder(recHash)
		if err != nil {
			rep.add(Finding{Code: CodeContainer, Detail: "encoder: " + err.Error()})
			return false
		}
		enc = e
		sink = io.MultiWriter(cmp, enc)
	}
	tw := tar.NewWriter(sink)
	tr := tar.NewReader(ra)
	var regions []region
	for _, want := range ents {
		h, err := tr.Next()
		if err != nil || h.Name != want.name {
			rep.add(Finding{Code: CodeContainer, Detail: "archive changed between verification passes"})
			return false
		}
		start := cmp.off
		if err := tw.WriteHeader(canonicalHeader(h.Name, h.Size)); err != nil {
			// A member whose name/size cannot be canonically encoded
			// cannot have been produced by Seal.
			rep.add(Finding{Code: CodeLayout, Path: h.Name, Detail: "member cannot be canonically encoded: " + err.Error(), Spans: []Span{want.hdr}})
			return false
		}
		regions = append(regions, region{Span{start, cmp.off}, "tar header", h.Name})
		if _, err := io.Copy(tw, tr); err != nil { //nolint:gosec // G110: streamed through the comparator, never buffered
			rep.add(Finding{Code: CodeContainer, Detail: "archive changed between verification passes"})
			return false
		}
		start = cmp.off
		if err := tw.Flush(); err != nil {
			rep.add(Finding{Code: CodeContainer, Detail: err.Error()})
			return false
		}
		if cmp.off > start {
			regions = append(regions, region{Span{start, cmp.off}, "tar padding", h.Name})
		}
	}
	start := cmp.off
	if err := tw.Close(); err != nil {
		rep.add(Finding{Code: CodeContainer, Detail: err.Error()})
		return false
	}
	regions = append(regions, region{Span{start, cmp.off}, "end-of-archive trailer", ""})
	cmp.finish()
	if cmp.diff >= 0 {
		f := Finding{Code: CodeLayout, Detail: fmt.Sprintf("byte %d differs from canonical layout", cmp.diff)}
		f.Spans = []Span{{cmp.diff, cmp.diff + 1}}
		found := false
		for _, r := range regions {
			if r.span.Contains(cmp.diff) {
				f.Path, f.Detail, f.Spans = r.path, fmt.Sprintf("%s byte %d differs from canonical layout", r.label, cmp.diff), []Span{r.span}
				found = true
				break
			}
		}
		if !found {
			f.Detail = fmt.Sprintf("unexpected data after end-of-archive trailer at byte %d", cmp.diff)
			f.Spans = []Span{{cmp.diff, max(cmp.off, cmp.diff+1)}}
		}
		rep.add(f)
		return false
	}
	if recompress {
		if err := enc.Close(); err != nil {
			rep.add(Finding{Code: CodeContainer, Detail: "encoder: " + err.Error()})
			return false
		}
		if got := hex.EncodeToString(recHash.Sum(nil)); rep.FileSHA256 != "" && got != rep.FileSHA256 {
			rep.add(Finding{Code: CodeContainerNoncan,
				Detail: "archive content is intact but the compressed bytes differ from the canonical encoding (the .tar.zst framing was altered)"})
		}
	}
	return true
}

// comparer is an io.Writer that compares everything written to it with the
// bytes of ref, remembering the first differing offset.
type comparer struct {
	ref  io.Reader
	off  int64
	diff int64
	buf  []byte
	eof  bool
}

func (c *comparer) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 && c.diff < 0 {
		chunk := min(len(p), len(c.buf))
		got, _ := io.ReadFull(c.ref, c.buf[:chunk])
		for i := 0; i < got; i++ {
			if c.buf[i] != p[i] {
				c.diff = c.off + int64(i)
				break
			}
		}
		if c.diff < 0 && got < chunk {
			c.diff = c.off + int64(got) // actual stream ended early
			c.eof = true
		}
		if c.diff >= 0 {
			break
		}
		c.off += int64(chunk)
		p = p[chunk:]
	}
	if c.diff >= 0 {
		c.off += int64(len(p))
	}
	return n, nil
}

// finish checks the actual stream has nothing after the canonical end.
func (c *comparer) finish() {
	if c.diff >= 0 || c.eof {
		return
	}
	var one [1]byte
	if n, _ := io.ReadFull(c.ref, one[:]); n > 0 {
		c.diff = c.off
	}
}

// LoadTrustedKeys reads PEM public keys to pin as trusted signers.
func LoadTrustedKeys(paths []string) ([]ed25519.PublicKey, error) {
	out := make([]ed25519.PublicKey, 0, len(paths))
	for _, p := range paths {
		k, err := keys.LoadPublic(p)
		if err != nil {
			return nil, fmt.Errorf("trusted key %s: %w", p, err)
		}
		out = append(out, k)
	}
	return out, nil
}
