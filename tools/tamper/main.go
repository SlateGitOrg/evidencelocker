// Command tamper makes deliberately corrupted copies of a bundle for demos
// and tests of the verifier. It never modifies its input.
//
//	tamper -mode content -path files/etc/crontab -offset 3 IN OUT   flip a byte inside one entry
//	tamper -mode tar -offset 1000 IN OUT                            flip a byte of the uncompressed tar
//	tamper -mode raw -offset 40 IN OUT                              flip a byte of the .tar.zst file
//
// Content and tar modes re-compress with the same encoder settings the
// sealer uses, so the verifier reports the edit itself rather than a
// container-level difference.
package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"
)

func main() {
	mode := flag.String("mode", "content", "content, tar or raw")
	entry := flag.String("path", "", "entry path (content mode)")
	offset := flag.Int64("offset", 0, "byte offset to flip (XOR 0xff)")
	flag.Parse()
	if flag.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "usage: tamper -mode content|tar|raw [-path P] -offset N IN OUT")
		os.Exit(2)
	}
	if err := run(*mode, *entry, *offset, flag.Arg(0), flag.Arg(1)); err != nil {
		fmt.Fprintln(os.Stderr, "tamper:", err)
		os.Exit(1)
	}
}

func run(mode, entry string, off int64, in, out string) error {
	raw, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	if mode == "raw" {
		if off < 0 || off >= int64(len(raw)) {
			return errors.New("offset out of range")
		}
		raw[off] ^= 0xff
		return write(out, raw)
	}
	dec, err := zstd.NewReader(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	tarb, err := io.ReadAll(dec)
	dec.Close()
	if err != nil {
		return err
	}
	switch mode {
	case "tar":
	case "content":
		start, size, err := locate(tarb, entry)
		if err != nil {
			return err
		}
		if off < 0 || off >= size {
			return fmt.Errorf("offset %d outside entry of %d bytes", off, size)
		}
		off += start
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
	if off < 0 || off >= int64(len(tarb)) {
		return errors.New("offset out of range")
	}
	tarb[off] ^= 0xff
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1), zstd.WithEncoderCRC(true))
	if err != nil {
		return err
	}
	if _, err := enc.Write(tarb); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	fmt.Printf("flipped tar byte %d\n", off)
	return write(out, buf.Bytes())
}

// locate returns the data offset and size of an entry in a tar stream.
func locate(tarb []byte, name string) (int64, int64, error) {
	cr := &counter{r: bytes.NewReader(tarb)}
	tr := tar.NewReader(cr)
	for {
		h, err := tr.Next()
		if err != nil {
			return 0, 0, fmt.Errorf("entry %q not found: %w", name, err)
		}
		if h.Name == name {
			return cr.n, h.Size, nil
		}
		if _, err := io.Copy(io.Discard, tr); err != nil { //nolint:gosec // G110: discarded, nothing buffered
			return 0, 0, err
		}
	}
}

type counter struct {
	r io.Reader
	n int64
}

func (c *counter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func write(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
