// Package keys manages the ed25519 keys that seal bundles and sign custody
// entries. Keys are stored as standard PEM (PKCS#8 private, PKIX public), so
// they interoperate with OpenSSL:
//
//	openssl pkey -in collector.key -pubout
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	pemPrivate = "PRIVATE KEY"
	pemPublic  = "PUBLIC KEY"
)

// Generate creates a new key pair from rnd (crypto/rand if nil).
func Generate(rnd io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	pub, priv, err := ed25519.GenerateKey(rnd)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return pub, priv, nil
}

// KeyID is a short, stable identifier: "ed25519:" + the first 16 bytes of
// SHA-256(public key) in hex.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:16])
}

// EncodePublic returns the standard base64 of the raw 32-byte key.
func EncodePublic(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }

// DecodePublic parses EncodePublic output, insisting on the canonical
// encoding so one key has exactly one textual form.
func DecodePublic(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key: %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	if base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("public key: non-canonical base64")
	}
	return ed25519.PublicKey(b), nil
}

// MarshalPrivate encodes a private key as PKCS#8 PEM.
func MarshalPrivate(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemPrivate, Bytes: der}), nil
}

// MarshalPublic encodes a public key as PKIX PEM.
func MarshalPublic(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemPublic, Bytes: der}), nil
}

// ParsePrivate decodes a PKCS#8 PEM ed25519 private key.
func ParsePrivate(b []byte) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != pemPrivate {
		return nil, errors.New("private key: no PEM \"PRIVATE KEY\" block")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key: %T is not ed25519", k)
	}
	return priv, nil
}

// ParsePublic decodes a PKIX PEM ed25519 public key.
func ParsePublic(b []byte) (ed25519.PublicKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != pemPublic {
		return nil, errors.New("public key: no PEM \"PUBLIC KEY\" block")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key: %T is not ed25519", k)
	}
	return pub, nil
}

// WritePair writes <base>.key (mode 0600) and <base>.pub (mode 0644). It
// refuses to overwrite an existing private key.
func WritePair(base string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	kb, err := MarshalPrivate(priv)
	if err != nil {
		return err
	}
	pb, err := MarshalPublic(pub)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(base+".key", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if _, err := f.Write(kb); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.WriteFile(base+".pub", pb, 0o644) //nolint:gosec // public key is meant to be shared
}

// LoadPrivate reads a private key file. It refuses files readable by group
// or others: a signing key anyone can read proves nothing.
func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private key %s has mode %04o; chmod 600 it", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivate(b)
}

// LoadPublic reads a public key file.
func LoadPublic(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublic(b)
}
