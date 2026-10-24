package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateWriteLoad(t *testing.T) {
	base := filepath.Join(t.TempDir(), "collector")
	pub, priv, err := Generate(bytes.NewReader(bytes.Repeat([]byte{4}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePair(base, pub, priv); err != nil {
		t.Fatal(err)
	}
	if err := WritePair(base, pub, priv); err == nil {
		t.Fatal("overwrote private key")
	}
	fi, _ := os.Stat(base + ".key")
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %v", fi.Mode())
	}
	p2, err := LoadPrivate(base + ".key")
	if err != nil || !p2.Equal(priv) {
		t.Fatalf("LoadPrivate: %v", err)
	}
	pub2, err := LoadPublic(base + ".pub")
	if err != nil || !pub2.Equal(pub) {
		t.Fatalf("LoadPublic: %v", err)
	}
	os.Chmod(base+".key", 0o644)
	if _, err := LoadPrivate(base + ".key"); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("world-readable key accepted: %v", err)
	}
	if _, err := LoadPrivate(base + ".missing"); err == nil {
		t.Fatal("missing key")
	}
	if _, err := LoadPublic(base + ".missing"); err == nil {
		t.Fatal("missing pub")
	}
	if _, _, err := Generate(nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Generate(bytes.NewReader(nil)); err == nil {
		t.Fatal("empty entropy accepted")
	}
}

func TestEncodingsAndIDs(t *testing.T) {
	pub, _, _ := Generate(nil)
	s := EncodePublic(pub)
	back, err := DecodePublic(s)
	if err != nil || !back.Equal(pub) {
		t.Fatal(err)
	}
	if id := KeyID(pub); !strings.HasPrefix(id, "ed25519:") || len(id) != len("ed25519:")+32 {
		t.Fatalf("KeyID %q", id)
	}
	for _, bad := range []string{"", "!!", "AAAA", s[:len(s)-2] + "=="} {
		if _, err := DecodePublic(bad); err == nil {
			t.Errorf("DecodePublic(%q) accepted", bad)
		}
	}
}

func TestParseRejectsWrongTypes(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ec)
	if _, err := ParsePrivate(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err == nil {
		t.Fatal("ECDSA private key accepted")
	}
	pder, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if _, err := ParsePublic(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pder})); err == nil {
		t.Fatal("ECDSA public key accepted")
	}
	for _, b := range [][]byte{nil, []byte("junk"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})} {
		if _, err := ParsePrivate(b); err == nil {
			t.Error("garbage private key accepted")
		}
	}
	for _, b := range [][]byte{nil, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}})} {
		if _, err := ParsePublic(b); err == nil {
			t.Error("garbage public key accepted")
		}
	}
}
