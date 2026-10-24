// Package merkle implements the RFC 9162 (Certificate Transparency v2)
// Merkle tree: domain-separated SHA-256 leaf and node hashes over a
// left-balanced binary tree, with inclusion (audit path) proofs.
//
// Domain separation (0x00 prefix for leaves, 0x01 for interior nodes) stops
// an attacker presenting an interior node as a leaf (second-preimage).
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Hash is a SHA-256 digest.
type Hash [32]byte

// String returns lowercase hex.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// ParseHash decodes 64 lowercase hex characters. Uppercase is rejected so
// every hash has exactly one valid encoding.
func ParseHash(s string) (Hash, error) {
	var h Hash
	if len(s) != 64 {
		return h, fmt.Errorf("hash %q: want 64 hex chars, got %d", s, len(s))
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return h, fmt.Errorf("hash %q: not lowercase hex", s)
		}
	}
	_, err := hex.Decode(h[:], []byte(s))
	return h, err
}

// EmptyRoot is the root of a tree with no leaves: SHA-256 of the empty string.
var EmptyRoot = Hash(sha256.Sum256(nil))

// LeafHash returns SHA-256(0x00 || data).
func LeafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out Hash
	h.Sum(out[:0])
	return out
}

// NodeHash returns SHA-256(0x01 || left || right).
func NodeHash(left, right Hash) Hash {
	var buf [65]byte
	buf[0] = 0x01
	copy(buf[1:33], left[:])
	copy(buf[33:], right[:])
	return sha256.Sum256(buf[:])
}

// Tree is a fully materialised Merkle tree. Building costs O(n) hashes and
// O(n) memory; each inclusion proof is then O(log n).
//
// levels[0] holds the leaf hashes. levels[k+1] pairs up levels[k]; an odd
// trailing node is promoted unchanged, which yields exactly RFC 9162's
// left-balanced tree (the largest power-of-two split).
type Tree struct {
	levels [][]Hash
}

// New builds a tree from leaf hashes (already LeafHash-ed).
func New(leaves []Hash) *Tree {
	t := &Tree{levels: [][]Hash{append([]Hash(nil), leaves...)}}
	for cur := t.levels[0]; len(cur) > 1; {
		next := make([]Hash, 0, (len(cur)+1)/2)
		for i := 0; i+1 < len(cur); i += 2 {
			next = append(next, NodeHash(cur[i], cur[i+1]))
		}
		if len(cur)%2 == 1 {
			next = append(next, cur[len(cur)-1])
		}
		t.levels = append(t.levels, next)
		cur = next
	}
	return t
}

// Size returns the number of leaves.
func (t *Tree) Size() int { return len(t.levels[0]) }

// Root returns the tree head hash.
func (t *Tree) Root() Hash {
	top := t.levels[len(t.levels)-1]
	if len(top) == 0 {
		return EmptyRoot
	}
	return top[0]
}

// Leaf returns leaf i's hash.
func (t *Tree) Leaf(i int) Hash { return t.levels[0][i] }

// ErrIndex is returned for an out-of-range leaf index.
var ErrIndex = errors.New("leaf index out of range")

// Proof returns the inclusion proof (audit path) for leaf i, ordered from
// the leaf's sibling upward, as defined by RFC 9162 section 2.1.3.1.
func (t *Tree) Proof(i int) ([]Hash, error) {
	if i < 0 || i >= t.Size() {
		return nil, ErrIndex
	}
	var path []Hash
	idx := i
	for lvl := 0; lvl < len(t.levels)-1; lvl++ {
		nodes := t.levels[lvl]
		sib := idx ^ 1
		if sib < len(nodes) {
			path = append(path, nodes[sib])
		}
		// A promoted node (no sibling) contributes nothing at this level.
		idx /= 2
	}
	return path, nil
}

// ErrProof is returned when an inclusion proof does not verify.
var ErrProof = errors.New("inclusion proof does not verify")

// VerifyInclusion checks that leaf (a LeafHash) is at index in a tree of
// size leaves with the given root, using the RFC 9162 section 2.1.3.2
// algorithm.
func VerifyInclusion(leaf Hash, index, size int, proof []Hash, root Hash) error {
	if index < 0 || index >= size {
		return ErrIndex
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return fmt.Errorf("%w: proof longer than tree height", ErrProof)
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fmt.Errorf("%w: proof shorter than tree height", ErrProof)
	}
	if r != root {
		return fmt.Errorf("%w: computed root %s != %s", ErrProof, r, root)
	}
	return nil
}
