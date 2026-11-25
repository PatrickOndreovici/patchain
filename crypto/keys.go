package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	privateKeySize = 64
	publicKeySize  = 32
	seedSize       = 32
	addressSize    = 20
)

type Address [addressSize]byte

func (a Address) Bytes() []byte {
	return a[:]
}

func (a Address) String() string {
	return hex.EncodeToString(a[:])
}

type Signature struct {
	value []byte
}

func (s *Signature) Bytes() []byte {
	return s.value
}

type PrivateKey struct {
	key ed25519.PrivateKey
}

func GeneratePrivateKey() *PrivateKey {
	seed := make([]byte, seedSize)
	_, err := io.ReadFull(rand.Reader, seed)
	if err != nil {
		panic(err)
	}
	return &PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}
}

func PrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	if len(seed) != seedSize {
		return nil, fmt.Errorf("invalid seed length: got %d, want %d", len(seed), seedSize)
	}
	return &PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}, nil
}

func (p *PrivateKey) Seed() []byte {
	seed := make([]byte, seedSize)
	copy(seed, p.key[:seedSize])
	return seed
}

func (p *PrivateKey) Bytes() []byte {
	return p.key
}

func (p *PrivateKey) Sign(msg []byte) *Signature {
	return &Signature{
		value: ed25519.Sign(p.key, msg),
	}
}

func (p *PrivateKey) PublicKey() *PublicKey {
	b := make([]byte, publicKeySize)
	copy(b, p.key[32:])
	return &PublicKey{key: b}
}

type PublicKey struct {
	key ed25519.PublicKey
}

func (p *PublicKey) Bytes() []byte {
	return p.key
}

func (p *PublicKey) Address() Address {
	hash := sha256.Sum256(p.key)
	var addr Address
	copy(addr[:], hash[len(hash)-addressSize:])
	return addr
}

func (p *PublicKey) Verify(msg []byte, sig *Signature) bool {
	if p == nil || sig == nil || len(sig.value) != ed25519.SignatureSize || len(p.key) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(p.key, msg, sig.value)
}
