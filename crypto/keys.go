package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
)

const (
	privateKeySize = 64
	publicKeySize  = 32
	seedSize       = 32
)

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

func (p *PublicKey) Verify(msg []byte, sig *Signature) bool {
	if p == nil || sig == nil || len(sig.value) != ed25519.SignatureSize || len(p.key) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(p.key, msg, sig.value)
}
