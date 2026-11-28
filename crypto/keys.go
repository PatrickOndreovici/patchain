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

func (a Address) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

func (a *Address) UnmarshalText(text []byte) error {
	b, err := hex.DecodeString(string(text))
	if err != nil {
		return err
	}
	if len(b) != addressSize {
		return fmt.Errorf("invalid address length: got %d, want %d", len(b), addressSize)
	}
	copy(a[:], b)
	return nil
}

type Signature struct {
	value []byte
}

func (s *Signature) Bytes() []byte {
	return s.value
}

func (s Signature) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(s.value)), nil
}

func (s *Signature) UnmarshalText(text []byte) error {
	b, err := hex.DecodeString(string(text))
	if err != nil {
		return err
	}
	if len(b) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: got %d, want %d", len(b), ed25519.SignatureSize)
	}
	s.value = b
	return nil
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

func (p PublicKey) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(p.key)), nil
}

func (p *PublicKey) UnmarshalText(text []byte) error {
	b, err := hex.DecodeString(string(text))
	if err != nil {
		return err
	}
	if len(b) != publicKeySize {
		return fmt.Errorf("invalid public key length: got %d, want %d", len(b), publicKeySize)
	}
	p.key = b
	return nil
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
