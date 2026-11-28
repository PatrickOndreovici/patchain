package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const hashSize = 32

type Hash [hashSize]byte

func HashData(data []byte) Hash {
	return sha256.Sum256(data)
}

func (h Hash) Bytes() []byte {
	return h[:]
}

func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

func (h Hash) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

func (h *Hash) UnmarshalText(text []byte) error {
	b, err := hex.DecodeString(string(text))
	if err != nil {
		return err
	}
	if len(b) != hashSize {
		return fmt.Errorf("invalid hash length: got %d, want %d", len(b), hashSize)
	}
	copy(h[:], b)
	return nil
}
