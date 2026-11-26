package crypto

import (
	"crypto/sha256"
	"encoding/hex"
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
