package chain

import (
	"blocker/crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

const (
	saltSize   = 32
	aesKeySize = 32 // 32 bytes = AES-256
)

type Account struct {
	privKey *crypto.PrivateKey
	addr    crypto.Address
}

// encryptedKeystore is the JSON structure persisted to <address>.json on disk.
type encryptedKeystore struct {
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func NewAccount() *Account {
	privKey := crypto.GeneratePrivateKey()
	return &Account{
		privKey: privKey,
		addr:    privKey.PublicKey().Address(),
	}
}

func (a *Account) Address() crypto.Address {
	return a.addr
}

func (a *Account) PublicKey() *crypto.PublicKey {
	return a.privKey.PublicKey()
}

// deriveKey stretches a human password + random salt into a 32-byte AES-256 key.
func deriveKey(pass, salt []byte) []byte {
	return argon2.IDKey(pass, salt, 1, 64*1024, 4, aesKeySize)
}

func (a *Account) Write(dir string, pass []byte) error {
	// 1. Generate a random 32-byte salt using io.ReadFull(rand.Reader, salt).
	salt := make([]byte, saltSize)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return err
	}

	// 2. Call deriveKey(pass, salt) to get the 32-byte AES key.
	key := deriveKey(pass, salt)

	// 3. Create AES cipher (aes.NewCipher) and wrap with GCM (cipher.NewGCM).
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// 4. Generate a random nonce of size gcm.NonceSize().
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	// 5. Encrypt a.privKey.Seed() using gcm.Seal(nil, nonce, a.privKey.Seed(), nil).
	encryptedKey := gcm.Seal(nil, nonce, a.privKey.Seed(), nil)

	// 6. Marshal encryptedKeystore{Salt, Nonce, Ciphertext} with json.Marshal.
	ks := encryptedKeystore{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: encryptedKey,
	}
	data, err := json.Marshal(ks)
	if err != nil {
		return err
	}

	// 7. Ensure dir exists (os.MkdirAll) and write to filepath.Join(dir, a.addr.String()+".json") with 0600 permissions.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, a.addr.String()+".json")
	return os.WriteFile(path, data, 0600)
}

func ReadAccount(path string, pass []byte) (*Account, error) {
	// TODO (your turn!):
	// 1. Read file bytes with os.ReadFile(path) and json.Unmarshal into encryptedKeystore.
	// 2. Re-derive the AES key with deriveKey(pass, ks.Salt).
	// 3. Create AES cipher (aes.NewCipher) and wrap with GCM (cipher.NewGCM).
	// 4. Decrypt the seed with gcm.Open(nil, ks.Nonce, ks.Ciphertext, nil).
	// 5. Reconstruct the private key with crypto.PrivateKeyFromSeed(seed).
	// 6. Return &Account{privKey: privKey, addr: privKey.PublicKey().Address()}, nil.
	return nil, nil
}
