package chain

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAccountWriteCreatesEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	acc := NewAccount()
	pass := []byte("super-secret-password")

	if err := acc.Write(dir, pass); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	path := filepath.Join(dir, acc.Address().String()+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected keystore file at %s: %v", path, err)
	}

	// Verify the raw password and raw private key seed are NOT stored in plain text.
	if bytes.Contains(raw, pass) {
		t.Fatal("keystore file must not contain the plaintext password")
	}
	if bytes.Contains(raw, acc.privKey.Seed()) {
		t.Fatal("keystore file must not contain the plaintext private key seed")
	}

	// Verify valid JSON with non-empty salt, nonce, and ciphertext.
	var ks encryptedKeystore
	if err := json.Unmarshal(raw, &ks); err != nil {
		t.Fatalf("keystore file is not valid JSON: %v", err)
	}
	if len(ks.Salt) != saltSize {
		t.Fatalf("expected salt length %d, got %d", saltSize, len(ks.Salt))
	}
	if len(ks.Nonce) == 0 || len(ks.Ciphertext) == 0 {
		t.Fatal("expected non-empty nonce and ciphertext")
	}
}

func TestAccountWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	acc := NewAccount()
	pass := []byte("my-wallet-password")

	if err := acc.Write(dir, pass); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	path := filepath.Join(dir, acc.Address().String()+".json")
	loaded, err := ReadAccount(path, pass)
	if err != nil {
		t.Fatalf("ReadAccount failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("ReadAccount returned nil account")
	}

	// Reloaded account must have the exact same address, public key, and signing ability.
	if loaded.Address() != acc.Address() {
		t.Fatalf("address mismatch: got %s, want %s", loaded.Address(), acc.Address())
	}
	if !bytes.Equal(loaded.PublicKey().Bytes(), acc.PublicKey().Bytes()) {
		t.Fatal("public key mismatch after reload")
	}

	// Prove the reloaded private key produces valid signatures for the original public key.
	msg := []byte("send 50 PAT to bob")
	sig := loaded.privKey.Sign(msg)
	if !acc.PublicKey().Verify(msg, sig) {
		t.Fatal("signature from reloaded account failed verification against original public key")
	}
}

func TestReadAccountWrongPassword(t *testing.T) {
	dir := t.TempDir()
	acc := NewAccount()
	if err := acc.Write(dir, []byte("correct-password")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	path := filepath.Join(dir, acc.Address().String()+".json")
	loaded, err := ReadAccount(path, []byte("wrong-password"))
	if err == nil {
		t.Fatalf("expected error with wrong password, got account %v", loaded)
	}
}

func TestReadAccountTamperedCiphertext(t *testing.T) {
	dir := t.TempDir()
	acc := NewAccount()
	pass := []byte("correct-password")
	if err := acc.Write(dir, pass); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	path := filepath.Join(dir, acc.Address().String()+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var ks encryptedKeystore
	if err := json.Unmarshal(raw, &ks); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	// Flip 1 bit in the encrypted seed; AES-GCM authentication must catch this!
	ks.Ciphertext[0] ^= 0x01
	tampered, _ := json.Marshal(ks)
	if err := os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if _, err := ReadAccount(path, pass); err == nil {
		t.Fatal("expected ReadAccount to reject tampered ciphertext")
	}
}
