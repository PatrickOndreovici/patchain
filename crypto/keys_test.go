package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()

	if len(privKey.Bytes()) != privateKeySize {
		t.Fatalf("expected private key length %d, got %d", privateKeySize, len(privKey.Bytes()))
	}

	pubKey := privKey.PublicKey()
	if len(pubKey.Bytes()) != publicKeySize {
		t.Fatalf("expected public key length %d, got %d", publicKeySize, len(pubKey.Bytes()))
	}

	// Generating a second key should produce a completely different key.
	otherPrivKey := GeneratePrivateKey()
	if bytes.Equal(privKey.Bytes(), otherPrivKey.Bytes()) {
		t.Fatal("expected two generated private keys to be different")
	}
}

func TestPublicKeyDefensiveCopy(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.PublicKey()

	original := append([]byte(nil), pubKey.Bytes()...)

	// Mutate the returned public key bytes; the private key must remain untouched.
	pubKey.Bytes()[0] ^= 0xff

	freshPubKey := privKey.PublicKey()
	if !bytes.Equal(original, freshPubKey.Bytes()) {
		t.Fatal("mutating PublicKey bytes corrupted the underlying PrivateKey")
	}
}

func TestPrivateKeySignAndVerify(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.PublicKey()
	msg := []byte("alice sends 10 coins to bob")

	sig := privKey.Sign(msg)
	if len(sig.Bytes()) != ed25519.SignatureSize {
		t.Fatalf("expected signature length %d, got %d", ed25519.SignatureSize, len(sig.Bytes()))
	}

	// 1. Valid signature with matching key and message should pass.
	if !pubKey.Verify(msg, sig) {
		t.Fatal("expected valid signature to pass verification")
	}

	// 2. Tampering with even one character of the message must fail.
	tamperedMsg := []byte("alice sends 90 coins to bob")
	if pubKey.Verify(tamperedMsg, sig) {
		t.Fatal("expected verification to fail for tampered message")
	}

	// 3. Verifying with a different account's public key must fail.
	otherPubKey := GeneratePrivateKey().PublicKey()
	if otherPubKey.Verify(msg, sig) {
		t.Fatal("expected verification to fail for wrong public key")
	}

	// 4. Flipping a single bit in the signature must fail.
	tamperedSigBytes := append([]byte(nil), sig.Bytes()...)
	tamperedSigBytes[0] ^= 0x01
	tamperedSig := &Signature{value: tamperedSigBytes}
	if pubKey.Verify(msg, tamperedSig) {
		t.Fatal("expected verification to fail for tampered signature")
	}
}

func TestPublicKeyVerifyEdgeCases(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.PublicKey()
	msg := []byte("hello blockchain")
	validSig := privKey.Sign(msg)

	// Nil signature must return false (never panic).
	if pubKey.Verify(msg, nil) {
		t.Fatal("expected nil signature to fail verification")
	}

	// Wrong-length signature must return false (never panic).
	shortSig := &Signature{value: []byte("too short")}
	if pubKey.Verify(msg, shortSig) {
		t.Fatal("expected short signature to fail verification")
	}

	// Empty/uninitialized PublicKey must return false (never panic).
	emptyPubKey := &PublicKey{}
	if emptyPubKey.Verify(msg, validSig) {
		t.Fatal("expected empty public key to fail verification")
	}

	// Nil PublicKey pointer must return false (never panic).
	var nilPubKey *PublicKey
	if nilPubKey.Verify(msg, validSig) {
		t.Fatal("expected nil public key to fail verification")
	}
}
