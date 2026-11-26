package chain

import (
	"testing"
)

func TestTxHashDeterministic(t *testing.T) {
	alice := NewAccount()
	bob := NewAccount()

	tx := NewTx(alice.Address(), bob.Address(), 25, 1)
	if tx.Hash() != tx.Hash() {
		t.Fatal("expected Tx.Hash() to be deterministic")
	}

	// Changing any single field must produce a completely different hash.
	modified := tx
	modified.Value = 26
	if tx.Hash() == modified.Hash() {
		t.Fatal("expected changing Value to produce a different Tx hash")
	}

	modifiedNonce := tx
	modifiedNonce.Nonce = 2
	if tx.Hash() == modifiedNonce.Hash() {
		t.Fatal("expected changing Nonce to produce a different Tx hash")
	}
}

func TestSignAndVerifyTx(t *testing.T) {
	alice := NewAccount()
	bob := NewAccount()

	tx := NewTx(alice.Address(), bob.Address(), 100, 1)
	stx, err := alice.SignTx(tx)
	if err != nil {
		t.Fatalf("SignTx failed: %v", err)
	}

	if !stx.Verify() {
		t.Fatal("expected valid SignedTx to pass Verify()")
	}
}

func TestVerifyTxRejectsTampering(t *testing.T) {
	alice := NewAccount()
	bob := NewAccount()
	mallory := NewAccount()

	tx := NewTx(alice.Address(), bob.Address(), 10, 1)
	validStx, err := alice.SignTx(tx)
	if err != nil {
		t.Fatalf("SignTx failed: %v", err)
	}

	tests := []struct {
		name   string
		tamper func(s *SignedTx)
	}{
		{
			name:   "modified Value",
			tamper: func(s *SignedTx) { s.Value = 1000 },
		},
		{
			name:   "modified To address",
			tamper: func(s *SignedTx) { s.To = mallory.Address() },
		},
		{
			name:   "modified From address",
			tamper: func(s *SignedTx) { s.From = mallory.Address() },
		},
		{
			name:   "modified Nonce",
			tamper: func(s *SignedTx) { s.Nonce = 2 },
		},
		{
			name:   "modified Time",
			tamper: func(s *SignedTx) { s.Time++ },
		},
		{
			name:   "swapped PubKey",
			tamper: func(s *SignedTx) { s.PubKey = mallory.PublicKey() },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tampered := validStx
			tc.tamper(&tampered)
			if tampered.Verify() {
				t.Fatalf("expected Verify() to reject SignedTx with %s", tc.name)
			}
		})
	}
}

func TestSignTxRejectsWrongAccount(t *testing.T) {
	alice := NewAccount()
	bob := NewAccount()

	// Transaction claims From = Alice, but Bob tries to sign it.
	tx := NewTx(alice.Address(), bob.Address(), 50, 1)
	if _, err := bob.SignTx(tx); err == nil {
		t.Fatal("expected SignTx to fail when account address does not match tx.From")
	}
}

func TestVerifyTxRejectsForgedOwnership(t *testing.T) {
	alice := NewAccount()
	mallory := NewAccount()

	// Attacker bypasses SignTx and manually crafts a SignedTx claiming From = Alice,
	// signed legitimately with Mallory's private key and carrying Mallory's public key.
	// Rule 2 (signature validity) would pass on its own, so Rule 1 (PubKey.Address() == From)
	// MUST catch this forgery!
	tx := NewTx(alice.Address(), mallory.Address(), 999, 1)
	forged := SignedTx{
		Tx:     tx,
		PubKey: mallory.PublicKey(),
		Sig:    mallory.privKey.Sign(tx.Hash().Bytes()),
	}

	if forged.Verify() {
		t.Fatal("expected Verify() to reject forged transaction where PubKey does not own From")
	}
}

func TestVerifyTxEdgeCases(t *testing.T) {
	alice := NewAccount()
	bob := NewAccount()
	tx := NewTx(alice.Address(), bob.Address(), 10, 1)
	validStx, err := alice.SignTx(tx)
	if err != nil {
		t.Fatalf("SignTx failed: %v", err)
	}

	// Zero-value SignedTx must return false (never panic).
	var empty SignedTx
	if empty.Verify() {
		t.Fatal("expected empty SignedTx to fail Verify()")
	}

	// Nil PubKey must return false.
	noPubKey := validStx
	noPubKey.PubKey = nil
	if noPubKey.Verify() {
		t.Fatal("expected SignedTx with nil PubKey to fail Verify()")
	}

	// Nil Sig must return false.
	noSig := validStx
	noSig.Sig = nil
	if noSig.Verify() {
		t.Fatal("expected SignedTx with nil Sig to fail Verify()")
	}
}
