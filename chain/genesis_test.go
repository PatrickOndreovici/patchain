package chain

import (
	"blocker/crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenesisHashDeterministic(t *testing.T) {
	authority := NewAccount()
	alice := NewAccount()

	g := NewGenesis("patchain", authority.Address(), map[crypto.Address]uint64{
		authority.Address(): 1000,
		alice.Address():     500,
	})

	if g.Hash() != g.Hash() {
		t.Fatal("expected Genesis.Hash() to be deterministic")
	}

	// Modifying any balance must change the Genesis hash.
	gCopy := g
	gCopy.Balances = map[crypto.Address]uint64{
		authority.Address(): 1000,
		alice.Address():     9999,
	}
	if g.Hash() == gCopy.Hash() {
		t.Fatal("expected changing Balances to change Genesis.Hash()")
	}
}

func TestSignAndVerifyGenesis(t *testing.T) {
	authority := NewAccount()
	alice := NewAccount()

	g := NewGenesis("patchain", authority.Address(), map[crypto.Address]uint64{
		authority.Address(): 1000,
		alice.Address():     250,
	})

	sg, err := authority.SignGenesis(g)
	if err != nil {
		t.Fatalf("SignGenesis failed: %v", err)
	}
	if !sg.Verify() {
		t.Fatal("expected valid SignedGenesis to pass Verify()")
	}
}

func TestSignGenesisRejectsWrongAuthority(t *testing.T) {
	authority := NewAccount()
	mallory := NewAccount()

	g := NewGenesis("patchain", authority.Address(), map[crypto.Address]uint64{
		authority.Address(): 1000,
	})

	if _, err := mallory.SignGenesis(g); err == nil {
		t.Fatal("expected SignGenesis to reject non-authority account")
	}
}

func TestVerifyGenesisRejectsTamperingAndForgery(t *testing.T) {
	authority := NewAccount()
	alice := NewAccount()
	mallory := NewAccount()

	g := NewGenesis("patchain", authority.Address(), map[crypto.Address]uint64{
		authority.Address(): 1000,
		alice.Address():     500,
	})
	valid, err := authority.SignGenesis(g)
	if err != nil {
		t.Fatalf("SignGenesis failed: %v", err)
	}

	// 1. Tampering with Chain name must fail Verify().
	tamperedChain := valid
	tamperedChain.Chain = "fakechain"
	if tamperedChain.Verify() {
		t.Fatal("expected Verify() to reject tampered Chain name")
	}

	// 2. Tampering with Time must fail Verify().
	tamperedTime := valid
	tamperedTime.Time++
	if tamperedTime.Verify() {
		t.Fatal("expected Verify() to reject tampered Time")
	}

	// 3. Forged ownership: Mallory signs Genesis claiming Authority = authority using Mallory's key.
	forged := SignedGenesis{
		Genesis: g,
		PubKey:  mallory.PublicKey(),
		Sig:     mallory.privKey.Sign(g.Hash().Bytes()),
	}
	if forged.Verify() {
		t.Fatal("expected Verify() to reject forged Genesis signed by non-authority")
	}

	// 4. Empty / nil fields must return false (never panic).
	var empty SignedGenesis
	if empty.Verify() {
		t.Fatal("expected empty SignedGenesis to fail Verify()")
	}
}

func TestWriteAndReadGenesis(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")

	authority := NewAccount()
	alice := NewAccount()

	g := NewGenesis("patchain", authority.Address(), map[crypto.Address]uint64{
		authority.Address(): 1000,
		alice.Address():     500,
	})
	sg, err := authority.SignGenesis(g)
	if err != nil {
		t.Fatalf("SignGenesis failed: %v", err)
	}

	if err := WriteGenesis(path, sg); err != nil {
		t.Fatalf("WriteGenesis failed: %v", err)
	}

	loaded, err := ReadGenesis(path)
	if err != nil {
		t.Fatalf("ReadGenesis failed: %v", err)
	}

	if !loaded.Verify() {
		t.Fatal("expected reloaded SignedGenesis to pass Verify()")
	}
	if loaded.Hash() != sg.Hash() {
		t.Fatalf("genesis hash mismatch: got %s, want %s", loaded.Hash(), sg.Hash())
	}
	if loaded.Chain != "patchain" {
		t.Fatalf("chain mismatch: got %q, want %q", loaded.Chain, "patchain")
	}
	if loaded.Authority != authority.Address() {
		t.Fatalf("authority mismatch: got %s, want %s", loaded.Authority, authority.Address())
	}
	if loaded.Balances[authority.Address()] != 1000 || loaded.Balances[alice.Address()] != 500 {
		t.Fatalf("unexpected balances after reload: %+v", loaded.Balances)
	}
}

func TestReadGenesisDetectsDiskTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")

	authority := NewAccount()
	alice := NewAccount()

	g := NewGenesis("patchain", authority.Address(), map[crypto.Address]uint64{
		authority.Address(): 1000,
		alice.Address():     500,
	})
	sg, err := authority.SignGenesis(g)
	if err != nil {
		t.Fatalf("SignGenesis failed: %v", err)
	}
	if err := WriteGenesis(path, sg); err != nil {
		t.Fatalf("WriteGenesis failed: %v", err)
	}

	// Simulate someone editing genesis.json in a text editor to inflate Alice's balance.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	tampered := strings.Replace(string(raw), "500", "9999999", 1)
	if err := os.WriteFile(path, []byte(tampered), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loaded, err := ReadGenesis(path)
	if err != nil {
		t.Fatalf("ReadGenesis failed: %v", err)
	}
	if loaded.Verify() {
		t.Fatal("expected Verify() to reject genesis.json modified on disk")
	}
}
