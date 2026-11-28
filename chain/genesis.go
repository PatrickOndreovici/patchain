package chain

import (
	"blocker/crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Genesis struct {
	Chain     string                    `json:"chain"`
	Authority crypto.Address            `json:"authority"`
	Balances  map[crypto.Address]uint64 `json:"balances"`
	Time      int64                     `json:"time"`
}

func NewGenesis(chain string, authority crypto.Address, balances map[crypto.Address]uint64) Genesis {
	return Genesis{
		Chain:     chain,
		Authority: authority,
		Balances:  balances,
		Time:      time.Now().UnixNano(),
	}
}

func (g Genesis) Hash() crypto.Hash {
	data, err := json.Marshal(g)
	if err != nil {
		panic(err)
	}
	return crypto.HashData(data)
}

type SignedGenesis struct {
	Genesis
	PubKey *crypto.PublicKey `json:"pubKey"`
	Sig    *crypto.Signature `json:"sig"`
}

func (a *Account) SignGenesis(g Genesis) (SignedGenesis, error) {
	if a.addr != g.Authority {
		return SignedGenesis{}, fmt.Errorf("account %s cannot sign genesis for authority %s", a.addr, g.Authority)
	}
	hash := g.Hash()
	sig := a.privKey.Sign(hash.Bytes())
	return SignedGenesis{
		Genesis: g,
		PubKey:  a.PublicKey(),
		Sig:     sig,
	}, nil
}

func (sg SignedGenesis) Verify() bool {
	if sg.PubKey == nil || sg.Sig == nil {
		return false
	}
	// Rule 1 (Ownership): does the public key derive the Genesis Authority address?
	if sg.PubKey.Address() != sg.Authority {
		return false
	}
	// Rule 2 (Integrity): did the Authority's private key sign this exact Genesis hash?
	return sg.PubKey.Verify(sg.Hash().Bytes(), sg.Sig)
}

func WriteGenesis(path string, sg SignedGenesis) error {
	data, err := json.MarshalIndent(sg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func ReadGenesis(path string) (SignedGenesis, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SignedGenesis{}, err
	}
	var sg SignedGenesis
	if err := json.Unmarshal(data, &sg); err != nil {
		return SignedGenesis{}, err
	}
	return sg, nil
}
