package chain

import (
	"blocker/crypto"
	"encoding/json"
	"fmt"
	"time"
)

type Tx struct {
	From  crypto.Address `json:"from"`
	To    crypto.Address `json:"to"`
	Value uint64         `json:"value"`
	Nonce uint64         `json:"nonce"`
	Time  int64          `json:"time"`
}

func NewTx(from, to crypto.Address, value, nonce uint64) Tx {
	return Tx{
		From:  from,
		To:    to,
		Value: value,
		Nonce: nonce,
		Time:  time.Now().UnixNano(),
	}
}

func (tx Tx) Hash() crypto.Hash {
	data, err := json.Marshal(tx)
	if err != nil {
		panic(err)
	}
	return crypto.HashData(data)
}

type SignedTx struct {
	Tx
	PubKey *crypto.PublicKey `json:"pubKey"`
	Sig    *crypto.Signature `json:"sig"`
}

func (a *Account) SignTx(tx Tx) (SignedTx, error) {
	if a.addr != tx.From {
		return SignedTx{}, fmt.Errorf("account %s cannot sign tx from %s", a.addr, tx.From)
	}
	hash := tx.Hash()
	sig := a.privKey.Sign(hash.Bytes())
	return SignedTx{
		Tx:     tx,
		PubKey: a.PublicKey(),
		Sig:    sig,
	}, nil
}

func (stx SignedTx) Verify() bool {
	if stx.PubKey == nil || stx.Sig == nil {
		return false
	}
	// Rule 1 (Ownership): does the public key derive the claimed From address?
	if stx.PubKey.Address() != stx.From {
		return false
	}
	// Rule 2 (Integrity): did the matching private key sign this exact Tx hash?
	return stx.PubKey.Verify(stx.Hash().Bytes(), stx.Sig)
}
