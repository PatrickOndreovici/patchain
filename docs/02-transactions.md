# Lesson 2: Transactions, Nonces & Replay Protection

> **Packages built:** `crypto/` ([`hash.go`](../crypto/hash.go)) and `chain/` ([`tx.go`](../chain/tx.go), [`tx_test.go`](../chain/tx_test.go))

This lesson covers how value moves between accounts, how digital signatures prevent forgery and tampering, and how sequential **Nonces** stop replay attacks.

---

## 1. Account Model vs. UTXO Model

Blockchains generally track balances in one of two ways:

| Model | Used By | How It Works |
| :--- | :--- | :--- |
| **Account Model** *(our chain)* | Ethereum, Solana | Each `Address` has a `balance` and a `nonce`. Sending 10 coins subtracts `10` from `From` and adds `10` to `To`. |
| **UTXO Model** | Bitcoin | Works like physical cash bills: you consume whole previous "outputs" and create new outputs (including "change" back to yourself). |

---

## 2. Anatomy of a Transaction (`Tx`)

```text
┌──────────────────────────────────────────────┐
│  Tx (Unsigned Transfer Instruction)          │
│  From:  a4f9...3c12  (Sender Address)        │
│  To:    81bd...902e  (Recipient Address)     │
│  Value: 10           (uint64 — integer units)│
│  Nonce: 1            (Sender's tx counter)   │
│  Time:  1764159500   (int64 — UnixNano)      │
└──────────────────────────────────────────────┘
```

### Key Design Choices
* **Why `uint64` for `Value` (never `float64`)?** Floating-point numbers introduce rounding errors (`0.1 + 0.2 != 0.3`). Blockchains always use exact integers representing the smallest currency unit.
* **Why `int64` (`UnixNano`) for `Time`?** Every node on the network must compute the **exact same SHA-256 hash** for a transaction. Go's `time.Time` includes timezone metadata that can serialize differently across machines; an `int64` timestamp is 100% deterministic everywhere.
* **Why pass `Tx` by value?** Keeping `Tx` as a small value struct prevents accidental shared-pointer mutation after signing.

---

## 3. Hashing & Two-Rule Verification (`SignedTx`)

To authorize a transaction, the sender hashes `Tx` with **SHA-256** (`crypto.Hash`), signs that 32-byte digest with their **Ed25519 Private Key**, and bundles everything into a `SignedTx`:

```text
SignedTx = { Tx, PubKey, Sig }
```

When any peer receives a `SignedTx`, `Verify()` enforces **both** rules:

```text
Rule 1 — Ownership:   stx.PubKey.Address() == stx.From
                      Proves this public key actually owns the claimed From address.
                      (Stops Mallory from signing a tx with From = Alice using Mallory's own key!)

Rule 2 — Integrity:   stx.PubKey.Verify(stx.Hash().Bytes(), stx.Sig)
                      Proves the matching private key signed these exact Tx fields.
                      (Stops anyone from modifying Value, To, Nonce, or Time in transit!)
```

> **Ed25519 vs. Ethereum ECDSA:** Ethereum's ECDSA signatures allow deriving the sender's public key mathematically from the signature (`ecrecover`). With Ed25519, we explicitly attach `PubKey` to `SignedTx` and check `PubKey.Address() == From` — fast, explicit, and easy to audit.

---

## 4. Replay Attacks & Transaction Nonces

Suppose `Tx` had **no `Nonce`**:
1. Alice genuinely signs: *"Send 10 coins from Alice to Bob"*.
2. The network verifies Alice's signature (**valid!**) and pays Bob 10 coins.
3. Bob copy-pastes that exact same `SignedTx` and broadcasts it 50 more times. The signature is still valid — Alice's wallet gets drained!

### How the `Nonce` Solves It
* Every account maintains a sequential counter (`0, 1, 2, ...`).
* Alice's first transaction must have `Nonce: 1`, her second `Nonce: 2`, and so on.
* Once `Nonce: 1` is executed, the state engine (Lesson 4) rejects any duplicate `Nonce: 1`.
* Because `Nonce` is part of `Tx` and covered by `Tx.Hash()`, Bob cannot edit `Nonce: 1` → `2` without invalidating Alice's signature.

*(Reminder: This sequential **transaction nonce** is completely separate from the random 12-byte **AES-GCM encryption nonce** used in Lesson 1's keystore.)*

---

## 5. Verification & Tests

Run the test suite:

```bash
go test -v ./chain -run Test.*Tx
```

**What `chain/tx_test.go` proves:**
* `TestTxHashDeterministic`: Identical transactions produce identical hashes; modifying `Value` or `Nonce` changes the hash.
* `TestSignAndVerifyTx`: A properly signed transaction passes `Verify()`.
* `TestVerifyTxRejectsTampering`: Mutating `Value`, `To`, `From`, `Nonce`, `Time`, or `PubKey` after signing causes `Verify()` to return `false`.
* `TestSignTxRejectsWrongAccount`: `Account.SignTx` refuses to sign a transaction whose `From` belongs to another account.
* `TestVerifyTxRejectsForgedOwnership`: Even if an attacker bypasses `SignTx` and crafts a `SignedTx` with `From = Alice` signed validly by Mallory's key, **Rule 1** catches and rejects the forgery.
* `TestVerifyTxEdgeCases`: Empty structs or `nil` `PubKey`/`Sig` safely return `false` without panicking.

---

## Next Up

👉 **Lesson 3: Genesis Block, Chaining & Disk Storage (`chain/genesis.go`, `chain/block.go`)** — bundling verified transactions into cryptographically linked blocks (`ParentHash`) and persisting the ledger to disk.
