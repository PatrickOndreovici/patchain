# Lesson 1: Keys, Addresses & Encrypted Accounts

> **Packages built:** `crypto/` ([`keys.go`](../crypto/keys.go), [`keys_test.go`](../crypto/keys_test.go)) and `chain/` ([`account.go`](../chain/account.go), [`account_test.go`](../chain/account_test.go))

This lesson covers the cryptographic foundation of a blockchain: how accounts exist without a central database, how ownership is proven mathematically, and how private keys are safely stored on disk.

---

## 1. Why Start With Keys?

Traditional web apps store accounts in a central database (`email` + `hashed password`). A decentralized blockchain has no central server or user table. Instead, **identity and ownership are pure mathematics**:

* **No sign-up required:** Generating a key pair offline creates a valid blockchain account immediately.
* **No passwords on-chain:** You prove ownership by producing a **digital signature** with your private key that any node on the network can verify using your public key.
* **Everything else builds on this:** You cannot create Transactions without Signatures, Blocks without Transactions, or a Blockchain without Blocks.

---

## 2. The One-Way Identity Pipeline

Every account in this blockchain is derived through a **one-way cryptographic chain** starting from a single 32-byte random secret:

```text
1. SEED (32 random bytes from OS CSPRNG)    ◄── Master secret (all you need to back up)
       │
       │  ed25519.NewKeyFromSeed(seed)
       ▼
2. PRIVATE KEY (64 bytes = Seed + PubKey)   ◄── Kept secret; used to SIGN messages/txs
       │
       │  p.key[32:]  (last 32 bytes)
       ▼
3. PUBLIC KEY (32 bytes)                    ◄── Shared publicly; used to VERIFY signatures
       │
       │  SHA-256(pubKey) → last 20 bytes
       ▼
4. ADDRESS (20 bytes / 40 hex chars)        ◄── Public account ID (like a bank IBAN)
```

**Why "one-way" matters:**
* Knowing **#1 (Seed)** lets you deterministically regenerate **#2, #3, and #4** on any machine.
* Knowing **#4 (Address)** or **#3 (Public Key)** makes it computationally impossible to work backward to find **#2** or **#1**.

---

## 3. The 4 Cryptographic Primitives We Used

| Algorithm | Category | Input → Output | Role in Our Blockchain |
| :--- | :--- | :--- | :--- |
| **Ed25519** | Asymmetric Digital Signatures (2 keys) | `(PrivateKey, msg)` → `64B Signature`<br>`(PublicKey, msg, sig)` → `bool` | Account key pairs, signing & verifying transactions and blocks. |
| **SHA-256** | Cryptographic Hash (one-way) | `any bytes` → `32B digest` | Deriving Addresses from Public Keys *(later: Tx hashes, Block `ParentHash`, Merkle Trees)*. |
| **Argon2id** | Password KDF (Key Derivation) | `(password, 32B salt)` → `32B AES key` | Turns a human password into a strong, brute-force-resistant AES-256 key. |
| **AES-256-GCM** | Authenticated Symmetric Encryption (1 key) | `(32B key, 12B nonce, seed)` → `ciphertext` | Encrypts the 32-byte Seed for safe disk storage & detects wrong passwords or file tampering. |

---

## 4. Deep Dive: How Each Algorithm Works

### 4.1 Ed25519 (Digital Signatures)

**Ed25519** is a modern Edwards-curve signature algorithm (EdDSA) used by Solana, Cosmos/Tendermint, Polkadot, and NEAR. It is fast, produces compact keys/signatures, and avoids several classic pitfalls of older ECDSA implementations.

#### Secure Randomness (`crypto/rand`)
Keys must be generated using a **CSPRNG** (`crypto/rand.Reader`, backed by OS kernel entropy) — *never* `math/rand`, which is predictable and would allow attackers to guess private keys.

#### Go's 64-Byte `ed25519.PrivateKey` Layout
Computing the public key from a seed requires elliptic-curve multiplication. To avoid recomputing it repeatedly, Go precomputes the public key once and appends it to the seed:

```text
┌──────────────────────────────┬──────────────────────────────┐
│         Bytes 0..31          │         Bytes 32..63         │
│          (32 bytes)          │          (32 bytes)          │
├──────────────────────────────┼──────────────────────────────┤
│         SECRET SEED          │          PUBLIC KEY          │
│         p.key[:32]           │          p.key[32:]          │
└──────────────────────────────┴──────────────────────────────┘
```

#### Signing ≠ Encrypting
Calling `privKey.Sign(msg)` does **not** hide `msg` — the message remains readable. Instead, it outputs a 64-byte mathematical proof (`Signature`) guaranteeing two properties when checked via `pubKey.Verify(msg, sig)`:
1. **Authenticity:** Only the holder of the matching private key could have created this signature.
2. **Integrity:** Changing even **1 single bit** of the message or signature causes `Verify` to return `false`.

#### Defensive Go Security Patterns Applied
* **Defensive copying:** `PrivateKey.PublicKey()` and `PrivateKey.Seed()` allocate new byte slices and use `copy(...)` so mutating a returned slice can never corrupt the underlying private key.
* **No panics on untrusted input:** `PublicKey.Verify` guards against `nil` pointers and invalid key/signature lengths (since Go's `ed25519.Verify` panics on bad public key lengths), preventing a malformed network message from crashing a node.

---

### 4.2 SHA-256 & Address Derivation

**SHA-256** (*Secure Hash Algorithm 256-bit*) maps arbitrary data to a fixed **32-byte fingerprint** with 4 critical properties:
1. **Fixed length:** Always 32 bytes regardless of input size.
2. **Deterministic:** Same input always produces the exact same output.
3. **Avalanche effect:** Flipping 1 bit in the input completely scrambles the output.
4. **One-way & collision-resistant:** Cannot be reversed; finding two inputs with the same hash is infeasible ($2^{256}$ space).

#### Why Hash the Public Key Into an `Address`?
In [`crypto/keys.go`](../crypto/keys.go), `PublicKey.Address()` computes `sha256.Sum256(p.key)` and takes the **last 20 bytes** (40 hex characters):
* **Compact & uniformly random:** Every bit of a SHA-256 digest is uniformly distributed, making truncation to 20 bytes safe.
* **Extra defense layer:** While an account only receives coins, its raw public key stays hidden behind a one-way hash until it sends its first outgoing transaction.
* **Algorithm-independent:** Addresses are always 20 bytes regardless of public key size.

#### Why `type Address [20]byte` Instead of `[]byte`?
In Go, slices (`[]byte`) are **not comparable** — they cannot be compared with `==` or used as map keys. Using a fixed-size array `type Address [20]byte` guarantees exact length at compile time and allows direct `addr1 == addr2` comparisons and `map[Address]uint64` balance tables (the same idiom used by `go-ethereum`).

---

### 4.3 Encrypted Account Keystores (Argon2id + AES-256-GCM)

Keys generated in RAM disappear when a program exits. Saving a raw seed to disk in plain text is unsafe, so [`chain/account.go`](../chain/account.go) persists accounts in an encrypted JSON keystore (`<address>.json`), locked with a user passphrase.

#### Why We Only Need to Encrypt the 32-Byte Seed
Because `ed25519.NewKeyFromSeed(seed)` deterministically rebuilds the full 64-byte private key, 32-byte public key, and 20-byte address, the **32-byte seed** is the only secret that ever needs to be persisted.

> **Real-world connection:** Hardware and browser wallets (like MetaMask or Ledger) represent this exact same secret seed in two ways:
> * **On paper (for humans):** 12 or 24 English words (BIP-39 seed phrase) that encode the seed bytes.
> * **On disk (for computers):** An encrypted JSON keystore locked with your password — the exact mechanism implemented here.

#### How Saving (`Account.Write`) & Loading (`ReadAccount`) Work

```text
SAVING (Write):
  Password + Random Salt (32B) ──► Argon2id ──► Strong AES-256 Key (32B)
                                                       │
  PrivateKey Seed (32B) + Random Nonce (12B) ──────────┴──► AES-GCM Seal ──► Ciphertext

  Saved to <address>.json (0600 permissions):
  { "salt": "...", "nonce": "...", "ciphertext": "..." }
  (Password and raw Seed are NEVER written to disk!)

LOADING (ReadAccount):
  Password + Saved Salt ──► Argon2id ──► Same AES-256 Key (32B)
                                                │
  Saved Ciphertext + Saved Nonce ───────────────┴──► AES-GCM Open ──► Seed (32B) ──► PrivateKey!
```

#### Why Each Ingredient Exists
1. **Argon2id (Key Derivation Function — NOT encryption):**
   * AES-256 strictly requires a strong 32-byte key; you cannot pass a short human password directly into AES.
   * Argon2id stretches `(password, salt)` using deliberate CPU + memory cost (`64 MiB`), making brute-force guessing painfully slow.
2. **Random `Salt` (32 bytes, stored openly in JSON):**
   * Not secret! Stored so `ReadAccount` can reproduce the exact same AES key tomorrow.
   * Ensures two accounts with identical passwords still produce completely different AES keys and ciphertexts.
3. **Random `Nonce` (12 bytes, stored openly in JSON):**
   * Not secret! Required by AES-GCM so encrypting the same data twice with the same key yields different ciphertexts.
   * *Note:* This AES encryption nonce is completely separate from the per-account transaction nonce introduced in Lesson 2.
4. **AES-256-GCM (Authenticated Encryption):**
   * Encrypts the 32-byte seed **and** attaches an authentication tag.
   * If a user enters the **wrong password** or flips even **1 bit** of the saved `ciphertext` or `salt`, `gcm.Open(...)` automatically rejects it with an authentication error instead of silently returning garbage bytes.

---

## 5. Verification & Tests

Run the full Lesson 1 test suite:

```bash
go test -v ./crypto ./chain
```

**What the tests prove:**
* `crypto/keys_test.go`: Key lengths, uniqueness, seed round-trip (`Seed` ↔ `PrivateKeyFromSeed`), defensive copy isolation, deterministic 20-byte hex `Address` & map-key usage, valid signatures, rejection of tampered messages/signatures/wrong keys, and panic-free handling of `nil`/malformed inputs.
* `chain/account_test.go`: Encrypted file creation (verifying neither password nor raw seed appears in plain text), write → reload round-trip with working signatures, rejection of wrong passwords, rejection of tampered ciphertext/salt, and safe handling of missing files, invalid JSON, and bad nonce lengths.

---

## Next Up

👉 **Lesson 2: Transactions, Nonces & Replay Protection (`chain/tx.go`)** — using our `Account`, `Address`, `PublicKey`, and `Signature` to build signed value transfers that cannot be forged or replayed.
