# goblockchain

🧊 고언어로 작성하는 블록체인 코어 핵심 API 

- Blockchain address generation
- Wallet
- Wallet transaction
- ECDSA sign
- Blockchain
- Blockchain Transaction
- ECDSA verify
- Blockchain Mining

## main.go
```go
package main

import (
	"fmt"
	"log"

	"github.com/szlove/goblockchain/blockchain"
	"github.com/szlove/goblockchain/wallet"
)

func init() {
	log.SetPrefix("Blockchain: ")
}

func LogIfError(err error) {
	if err != nil {
		log.Println(err)
	}
}

func main() {
	// create wallets
	walletM := wallet.NewWallet()
	walletA := wallet.NewWallet()
	walletB := wallet.NewWallet()

	// wallet transactions
	tx1 := wallet.NewTransaction(&wallet.NewTransactionParams{
		SenderBlockchainAddress:    walletA.BlockchainAddress(),
		RecipientBlockchainAddress: walletB.BlockchainAddress(),
		Value:                      1.0,
		SenderPrivateKey:           walletA.PrivateKey(),
		SenderPublicKey:            walletA.PublicKey(),
	})
	tx2 := wallet.NewTransaction(&wallet.NewTransactionParams{
		SenderBlockchainAddress:    walletB.BlockchainAddress(),
		RecipientBlockchainAddress: walletM.BlockchainAddress(),
		Value:                      0.5,
		SenderPrivateKey:           walletB.PrivateKey(),
		SenderPublicKey:            walletB.PublicKey(),
	})

	// create blockchain
	bc := blockchain.NewBlockchain(walletM.BlockchainAddress())
	fmt.Printf("Blockchain Address: %s\n\n", bc.Address())

	// blockchain transactions
	err := bc.AddTransaction(&blockchain.AddTransactionParams{
		SenderBlockchainAddress:    walletA.BlockchainAddress(),
		RecipientBlockchainAddress: walletB.BlockchainAddress(),
		Value:                      1.0,
		SenderPublicKey:            walletA.PublicKey(),
		Signature:                  tx1.Sign(),
	})
	LogIfError(err)
	err = bc.AddTransaction(&blockchain.AddTransactionParams{
		SenderBlockchainAddress:    walletB.BlockchainAddress(),
		RecipientBlockchainAddress: walletM.BlockchainAddress(),
		Value:                      0.5,
		SenderPublicKey:            walletB.PublicKey(),
		Signature:                  tx2.Sign(),
	})
	LogIfError(err)
	log.Printf("transaction_pool    %+v\n", bc.TransactionPool()) // [0x.., 0x..]
	log.Printf("chain               %+v\n", bc.Chain())           // [0x..] genesis block only

	// blockchain mining
	log.Println("mining.. ⛏️")
	if err := bc.Mining(); err != nil {
		log.Println(err)
	}
	log.Printf("transaction_pool    %+v\n", bc.TransactionPool()) // []
	log.Printf("chain               %+v\n", bc.Chain())           // [0x.., 0x..] new block created
}
```

## util/ecdsa.go
```go
package util

import "math/big"

type Signature struct {
	R *big.Int
	S *big.Int
}
```

## wallet/wallet.go
```go
package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

type Wallet struct {
	blockchainAddress string
	privateKey        *ecdsa.PrivateKey
	publicKey         *ecdsa.PublicKey
}

func (w *Wallet) BlockchainAddress() string     { return w.blockchainAddress }
func (w *Wallet) PrivateKey() *ecdsa.PrivateKey { return w.privateKey }
func (w *Wallet) PublicKey() *ecdsa.PublicKey   { return w.publicKey }

func NewWallet() *Wallet {
	// Technical background of version 1 Bitcoin address
	// wiki - https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses

	// 0 - Having a private ECDSA key
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// 1 - Take the corresponding public key generated with it (33 bytes, 1 byte 0x02 (y-coord is even), and 32 bytes corresponding to X coordinate)
	publicKey := &privateKey.PublicKey
	comb1 := make([]byte, 65)
	comb1[0] = 0x02
	copy(comb1[1:33], publicKey.X.Bytes())
	copy(comb1[33:65], publicKey.Y.Bytes())
	// 2 - Perform SHA-256 hashing on the public key
	hash2 := sha256.New()
	hash2.Write(comb1)
	digest2 := hash2.Sum(nil)
	// 3 - Perform RIPEMD-160 hashing on the result of SHA-256
	hash3 := ripemd160.New()
	hash3.Write(digest2)
	digest3 := hash3.Sum(nil)
	// 4 - Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
	v4 := make([]byte, 21)
	v4[0] = 0x00
	copy(v4[1:21], digest3)
	// 5 - Perform SHA-256 hash on the extended RIPEMD-160 result
	hash5 := sha256.New()
	hash5.Write(v4)
	digest5 := hash5.Sum(nil)
	// 6 - Perform SHA-256 hash on the result of the previous SHA-256 hash
	hash6 := sha256.New()
	hash6.Write(digest5)
	digest6 := hash6.Sum(nil)
	// 7 - Take the first 4 bytes of the second SHA-256 hash. This is the address checksum
	checksum := digest6[:4]
	// 8 - Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.
	comb8 := make([]byte, 25)
	copy(comb8[:21], v4)
	copy(comb8[21:25], checksum)
	// 9 - Convert the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format
	blockchainAddress := base58.Encode(comb8)
	return &Wallet{
		blockchainAddress: blockchainAddress,
		privateKey:        privateKey,
		publicKey:         publicKey,
	}
}
```

## wallet/transaction.go
```go
package wallet

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"

	"github.com/szlove/goblockchain/util"
)

type Transaction struct {
	senderBlockchainAddress    string
	recipientBlockchainAddress string
	value                      float64
	senderPrivateKey           *ecdsa.PrivateKey
	senderPublicKey            *ecdsa.PublicKey
}

func (tx *Transaction) SenderBlockchainAddress() string    { return tx.senderBlockchainAddress }
func (tx *Transaction) RecipientBlockchainAddress() string { return tx.recipientBlockchainAddress }
func (tx *Transaction) Value() float64                     { return tx.value }

func (tx *Transaction) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SenderBlockchainAddress    string  `json:"sender_blockchain_address"`
		RecipientBlockchainAddress string  `json:"recipient_blockchain_address"`
		Value                      float64 `json:"value"`
	}{
		SenderBlockchainAddress:    tx.senderBlockchainAddress,
		RecipientBlockchainAddress: tx.recipientBlockchainAddress,
		Value:                      tx.value,
	})
}

type NewTransactionParams struct {
	SenderBlockchainAddress    string
	RecipientBlockchainAddress string
	Value                      float64
	SenderPrivateKey           *ecdsa.PrivateKey
	SenderPublicKey            *ecdsa.PublicKey
}

func NewTransaction(arg *NewTransactionParams) *Transaction {
	return &Transaction{
		senderBlockchainAddress:    arg.SenderBlockchainAddress,
		recipientBlockchainAddress: arg.RecipientBlockchainAddress,
		value:                      arg.Value,
		senderPrivateKey:           arg.SenderPrivateKey,
		senderPublicKey:            arg.SenderPublicKey,
	}
}

func (tx *Transaction) Sign() *util.Signature {
	txBytes, _ := json.Marshal(tx)
	hash := sha256.Sum256(txBytes)
	r, s, _ := ecdsa.Sign(rand.Reader, tx.senderPrivateKey, hash[:])
	return &util.Signature{R: r, S: s}
}
```

## blockchain/blockchain.go
```go
package blockchain

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/szlove/goblockchain/util"
)

const (
	MINING_DIFFICULTY int     = 5
	MINING_SENDER     string  = "THE BLOCKCHAIN"
	MINING_REWARD     float64 = 1.0
)

type Blockchain struct {
	address         string
	transactionPool []*Transaction
	chain           []*Block
}

func (bc *Blockchain) Address() string                 { return bc.address }
func (bc *Blockchain) TransactionPool() []*Transaction { return bc.transactionPool }
func (bc *Blockchain) Chain() []*Block                 { return bc.chain }

func NewBlockchain(blockchainAddress string) *Blockchain {
	bc := &Blockchain{}
	bc.address = blockchainAddress
	bc.transactionPool = []*Transaction{}
	bc.chain = []*Block{}
	genesisBlock := &Block{}
	bc.createBlock(genesisBlock.Hash(), 0)
	return bc
}

func (bc *Blockchain) createBlock(previousHash [32]byte, nonce int) {
	b := NewBlock(previousHash, nonce, bc.transactionPool)
	bc.chain = append(bc.chain, b)
	bc.transactionPool = []*Transaction{}
}

func (bc *Blockchain) verifyTransaction(tx *Transaction, senderPublicKey *ecdsa.PublicKey, sign *util.Signature) error {
	txBytes, _ := json.Marshal(tx)
	hash := sha256.Sum256(txBytes)
	if !ecdsa.Verify(senderPublicKey, hash[:], sign.R, sign.S) {
		return fmt.Errorf("verification failed: transaction: %+v", tx)
	}
	return nil
}

type AddTransactionParams struct {
	SenderBlockchainAddress    string
	RecipientBlockchainAddress string
	Value                      float64
	SenderPublicKey            *ecdsa.PublicKey
	Signature                  *util.Signature
}

func (bc *Blockchain) AddTransaction(arg *AddTransactionParams) error {
	tx := NewTransaction(arg.SenderBlockchainAddress, arg.RecipientBlockchainAddress, arg.Value)
	if arg.SenderBlockchainAddress == MINING_SENDER {
		bc.transactionPool = append(bc.transactionPool, tx)
		return nil
	}
	if err := bc.verifyTransaction(tx, arg.SenderPublicKey, arg.Signature); err != nil {
		return err
	}
	bc.transactionPool = append(bc.transactionPool, tx)
	return nil
}

func (bc *Blockchain) lastBlock() *Block { return bc.chain[len(bc.chain)-1] }

func (bc *Blockchain) copyTransactionPool() []*Transaction {
	transactions := []*Transaction{}
	for _, tx := range transactions {
		transactions = append(transactions,
			NewTransaction(tx.senderBlockchainAddress, tx.recipientBlockchainAddress, tx.value))
	}
	return transactions
}

func (bc *Blockchain) validProof(previousHash [32]byte, nonce int, transactions []*Transaction) (ok bool) {
	guessBlock := &Block{
		previousHash: previousHash,
		nonce:        nonce,
		transactions: transactions,
	}
	hashString := fmt.Sprintf("%x", guessBlock.Hash())
	return hashString[:MINING_DIFFICULTY] == strings.Repeat("0", MINING_DIFFICULTY)
}

func (bc *Blockchain) proofOfWork(previousHash [32]byte) (nonce int) {
	nonce = 0
	transactions := bc.copyTransactionPool()
	for !bc.validProof(previousHash, nonce, transactions) {
		nonce++
	}
	return nonce
}

func (bc *Blockchain) Mining() error {
	bc.AddTransaction(&AddTransactionParams{
		SenderBlockchainAddress:    MINING_SENDER,
		RecipientBlockchainAddress: bc.address,
		Value:                      MINING_REWARD,
	})
	previousHash := bc.lastBlock().Hash()
	nonce := bc.proofOfWork(previousHash)
	bc.createBlock(previousHash, nonce)
	return nil
}
```

## blockchain/block.go
```go
package blockchain

import (
	"crypto/sha256"
	"encoding/json"
	"time"
)

type Block struct {
	timestamp    int64
	previousHash [32]byte
	nonce        int
	transactions []*Transaction
}

func (b *Block) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Timestamp    int64          `json:"timestamp"`
		PreviousHash [32]byte       `json:"previous_hash"`
		Nonce        int            `json:"nonce"`
		Transactions []*Transaction `json:"transactions"`
	}{
		Timestamp:    b.timestamp,
		PreviousHash: b.previousHash,
		Nonce:        b.nonce,
		Transactions: b.transactions,
	})
}

func NewBlock(previousHash [32]byte, nonce int, transactions []*Transaction) *Block {
	return &Block{
		timestamp:    time.Now().UnixNano(),
		previousHash: previousHash,
		nonce:        nonce,
		transactions: transactions,
	}
}

func (b *Block) Hash() [32]byte {
	blockBytes, _ := json.Marshal(b)
	return sha256.Sum256(blockBytes)
}
```

## blockchain/transaction.go
```go
package blockchain

import "encoding/json"

type Transaction struct {
	senderBlockchainAddress    string
	recipientBlockchainAddress string
	value                      float64
}

func (tx *Transaction) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SenderBlockchainAddress    string  `json:"sender_blockchain_address"`
		RecipientBlockchainAddress string  `json:"recipient_blockchain_address"`
		Value                      float64 `json:"value"`
	}{
		SenderBlockchainAddress:    tx.senderBlockchainAddress,
		RecipientBlockchainAddress: tx.recipientBlockchainAddress,
		Value:                      tx.value,
	})
}

func NewTransaction(sender, recipient string, value float64) *Transaction {
	return &Transaction{
		senderBlockchainAddress:    sender,
		recipientBlockchainAddress: recipient,
		value:                      value,
	}
}
```
