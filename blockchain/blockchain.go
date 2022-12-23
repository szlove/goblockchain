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
