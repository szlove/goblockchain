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
