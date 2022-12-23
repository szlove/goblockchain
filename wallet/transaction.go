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
