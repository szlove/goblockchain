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
