package crypto

import (
	"encoding/hex"
	"encoding/json"
	"log"

	"github.com/cloudflare/circl/sign"
	"golang.org/x/crypto/sha3"
)

// Sign підписує транзакцію і повертаю повноцінну Transaction з підписом і pubkey
func Sign(unsignTransaction UnsignTransaction, priv sign.PrivateKey, pub sign.PublicKey) (Transaction, error) {
	// TODO: SerializeTransaction
	rawData, err := json.Marshal(unsignTransaction)
	if err != nil {
		log.Println("помилка json.Marshal: ", err)
		return Transaction{}, err
	}

	rawDataHash := sha3.Sum224(rawData)

	sig := scheme.Sign(priv, rawDataHash[:], nil)
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		log.Println("помилка pub.MarshalBinary: ", err)
		return Transaction{}, err
	}

	return Transaction{
		From: unsignTransaction.From,
		To:   unsignTransaction.To, Amount: unsignTransaction.Amount,
		Timestamp: unsignTransaction.Timestamp,
		Nonce:     unsignTransaction.Nonce,
		Signature: sig,
		PubKey:    pubBytes,
	}, nil
}

// Verify робить перевірку підпису транзакції і власника гаманця з поля From
func Verify(transaction Transaction) bool {
	pubKey, err := scheme.UnmarshalBinaryPublicKey(transaction.PubKey)
	if err != nil {
		log.Println("помилка UnmarshalBinaryPublicKey: ", err)
		return false
	}

	unsignTransaction := transaction.GetUnsignTransaction()
	rawData, err := json.Marshal(unsignTransaction)
	if err != nil {
		log.Println("помилка json.Marshal: ", err)
		return false
	}

	rawDataHash := sha3.Sum224(rawData)

	// check that 'from' belongs to the transaction creator
	pubKeySum := sha3.Sum224(transaction.PubKey)
	if hex.EncodeToString(pubKeySum[:]) != transaction.From {
		return false
	}

	return scheme.Verify(pubKey, rawDataHash[:], transaction.Signature, nil)
}
