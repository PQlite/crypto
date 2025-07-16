package crypto

import (
	"log"
)

func Sign(binPriv []byte, message []byte) ([]byte, error) {
	priv, err := scheme.UnmarshalBinaryPrivateKey(binPriv)
	if err != nil {
		log.Println("помилка отримання priv: ", err)
		return []byte(""), err
	}
	return scheme.Sign(priv, message, nil), nil
}

func Verify(binPub []byte, message []byte, sig []byte) bool {
	pub, err := scheme.UnmarshalBinaryPublicKey(binPub)
	if err != nil {
		log.Println("помилка UnmarshalBinaryPublicKey: ", err)
		return false
	}

	return scheme.Verify(pub, message, sig, nil)
}
