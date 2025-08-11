package crypto

import (
	"crypto/ed25519"
	"fmt"
)

// TODO: зробити перевірку ключа, і повертати помилку, в разі проблем

func Sign(priv []byte, message []byte) ([]byte, error) {
	return ed25519.Sign(priv, message), nil
}

func Verify(pub []byte, message []byte, sig []byte) error {
	res := ed25519.Verify(pub, message, sig)
	if !res {
		return fmt.Errorf("not valid signature")
	}
	return nil
}
