package crypto

import (
	"crypto/ed25519"
	"fmt"
)

// TODO: зробити перевірку ключа, і повертати помилку, в разі проблем

func Sign(priv []byte, message []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("помилка розміру приватного ключа, треба: %d, отримано: %d", ed25519.PrivateKeySize, len(priv))
	}
	return ed25519.Sign(priv, message), nil
}

func Verify(pub []byte, message []byte, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("помилка розміру публічного ключа, треба: %d, отримано: %d", ed25519.PublicKeySize, len(pub))
	}
	res := ed25519.Verify(pub, message, sig)
	if !res {
		return fmt.Errorf("not valid signature")
	}
	return nil
}
