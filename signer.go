package crypto

import "crypto/ed25519"

func Sign(priv []byte, message []byte) ([]byte, error) {
	return ed25519.Sign(priv, message), nil
}

func Verify(pub []byte, message []byte, sig []byte) (bool, error) {
	return ed25519.Verify(pub, message, sig), nil
}
