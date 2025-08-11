// Package crypto відповідає за створення та використання ключів
package crypto

import (
	"crypto/ed25519"
)

func Create() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}
