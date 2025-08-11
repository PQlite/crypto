package crypto

import (
	"crypto/ed25519"
	"testing"
)

func TestCreate(t *testing.T) {
	pubKey, privKey, err := Create()
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	if pubKey == nil {
		t.Error("Public key is nil")
	}

	if privKey == nil {
		t.Error("Private key is nil")
	}

	if len(pubKey) != ed25519.PublicKeySize {
		t.Errorf("Public key size mismatch. Expected %d, Got %d", ed25519.PublicKeySize, len(pubKey))
	}

	if len(privKey) != ed25519.PrivateKeySize {
		t.Errorf("Private key size mismatch. Expected %d, Got %d", ed25519.PrivateKeySize, len(privKey))
	}
}
