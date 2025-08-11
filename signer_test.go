package crypto

import (
	"testing"
)

func TestSignVerify(t *testing.T) {
	pubKey, privKey, err := Create()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	message := []byte("This is a test message.")

	signature, err := Sign(privKey, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if signature == nil || len(signature) == 0 {
		t.Error("Signature is empty or nil")
	}

	valid, err := Verify(pubKey, message, signature)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !valid {
		t.Error("Signature is not valid")
	}

	// Test with a different message
	differentMessage := []byte("This is a different message.")
	valid, err = Verify(pubKey, differentMessage, signature)
	if err != nil {
		t.Fatalf("Verify failed with different message: %v", err)
	}

	if valid {
		t.Error("Signature should not be valid for a different message")
	}

	// Test with a corrupted signature
	corruptedSignature := make([]byte, len(signature))
	copy(corruptedSignature, signature)
	corruptedSignature[0] ^= 0x01 // Corrupt one byte

	valid, err = Verify(pubKey, message, corruptedSignature)
	if err != nil {
		t.Fatalf("Verify failed with corrupted signature: %v", err)
	}

	if valid {
		t.Error("Corrupted signature should not be valid")
	}

	// Test with wrong public key
	wrongPubKey, _, err := Create()
	if err != nil {
		t.Fatalf("Failed to generate wrong keys: %v", err)
	}

	valid, err = Verify(wrongPubKey, message, signature)
	if err != nil {
		t.Fatalf("Verify failed with wrong public key: %v", err)
	}

	if valid {
		t.Error("Signature should not be valid with wrong public key")
	}
}
