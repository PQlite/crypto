package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		password string
		expectErr bool
	}{
		{
			name:     "Valid encryption and decryption",
			data:     []byte("Hello, world!"),
			password: "testpassword",
			expectErr: false,
		},
		{
			name:     "Empty data",
			data:     []byte(""),
			password: "testpassword",
			expectErr: false,
		},
		{
			name:     "Long data",
			data:     bytes.Repeat([]byte("a"), 1024),
			password: "testpassword",
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encryptedData, err := Encrypt(tc.data, tc.password)
			if err != nil {
				if !tc.expectErr {
					t.Fatalf("Encrypt failed: %v", err)
				}
				return
			}

			decryptedData, err := Decrypt(encryptedData, tc.password)
			if err != nil {
				if !tc.expectErr {
					t.Fatalf("Decrypt failed: %v", err)
				}
				return
			}

			if !bytes.Equal(tc.data, decryptedData) {
				t.Errorf("Decrypted data does not match original data. Expected: %s, Got: %s", tc.data, decryptedData)
			}
		})
	}
}

func TestDecryptWithWrongPassword(t *testing.T) {
	data := []byte("Hello, world!")
	password := "correctpassword"
	wrongPassword := "wrongpassword"

	encryptedData, err := Encrypt(data, password)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(encryptedData, wrongPassword)
	if err == nil {
		t.Error("Decrypt with wrong password did not return an error")
	}
}

func TestDecryptWithCorruptedData(t *testing.T) {
	data := []byte("Hello, world!")
	password := "testpassword"

	encryptedData, err := Encrypt(data, password)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Corrupt the ciphertext
	corruptedData := make([]byte, len(encryptedData))
	copy(corruptedData, encryptedData)
	corruptedData[len(corruptedData)/2] ^= 0x01 // Flip a bit

	_, err = Decrypt(corruptedData, password)
	if err == nil {
		t.Error("Decrypt with corrupted data did not return an error")
	}
}

func TestDecryptTooShort(t *testing.T) {
	_, err := Decrypt([]byte("short"), "password")
	if err == nil {
		t.Error("Decrypt with too short data did not return an error")
	}
}
