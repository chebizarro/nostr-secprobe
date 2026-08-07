package crypto

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptXChaCha20Poly1305 provides a sample AEAD good path for test fixtures.
func EncryptXChaCha20Poly1305(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil { return nil, nil, err }
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	if _, err = rand.Read(nonce); err != nil { return nil, nil, err }
	ct := aead.Seal(nil, nonce, plaintext, aad)
	return nonce, ct, nil
}

func DecryptXChaCha20Poly1305(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil { return nil, err }
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil { return nil, errors.New("decryption failed") }
	return pt, nil
}
