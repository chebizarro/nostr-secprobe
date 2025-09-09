package nostrx

import (
	"crypto/rand"
	"encoding/hex"

	gonostr "github.com/nbd-wtf/go-nostr"
)

// GenerateKeyPair returns hex-encoded seckey and pubkey.
func GenerateKeyPair() (secHex string, pubHex string, err error) {
	// go-nostr v0.52 provides string helpers
	sk := gonostr.GeneratePrivateKey()
	pk, err := gonostr.GetPublicKey(sk)
	if err != nil { return "", "", err }
	return sk, pk, nil
}

// RandHex returns n random bytes hex-encoded.
func RandHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil { return "", err }
	return hex.EncodeToString(b), nil
}
