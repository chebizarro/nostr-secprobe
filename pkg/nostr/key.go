package nostrx

import (
	"crypto/rand"
	"encoding/hex"

	"fiatjaf.com/nostr"
)

// GenerateKeyPair returns hex-encoded seckey and pubkey.
func GenerateKeyPair() (secHex string, pubHex string, err error) {
	// fiatjaf.com/nostr provides Generate() and GetPublicKey()
	sk := nostr.Generate()
	pk := nostr.GetPublicKey(sk)
	return sk.Hex(), pk.Hex(), nil
}

// RandHex returns n random bytes hex-encoded.
func RandHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil { return "", err }
	return hex.EncodeToString(b), nil
}
