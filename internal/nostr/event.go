package nostrx

import (
	"crypto/sha256"
	"encoding/hex"

	gonostr "github.com/nbd-wtf/go-nostr"
)

// CanonicalID recomputes event id from serialized content per NIP-01.
func CanonicalID(ev *gonostr.Event) string {
	ser := ev.Serialize()
	h := sha256.Sum256(ser)
	return hex.EncodeToString(h[:])
}
