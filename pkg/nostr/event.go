package nostrx

import (
	"crypto/sha256"
	"encoding/hex"

	"fiatjaf.com/nostr"
)

// CanonicalID recomputes event id from serialized content per NIP-01.
func CanonicalID(ev *nostr.Event) string {
	ser := ev.Serialize()
	h := sha256.Sum256(ser)
	return hex.EncodeToString(h[:])
}
