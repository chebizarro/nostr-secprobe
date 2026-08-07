package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HKDF like KDF with explicit salt and info to emphasize domain separation.
func KDF(input, salt, info []byte, outLen int) []byte {
	prk := hmac.New(sha256.New, salt)
	prk.Write(input)
	prkSum := prk.Sum(nil)
	var out []byte
	var prev []byte
	var ctr byte = 1
	for len(out) < outLen {
		h := hmac.New(sha256.New, prkSum)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{ctr})
		prev = h.Sum(nil)
		out = append(out, prev...)
		ctr++
	}
	return out[:outLen]
}
