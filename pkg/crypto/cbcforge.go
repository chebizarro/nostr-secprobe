package crypto

// CBC tweak utilities for 1-block controlled modifications.
// For CBC, plaintext[i] = Dec(C[i]) XOR C[i-1]. To flip bits in first block, tweak IV.

// TweakIV applies a XOR mask to the IV to induce the same XOR in the first plaintext block.
func TweakIV(iv []byte, xorMask []byte) []byte {
	out := make([]byte, len(iv))
	for i := range iv {
		m := byte(0)
		if i < len(xorMask) { m = xorMask[i] }
		out[i] = iv[i] ^ m
	}
	return out
}
