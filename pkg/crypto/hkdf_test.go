package crypto

import (
	"bytes"
	"testing"
)

func TestKDFDomainSeparation(t *testing.T) {
	in := []byte("secret")
	salt := []byte("salt")
	a := KDF(in, salt, []byte("NIP04"), 32)
	b := KDF(in, salt, []byte("NIP46"), 32)
	if bytes.Equal(a, b) { t.Fatal("expected different outputs for different info labels") }
}
