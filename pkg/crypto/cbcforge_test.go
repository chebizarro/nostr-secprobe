package crypto

import "testing"

func TestTweakIV(t *testing.T) {
	iv := []byte{0x00,0x01,0x02}
	x := []byte{0xff,0x00,0x01}
	out := TweakIV(iv, x)
	if out[0] != 0xff || out[1] != 0x01 || out[2] != 0x03 { t.Fatalf("unexpected: %v", out) }
}
