package relay

import "testing"

func TestChoose(t *testing.T) {
	if choose(true, 1, 2) != 1 { t.Fatal("expected 1") }
	if choose(false, 1, 2) != 2 { t.Fatal("expected 2") }
}
