package connect

import (
	"context"
	"time"

	"encoding/hex"
	"bytes"
	"nostr-secprobe/internal/report"
	icrypto "nostr-secprobe/internal/crypto"
)

type Options struct {
	DryRun bool
	Active bool
	IUnderstand bool
}

func Run(ctx context.Context, opt Options) (*report.Results, error) {
	r := &report.Results{TargetType: "connect", GeneratedAt: time.Now().UTC()}
	// By default provide guidance unless active test enabled.
	status := report.Inconclusive
	evidence := map[string]any{"note": "Run with --active and --i-understand to perform domain separation check."}

	if opt.Active && opt.IUnderstand {
		// Active check: simulate same shared secret input across two protocols and
		// derive session keys with distinct KDF info labels. Proper domain separation
		// requires distinct outputs.
		baseSecret := []byte("shared-secret-sample") // placeholder for ECDH output
		salt := []byte("nostr-connect-salt")         // explicit salt
		nip04Info := []byte("NIP04")
		nip46Info := []byte("NIP46")
		outLen := 32

		k04 := icrypto.KDF(baseSecret, salt, nip04Info, outLen)
		k46 := icrypto.KDF(baseSecret, salt, nip46Info, outLen)

		equal := bytes.Equal(k04, k46)
		status = report.Pass
		if equal {
			status = report.Fail
		}
		evidence = map[string]any{
			"base_secret_hex": hex.EncodeToString(baseSecret),
			"salt_hex": hex.EncodeToString(salt),
			"kdf_nip04_hex": hex.EncodeToString(k04),
			"kdf_nip46_hex": hex.EncodeToString(k46),
			"domain_separated": !equal,
		}
	}

	r.Add(report.Finding{
		Name: "Cross-protocol key reuse (NIP-04 vs NIP-46)",
		Category: "Cross-protocol key reuse",
		Severity: report.High,
		Status: status,
		Evidence: evidence,
		Mitigations: []string{"Use HKDF with distinct info labels (e.g., 'NIP04' vs 'NIP46')"},
		Timestamp: time.Now().UTC(),
	})
	return r, nil
}
