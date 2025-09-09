package connect

import (
	"context"
	"time"

	"nostr-secprobe/internal/report"
)

type Options struct {
	DryRun bool
	Active bool
	IUnderstand bool
}

func Run(ctx context.Context, opt Options) (*report.Results, error) {
	r := &report.Results{TargetType: "connect", GeneratedAt: time.Now().UTC()}
	r.Add(report.Finding{
		Name: "Cross-protocol key reuse (NIP-04 vs NIP-46)",
		Category: "Cross-protocol key reuse",
		Severity: report.High,
		Status: report.Inconclusive,
		Evidence: map[string]any{"note": "Stub harness; run active test to compare KDF domain separation."},
		Mitigations: []string{"Use HKDF with distinct info labels (e.g., 'NIP04' vs 'NIP46')"},
		Timestamp: time.Now().UTC(),
	})
	return r, nil
}
