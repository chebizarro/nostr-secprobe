package client

import (
	"context"
	"time"

	"nostr-secprobe/internal/report"
)

type Options struct {
	PreviewHost string
	Active      bool
	IUnderstand bool
	DryRun      bool
}

func Run(ctx context.Context, opt Options) (*report.Results, error) {
	r := &report.Results{TargetType: "client", GeneratedAt: time.Now().UTC()}
	// Stub: In default path, we simulate that no preview fetch occurred.
	r.Add(report.Finding{
		Name: "Receiver-side link preview leakage",
		Category: "Preview-based leakage/oracles",
		Severity: report.High,
		Status: report.Inconclusive,
		Evidence: map[string]any{"note": "Harness not connected; run with --preview-host and your client harness for active checks."},
		Mitigations: []string{"Disable receiver-side previews or use hardened proxy"},
		Timestamp: time.Now().UTC(),
	})
	return r, nil
}
