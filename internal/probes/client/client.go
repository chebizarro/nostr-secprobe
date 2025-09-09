package client

import (
	"context"
	"time"

	"nostr-secprobe/internal/report"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

type Options struct {
	PreviewHost string
	Active      bool
	IUnderstand bool
	DryRun      bool
}

func Run(ctx context.Context, opt Options) (*report.Results, error) {
	r := &report.Results{TargetType: "client", GeneratedAt: time.Now().UTC()}
	status := report.Inconclusive
	evidence := map[string]any{"note": "Run with --active and --preview-host to set up a unique preview URL and observe fetches in the preview server logs."}

	if opt.Active && opt.PreviewHost != "" && opt.IUnderstand {
		// Create a unique token and a candidate URL for the client to preview.
		tok := make([]byte, 16)
		if _, err := rand.Read(tok); err == nil {
			token := hex.EncodeToString(tok)
			url := fmt.Sprintf("%s/preview?token=%s", opt.PreviewHost, token)
			evidence = map[string]any{
				"preview_url": url,
				"instruction": "Send a message that causes the client to render a preview for the URL. If the client performs receiver-side fetching, the preview server will log an inbound request containing this token.",
				"verify": "Run: nostr-secprobe serve preview-probe --addr :8080 and watch stdout for JSON lines showing the token.",
			}
		}
		// Without live harness integration, we cannot auto-verify; keep inconclusive with actionable evidence.
	}

	r.Add(report.Finding{
		Name: "Receiver-side link preview leakage",
		Category: "Preview-based leakage/oracles",
		Severity: report.High,
		Status: status,
		Evidence: evidence,
		Mitigations: []string{"Disable receiver-side previews or use hardened proxy"},
		Timestamp: time.Now().UTC(),
	})
	return r, nil
}
