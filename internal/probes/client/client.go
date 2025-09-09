package client

import (
	"context"
	"time"

	"nostr-secprobe/internal/report"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"io"
	"encoding/json"
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
	activeFlag := false

	if opt.Active && opt.PreviewHost != "" && opt.IUnderstand {
		// Create a unique token and a candidate URL for the client to preview.
		tok := make([]byte, 16)
		if _, err := rand.Read(tok); err == nil {
			token := hex.EncodeToString(tok)
			url := fmt.Sprintf("%s/preview?token=%s", opt.PreviewHost, token)
			activeFlag = true
			// Default evidence
			ev := map[string]any{
				"preview_url": url,
				"token": token,
				"instruction": "Send a message that causes the client to render a preview for the URL. If the client performs receiver-side fetching, the preview server will log an inbound request containing this token.",
				"verify": "Tool will now poll /_seen for up to ~15s to auto-detect fetch.",
			}
			// Attempt auto-detection by polling preview server /_seen
			if !opt.DryRun {
				deadline := time.Now().Add(15 * time.Second)
				seen := false
				for time.Now().Before(deadline) {
					reqURL := fmt.Sprintf("%s/_seen?token=%s", opt.PreviewHost, token)
					req, _ := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
					resp, err := http.DefaultClient.Do(req)
					if err == nil && resp != nil {
						body, _ := io.ReadAll(resp.Body)
						resp.Body.Close()
						var obj struct { Seen bool `json:"seen"` }
						_ = json.Unmarshal(body, &obj)
						if obj.Seen { seen = true; break }
					}
					time.Sleep(500 * time.Millisecond)
				}
				ev["auto_detect_seen"] = seen
				if seen { status = report.Pass }
			}
			evidence = ev
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
		Active: activeFlag,
	})
	return r, nil
}
