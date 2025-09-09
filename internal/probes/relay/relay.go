package relay

import (
	"context"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	nostrx "nostr-secprobe/internal/nostr"
	"nostr-secprobe/internal/report"
	"nostr-secprobe/pkg/logx"
)

type Options struct {
	Targets     []string
	Rate        int
	MaxEvents   int
	DryRun      bool
	Active      bool
	IUnderstand bool
	PubKeyHex   string
	SecKeyHex   string
	NoStore     bool
}

func Run(ctx context.Context, opt Options) (*report.Results, error) {
	r := &report.Results{TargetType: "relay", Targets: opt.Targets, GeneratedAt: time.Now().UTC()}
	// Key management: use provided or generate ephemeral
	sk := opt.SecKeyHex
	pk := opt.PubKeyHex
	if sk == "" || pk == "" {
		// generate
		gsk, gpk, err := nostrx.GenerateKeyPair()
		if err != nil { return nil, err }
		sk = gsk
		pk = gpk
		if !opt.NoStore {
			logx.Infof("generated ephemeral key; pubkey=%s", pk)
		}
	}
	r.PubKey = pk

	client := nostrx.RelayClient{}

	// Control event
	ev := gonostr.Event{PubKey: pk, CreatedAt: gonostr.Now(), Kind: gonostr.KindTextNote, Content: "secprobe control"}
	if err := ev.Sign(sk); err != nil { return nil, err }
	if !opt.DryRun {
		for _, url := range opt.Targets {
			st, err := client.PublishWithAck(ctx, url, &ev)
			ok := err == nil && st != nil && st.Success
			r.Add(report.Finding{
				Name: "Event publish control",
				Category: "Event-ID & signature integrity",
				Severity: report.Low,
				Status: choose(ok, report.Pass, report.Inconclusive),
				Evidence: map[string]any{"event_id": ev.ID, "relay": url, "status": st},
				Mitigations: []string{"Recompute event id from canonical bytes", "Verify Schnorr signatures before trust/cache"},
				Timestamp: time.Now().UTC(),
			})
		}
	}

	// Mutated body but old id/signature should be rejected
	mut := ev
	mut.Content = ev.Content + " (mutated)"
	// keep old ID and sig intentionally: emulate a forged update relying on trust-on-id
	mut.ID = ev.ID
	mut.Sig = ev.Sig
	if !opt.DryRun {
		for _, url := range opt.Targets {
			st, err := client.PublishWithAck(ctx, url, &mut)
			rejected := err == nil && st != nil && !st.Success
			r.Add(report.Finding{
				Name: "Reject mutated body with stale id/sig",
				Category: "Event-ID & signature integrity",
				Severity: report.Medium,
				Status: choose(rejected, report.Pass, report.Fail),
				Evidence: map[string]any{"orig_id": ev.ID, "mut_id": mut.ID, "relay": url, "status": st, "error": errString(err)},
				Mitigations: []string{"Always recompute id from serialized bytes", "Always verify signature"},
				Timestamp: time.Now().UTC(),
			})
		}
	}

	// Duplicate event rejection: attempt to re-publish the same event ID/signature.
	if !opt.DryRun {
		for _, url := range opt.Targets {
			st2, err2 := client.PublishWithAck(ctx, url, &ev)
			// Expect rejection; if accepted again, that's suspicious.
			rejected := err2 == nil && st2 != nil && !st2.Success
			r.Add(report.Finding{
				Name: "Reject duplicate event (id replay)",
				Category: "Replay & duplication control",
				Severity: report.Low,
				Status: choose(rejected, report.Pass, report.Fail),
				Evidence: map[string]any{"event_id": ev.ID, "relay": url, "status": st2, "error": errString(err2)},
				Mitigations: []string{"Track seen event IDs and reject duplicates"},
				Timestamp: time.Now().UTC(),
			})
		}
	}

	// Simple rate/burst behavior probe (informational unless we can detect clear limit signals).
	if opt.Active && !opt.DryRun {
		burstN := opt.MaxEvents
		if burstN <= 0 || burstN > 20 { burstN = 20 }
		for _, url := range opt.Targets {
			sent := 0
			fails := 0
			for i := 0; i < burstN; i++ {
				e := gonostr.Event{PubKey: pk, CreatedAt: gonostr.Now(), Kind: gonostr.KindTextNote, Content: "secprobe burst"}
				if err := e.Sign(sk); err != nil { fails++; continue }
				st, err := client.PublishWithAck(ctx, url, &e)
				if err != nil || st == nil || !st.Success { fails++ } else { sent++ }
			}
			r.Add(report.Finding{
				Name: "Rate limiting / burst behavior (informational)",
				Category: "Rate limiting",
				Severity: report.Low,
				Status: report.Inconclusive,
				Evidence: map[string]any{"relay": url, "attempted": burstN, "sent": sent, "failures": fails},
				Mitigations: []string{"Enforce per-pubkey/per-IP rate limiting and provide clear backpressure responses"},
				Timestamp: time.Now().UTC(),
			})
		}
	}

	return r, nil
}

func choose[T any](cond bool, a, b T) T { if cond { return a }; return b }
func errString(err error) string { if err==nil {return ""}; return err.Error() }
