package relay

import (
	"context"
	"time"
	"strings"
	"sort"

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

			// Subscription integrity: fetch the event back and verify canonical ID matches
			if ok {
				rx, errc := gonostr.RelayConnect(ctx, url)
				if errc == nil {
					func() {
						defer rx.Close()
						ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
						defer cancel()
						evs, qerr := rx.QuerySync(ctx2, gonostr.Filter{IDs: []string{ev.ID}})
						if qerr != nil {
							r.Add(report.Finding{
								Name: "Subscription/query integrity",
								Category: "Event-ID & signature integrity",
								Severity: report.Low,
								Status: report.Inconclusive,
								Evidence: map[string]any{"relay": url, "error": qerr.Error()},
								Mitigations: []string{"Ensure ID is recomputed on store/retrieval"},
								Timestamp: time.Now().UTC(),
							})
							return
						}
						if len(evs) == 0 {
							r.Add(report.Finding{
								Name: "Subscription/query integrity",
								Category: "Event-ID & signature integrity",
								Severity: report.Low,
								Status: report.Inconclusive,
								Evidence: map[string]any{"relay": url, "note": "event not returned by ID shortly after publish"},
								Mitigations: []string{"Ensure ID search works or allow for propagation delay"},
								Timestamp: time.Now().UTC(),
							})
							return
						}
						// Verify canonical id of the first match
						got := evs[0]
						canon := nostrx.CanonicalID(got)
						matches := canon == got.ID
						r.Add(report.Finding{
							Name: "Subscription/query canonical ID matches",
							Category: "Event-ID & signature integrity",
							Severity: report.Low,
							Status: choose(matches, report.Pass, report.Fail),
							Evidence: map[string]any{"relay": url, "returned_id": got.ID, "recomputed_id": canon},
							Mitigations: []string{"Always recompute ID from serialize()"},
							Timestamp: time.Now().UTC(),
						})
					}()
				}
			}
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
				Active: true,
			})
		}
	}

	// Malformed signature rejection: sign a valid event, then corrupt its signature.
	if !opt.DryRun {
		bad := ev
		// Ensure we have a signature field style as hex string of 64 bytes (128 hex chars).
		bad.Sig = strings.Repeat("0", 128)
		for _, url := range opt.Targets {
			st3, err3 := client.PublishWithAck(ctx, url, &bad)
			rejected := err3 == nil && st3 != nil && !st3.Success
			r.Add(report.Finding{
				Name: "Reject invalid signature",
				Category: "Event signature validation",
				Severity: report.High,
				Status: choose(rejected, report.Pass, report.Fail),
				Evidence: map[string]any{"event_id": bad.ID, "relay": url, "status": st3, "error": errString(err3)},
				Mitigations: []string{"Verify Schnorr signatures and reject invalid events"},
				Timestamp: time.Now().UTC(),
				Active: true,
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
			var durs []time.Duration
			var qdurs []time.Duration
			// Create a query connection if available for timing queries
			rx, rxErr := gonostr.RelayConnect(ctx, url)
			if rxErr == nil { defer rx.Close() }
			for i := 0; i < burstN; i++ {
				e := gonostr.Event{PubKey: pk, CreatedAt: gonostr.Now(), Kind: gonostr.KindTextNote, Content: "secprobe burst"}
				if err := e.Sign(sk); err != nil { fails++; continue }
				t0 := time.Now()
				st, err := client.PublishWithAck(ctx, url, &e)
				durs = append(durs, time.Since(t0))
				if err != nil || st == nil || !st.Success { fails++ } else {
					sent++
					// Time a query-by-ID round-trip when we have a connection
					if rxErr == nil {
						ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
						qt0 := time.Now()
						_, qerr := rx.QuerySync(ctx2, gonostr.Filter{IDs: []string{e.ID}})
						cancel()
						_ = qerr // treat any response time equally for now
						qdurs = append(qdurs, time.Since(qt0))
					}
				}
			}
			// compute simple stats in milliseconds
			ms := func(d time.Duration) float64 { return float64(d.Milliseconds()) }
			var min, max time.Duration
			var sum time.Duration
			if len(durs) > 0 { min, max = durs[0], durs[0] }
			for _, d := range durs {
				if d < min { min = d }
				if d > max { max = d }
				sum += d
			}
			avg := time.Duration(0)
			if len(durs) > 0 { avg = time.Duration(int64(sum) / int64(len(durs))) }
			// percentiles
			var p50, p90, p99 float64
			if len(durs) > 0 {
				cds := make([]time.Duration, len(durs))
				copy(cds, durs)
				sort.Slice(cds, func(i, j int) bool { return cds[i] < cds[j] })
				idx := func(p float64) int {
					n := len(cds)
					if n == 0 { return 0 }
					k := int(p*float64(n-1) + 0.5)
					if k < 0 { k = 0 }
					if k >= n { k = n-1 }
					return k
				}
				p50 = ms(cds[idx(0.50)])
				p90 = ms(cds[idx(0.90)])
				p99 = ms(cds[idx(0.99)])
			}
			// query percentiles
			var qp50, qp90, qp99, qmin, qavg, qmax float64
			if len(qdurs) > 0 {
				qminD, qmaxD := qdurs[0], qdurs[0]
				var qsum time.Duration
				cds := make([]time.Duration, len(qdurs))
				copy(cds, qdurs)
				sort.Slice(cds, func(i, j int) bool { return cds[i] < cds[j] })
				idx := func(p float64) int {
					n := len(cds)
					if n == 0 { return 0 }
					k := int(p*float64(n-1) + 0.5)
					if k < 0 { k = 0 }
					if k >= n { k = n-1 }
					return k
				}
				for _, d := range qdurs {
					if d < qminD { qminD = d }
					if d > qmaxD { qmaxD = d }
					qsum += d
				}
				qp50 = ms(cds[idx(0.50)])
				qp90 = ms(cds[idx(0.90)])
				qp99 = ms(cds[idx(0.99)])
				qmin = ms(qminD)
				qmax = ms(qmaxD)
				qavg = ms(time.Duration(int64(qsum) / int64(len(qdurs))))
			}
			r.Add(report.Finding{
				Name: "Rate limiting / burst behavior (informational)",
				Category: "Rate limiting",
				Severity: report.Low,
				Status: report.Inconclusive,
				Evidence: map[string]any{
					"relay": url,
					"attempted": burstN,
					"sent": sent,
					"failures": fails,
					"latency_ms_min": ms(min),
					"latency_ms_avg": ms(avg),
					"latency_ms_max": ms(max),
					"latency_ms_p50": p50,
					"latency_ms_p90": p90,
					"latency_ms_p99": p99,
					"query_latency_ms_min": qmin,
					"query_latency_ms_avg": qavg,
					"query_latency_ms_max": qmax,
					"query_latency_ms_p50": qp50,
					"query_latency_ms_p90": qp90,
					"query_latency_ms_p99": qp99,
				},
				Mitigations: []string{"Enforce per-pubkey/per-IP rate limiting and provide clear backpressure responses"},
				Timestamp: time.Now().UTC(),
				Active: true,
			})
		}
	}

	// Additional active checks: malformed events and filter fuzzing
	if opt.Active && !opt.DryRun {
		for _, url := range opt.Targets {
			// 1) Invalid pubkey with stale id/sig
			badPK := ev
			badPK.PubKey = "00"
			stpk, errpk := client.PublishWithAck(ctx, url, &badPK)
			rejectedPK := errpk == nil && stpk != nil && !stpk.Success
			r.Add(report.Finding{
				Name: "Reject invalid pubkey in event",
				Category: "Event validation",
				Severity: report.Medium,
				Status: choose(rejectedPK, report.Pass, report.Fail),
				Evidence: map[string]any{"relay": url, "status": stpk, "error": errString(errpk)},
				Mitigations: []string{"Validate pubkey encoding and signature binding"},
				Timestamp: time.Now().UTC(),
				Active: true,
			})

			// 2) Invalid kind (negative), properly signed
			badKind := gonostr.Event{PubKey: pk, CreatedAt: gonostr.Now(), Kind: -1, Content: "secprobe bad kind"}
			if err := badKind.Sign(sk); err == nil {
				stk, errk := client.PublishWithAck(ctx, url, &badKind)
				// Expect rejection, but if accepted we mark Fail
				rejectedK := errk == nil && stk != nil && !stk.Success
				r.Add(report.Finding{
					Name: "Reject invalid kind (negative)",
					Category: "Event validation",
					Severity: report.Low,
					Status: choose(rejectedK, report.Pass, report.Fail),
					Evidence: map[string]any{"relay": url, "status": stk, "error": errString(errk)},
					Mitigations: []string{"Enforce valid kind ranges per policy"},
					Timestamp: time.Now().UTC(),
					Active: true,
				})
			}

			// 3) Oversized content (16 KiB)
			big := make([]byte, 16*1024)
			for i := range big { big[i] = 'A' }
			bigEv := gonostr.Event{PubKey: pk, CreatedAt: gonostr.Now(), Kind: gonostr.KindTextNote, Content: string(big)}
			if err := bigEv.Sign(sk); err == nil {
				stb, errb := client.PublishWithAck(ctx, url, &bigEv)
				// Relay policy-dependent: treat acceptance as Inconclusive, rejection as Pass.
				rejectedBig := errb == nil && stb != nil && !stb.Success
				status := report.Inconclusive
				if rejectedBig { status = report.Pass }
				r.Add(report.Finding{
					Name: "Oversized content policy",
					Category: "Event size policy",
					Severity: report.Low,
					Status: status,
					Evidence: map[string]any{"relay": url, "size_bytes": len(big), "status": stb, "error": errString(errb)},
					Mitigations: []string{"Document and enforce reasonable content size limits"},
					Timestamp: time.Now().UTC(),
					Active: true,
				})
			}

			// 4) Subscription filter fuzzing: invalid IDs and kinds
			rx, errc := gonostr.RelayConnect(ctx, url)
			if errc == nil {
				func() {
					defer rx.Close()
					ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
					defer cancel()
					// Invalid IDs (non-hex), invalid kinds (negative)
					_, qerr := rx.QuerySync(ctx2, gonostr.Filter{IDs: []string{"nothex-id"}, Kinds: []int{-5}})
					// We consider either an error response or empty result as acceptable handling.
					st := report.Pass
					if qerr != nil { st = report.Pass } // handled with error is fine
					r.Add(report.Finding{
						Name: "Subscription filter fuzz handling",
						Category: "Input validation",
						Severity: report.Low,
						Status: st,
						Evidence: map[string]any{"relay": url, "error": errString(qerr)},
						Mitigations: []string{"Validate filters and avoid processing invalid IDs/kinds"},
						Timestamp: time.Now().UTC(),
						Active: true,
					})
				}()
			}

			// 5) Future timestamp policy
			future := gonostr.Event{PubKey: pk, CreatedAt: gonostr.Timestamp(time.Now().Add(48 * time.Hour).Unix()), Kind: gonostr.KindTextNote, Content: "secprobe future timestamp"}
			if err := future.Sign(sk); err == nil {
				stf, errf := client.PublishWithAck(ctx, url, &future)
				// Relay policy-dependent: if rejected, PASS; if accepted, INCONCLUSIVE
				rejectedF := errf == nil && stf != nil && !stf.Success
				st := report.Inconclusive
				if rejectedF { st = report.Pass }
				r.Add(report.Finding{
					Name: "Future timestamp policy",
					Category: "Event timestamp policy",
					Severity: report.Low,
					Status: st,
					Evidence: map[string]any{"relay": url, "created_at": future.CreatedAt, "status": stf, "error": errString(errf)},
					Mitigations: []string{"Reject events too far in the future or clamp timestamps"},
					Timestamp: time.Now().UTC(),
					Active: true,
				})
			}

			// 6) Invalid tag format (malformed tag entry)
			badTags := gonostr.Event{PubKey: pk, CreatedAt: gonostr.Now(), Kind: gonostr.KindTextNote, Content: "secprobe bad tag"}
			badTags.Tags = append(badTags.Tags, []string{"malformed"}) // single-element tag
			if err := badTags.Sign(sk); err == nil {
				stbtag, errbtag := client.PublishWithAck(ctx, url, &badTags)
				// Many relays may accept unknown tag shapes; treat rejection as PASS, acceptance as INCONCLUSIVE
				rejectedT := errbtag == nil && stbtag != nil && !stbtag.Success
				st := report.Inconclusive
				if rejectedT { st = report.Pass }
				r.Add(report.Finding{
					Name: "Malformed tag handling",
					Category: "Input validation",
					Severity: report.Low,
					Status: st,
					Evidence: map[string]any{"relay": url, "status": stbtag, "error": errString(errbtag)},
					Mitigations: []string{"Validate tag structure per NIP-01 or server policy"},
					Timestamp: time.Now().UTC(),
					Active: true,
				})
			}

			// 7) Non-hex pubkey
			badPKNonHex := ev
			badPKNonHex.PubKey = "zzzz"
			stpknh, errpknh := client.PublishWithAck(ctx, url, &badPKNonHex)
			rejectedPKNH := errpknh == nil && stpknh != nil && !stpknh.Success
			r.Add(report.Finding{
				Name: "Reject non-hex pubkey",
				Category: "Event validation",
				Severity: report.Medium,
				Status: choose(rejectedPKNH, report.Pass, report.Fail),
				Evidence: map[string]any{"relay": url, "status": stpknh, "error": errString(errpknh)},
				Mitigations: []string{"Validate pubkey encoding strictly as hex"},
				Timestamp: time.Now().UTC(),
				Active: true,
			})

			// 8) Short hex pubkey (too short)
			badPKShort := ev
			badPKShort.PubKey = "deadbeef"
			stpks, errpks := client.PublishWithAck(ctx, url, &badPKShort)
			rejectedPKS := errpks == nil && stpks != nil && !stpks.Success
			r.Add(report.Finding{
				Name: "Reject short hex pubkey",
				Category: "Event validation",
				Severity: report.Medium,
				Status: choose(rejectedPKS, report.Pass, report.Fail),
				Evidence: map[string]any{"relay": url, "status": stpks, "error": errString(errpks)},
				Mitigations: []string{"Validate pubkey length and structure"},
				Timestamp: time.Now().UTC(),
				Active: true,
			})

			// 9) Past timestamp skew policy (-48h)
			past := gonostr.Event{PubKey: pk, CreatedAt: gonostr.Timestamp(time.Now().Add(-48 * time.Hour).Unix()), Kind: gonostr.KindTextNote, Content: "secprobe past timestamp"}
			if err := past.Sign(sk); err == nil {
				stp, errp := client.PublishWithAck(ctx, url, &past)
				// Policy-dependent; treat acceptance as INCONCLUSIVE, rejection as PASS
				rejectedP := errp == nil && stp != nil && !stp.Success
				st := report.Inconclusive
				if rejectedP { st = report.Pass }
				r.Add(report.Finding{
					Name: "Past timestamp policy",
					Category: "Event timestamp policy",
					Severity: report.Low,
					Status: st,
					Evidence: map[string]any{"relay": url, "created_at": past.CreatedAt, "status": stp, "error": errString(errp)},
					Mitigations: []string{"Clamp or accept within allowed skew; reject too old events if policy requires"},
					Timestamp: time.Now().UTC(),
					Active: true,
				})
			}

			// 10) Empty tag and too-long tag
			emptyTag := gonostr.Event{PubKey: pk, CreatedAt: gonostr.Now(), Kind: gonostr.KindTextNote, Content: "secprobe empty tag"}
			emptyTag.Tags = append(emptyTag.Tags, []string{})
			if err := emptyTag.Sign(sk); err == nil {
				ste, erre := client.PublishWithAck(ctx, url, &emptyTag)
				rejectedE := erre == nil && ste != nil && !ste.Success
				st := report.Inconclusive
				if rejectedE { st = report.Pass }
				r.Add(report.Finding{
					Name: "Empty tag handling",
					Category: "Input validation",
					Severity: report.Low,
					Status: st,
					Evidence: map[string]any{"relay": url, "status": ste, "error": errString(erre)},
					Mitigations: []string{"Reject empty tag entries or normalize per policy"},
					Timestamp: time.Now().UTC(),
					Active: true,
				})
			}
			tooLongTag := gonostr.Event{PubKey: pk, CreatedAt: gonostr.Now(), Kind: gonostr.KindTextNote, Content: "secprobe long tag"}
			tooLongTag.Tags = append(tooLongTag.Tags, []string{"x","1","2","3","4","5","6","7","8","9","10"})
			if err := tooLongTag.Sign(sk); err == nil {
				stl, errl := client.PublishWithAck(ctx, url, &tooLongTag)
				// Policy varies; treat rejection as PASS
				rejectedL := errl == nil && stl != nil && !stl.Success
				st := report.Inconclusive
				if rejectedL { st = report.Pass }
				r.Add(report.Finding{
					Name: "Too-long tag handling",
					Category: "Input validation",
					Severity: report.Low,
					Status: st,
					Evidence: map[string]any{"relay": url, "status": stl, "error": errString(errl)},
					Mitigations: []string{"Enforce reasonable tag element length and count"},
					Timestamp: time.Now().UTC(),
					Active: true,
				})
			}
		}
	}

	return r, nil
}

func choose[T any](cond bool, a, b T) T { if cond { return a }; return b }
func errString(err error) string { if err==nil {return ""}; return err.Error() }
