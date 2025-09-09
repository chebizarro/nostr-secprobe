# nostr-secprobe

A cross-platform Go CLI to test your own Nostr relays and clients for known vulnerability classes.

- MIT licensed. No CGO by default. Works on Windows/macOS/Linux.
- JSON/HTML/PDF reports with relay-grouped sections, severity/ACTIVE badges, summary table, and an interactive "Hide INCONCLUSIVE" toggle.
- Built-in preview-probe helper server for controlled preview-leakage tests.

## Install

```bash
git clone https://github.com/your-org/nostr-secprobe
cd nostr-secprobe
go build ./cmd/nostr-secprobe
```

## Quickstart

```bash
# Relay basics
./nostr-secprobe probe relay \
  --targets wss://relay.example,wss://relay.local:7443 \
  --out r.json --html r.html --pdf r.pdf

# Active checks (intrusive): replay/invalid-sig/malformed/rate/burst, latency percentiles
./nostr-secprobe probe relay \
  --targets wss://relay.example \
  --active --i-understand

# Preview-probe (local)
./nostr-secprobe serve preview-probe --addr :8080 &
./nostr-secprobe probe client --preview-host http://127.0.0.1:8080 --active --i-understand

# Connect (domain separation: NIP-04 vs NIP-46)
./nostr-secprobe probe connect --active --i-understand
```

## Probes (overview)

- Relay
  - Publish control; subscription integrity.
  - Reject mutated body with stale id/signature; reject duplicate (ID replay).
  - Reject invalid signature.
  - Rate/burst behavior with latency metrics: min/avg/max and P50/P90/P99.
  - Malformed/policy checks: pubkey encoding/length, kind, timestamps (past/future), tags (empty/too-long/malformed).
- Client
  - Preview-leakage harness: generates a unique tokenized URL; polls preview server `/_seen` to auto-detect and mark PASS.
- Connect
  - HKDF domain separation (NIP-04 vs NIP-46) PASS when outputs differ.

## Reports

- JSON via `--out`, HTML via `--html`, optional PDF via `--pdf`.
- HTML features:
  - Summary table per relay: PASS/FAIL/INCONCLUSIVE counts.
  - Grouped sections per relay; severity and ACTIVE badges.
  - Dark mode and print-friendly CSS.
  - Checkbox to “Hide INCONCLUSIVE” cards.

## ENV

```
NSEC_TARGETS=wss://relay.example:443,wss://relay.local:7443
NSEC_PREVIEW_HOST=http://127.0.0.1:8080
NSEC_PUBKEY=hexpub
NSEC_SECKEY=hexsec
NSEC_OUT=report.json
NSEC_RATE=5
NSEC_MAX_EVENTS=100
NSEC_TIMEOUT=30s
```

## Keys

- Provide `--pubkey/--seckey` to use fixed keys.
- If omitted, an ephemeral keypair is generated and logged (unless `--no-store`).

## Legal & Safety

- For testing systems you own or are explicitly authorized to assess.
- Intrusive checks require `--active --i-understand`.
- Respect rate limits and applicable laws.
- Report security issues privately via GitHub Security Advisories.
