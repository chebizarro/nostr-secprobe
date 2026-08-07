# nostr-secprobe

A cross-platform Go CLI to test your own Nostr relays and clients for known vulnerability classes.

- MIT licensed. No CGO by default. Works on Windows/macOS/Linux.
- JSON/HTML/PDF reports with relay-grouped sections, severity/ACTIVE badges, summary table, and an interactive "Hide INCONCLUSIVE" toggle.
- Built-in preview-probe helper server for controlled preview-leakage tests.

## Install

Pick one of the options below.

### From source (Go)
```bash
git clone https://github.com/your-org/nostr-secprobe
cd nostr-secprobe
go build ./cmd/nostr-secprobe
./nostr-secprobe --version
```

### Prebuilt binaries (Releases)
- Download the archive for your OS/arch from the GitHub Releases page.
- Extract and run `nostr-secprobe` (or `nostr-secprobe.exe` on Windows).

### Homebrew (macOS)
```bash
brew tap your-org/homebrew-tap
brew install nostr-secprobe
nostr-secprobe --version
```

### Scoop (Windows)
```powershell
scoop bucket add your-bucket https://github.com/your-org/scoop-bucket
scoop install nostr-secprobe
nostr-secprobe --version
```

### Docker (GHCR)
```bash
docker pull ghcr.io/your-org/nostr-secprobe:latest
docker run --rm ghcr.io/your-org/nostr-secprobe:latest --help
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
  --active --i-understand \
  --concurrency 4 --backoff 250ms --retries 2

# Preview-probe (local)
./nostr-secprobe serve preview-probe --addr :8080 &
./nostr-secprobe probe client --preview-host http://127.0.0.1:8080 --active --i-understand

# Connect (domain separation: NIP-04 vs NIP-46)
./nostr-secprobe probe connect --active --i-understand
```

## Library usage

Import the relay probe from `git.sharegap.net/cascadia/nostr-secprobe/pkg/probes/relay`:

```go
package main

import (
    "context"
    "log"

    "git.sharegap.net/cascadia/nostr-secprobe/pkg/probes/relay"
)

func main() {
    results, err := relay.Run(context.Background(), relay.Options{
        Targets: []string{"wss://relay.example"},
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("findings: %d", len(results.Findings))
}
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

## Docker

Build locally and run:

```bash
docker build -t ghcr.io/your-org/nostr-secprobe:dev .
docker run --rm ghcr.io/your-org/nostr-secprobe:dev --help

# Example relay probe from Docker
docker run --rm ghcr.io/your-org/nostr-secprobe:dev \
  probe relay --targets wss://relay.example --active --i-understand \
  --concurrency 4 --backoff 250ms --retries 2
```

Published images (on tags) are available at `ghcr.io/<owner>/<repo>:<tag>` and `:latest`.

## Config file (JSON)

All common flags can be provided via a JSON config, then overridden by CLI flags:

```json
{
  "targets": "wss://relay.example.org,wss://relay2.example.org",
  "active": true,
  "i_understand": true,
  "rate": 5,
  "max_events": 20,
  "timeout": "1m",
  "concurrency": 4,
  "backoff": "250ms",
  "retries": 2,
  "log_level": "info",
  "html": "report.html",
  "out": "report.json"
}
```

Run with:

```bash
./nostr-secprobe --config config.json probe relay
```

## Flags (selected)

- `--concurrency` (int): in-flight publishes per target during bursts (default 1).
- `--backoff` (duration): sleep after failed publish (e.g., `200ms`).
- `--retries` (int): retry failed publishes up to N times with exponential backoff (if `--backoff` > 0).
- `--config` (path): JSON file to load defaults from.

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
