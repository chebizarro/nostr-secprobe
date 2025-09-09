# nostr-secprobe

A cross-platform Go CLI to test your own Nostr relays and clients for known vulnerability classes.

- MIT licensed. No CGO by default. Works on Windows/macOS/Linux.
- JSON/HTML/PDF reports.
- Preview-probe helper server.

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

# Preview-probe (local)
./nostr-secprobe serve preview-probe --addr :8080 &
./nostr-secprobe probe client --preview-host http://127.0.0.1:8080 --active --i-understand
```

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

## Legal

For testing your own deployments/products. Intrusive tests require `--active --i-understand`.
