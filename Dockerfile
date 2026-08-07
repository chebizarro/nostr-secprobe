# syntax=docker/dockerfile:1.6

# --- Builder stage ---
FROM golang:1.24 as builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Build statically linked binary (CGO disabled)
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o /out/nostr-secprobe ./cmd/nostr-secprobe

# --- Runtime stage ---
# Use distroless base with certs for TLS
FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=builder /out/nostr-secprobe /usr/local/bin/nostr-secprobe
USER nonroot
ENTRYPOINT ["/usr/local/bin/nostr-secprobe"]
CMD ["--help"]
