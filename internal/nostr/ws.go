package nostrx

import (
	"context"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"
)

type RelayClient struct{}

type Status struct{
	Success bool
	Message string
}

func (RelayClient) PublishWithAck(ctx context.Context, url string, ev *gonostr.Event) (*Status, error) {
	r, err := gonostr.RelayConnect(ctx, url)
	if err != nil { return nil, err }
	defer r.Close()
	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := r.Publish(ctx2, *ev); err != nil {
		return &Status{Success: false, Message: err.Error()}, nil
	}
	return &Status{Success: true, Message: "ok"}, nil
}
