package nostrx

import (
	"context"
	"time"

	"fiatjaf.com/nostr"
)

type RelayClient struct{}

type Status struct{
	Success bool
	Message string
}

func (RelayClient) PublishWithAck(ctx context.Context, url string, ev *nostr.Event) (*Status, error) {
	r, err := nostr.RelayConnect(ctx, url, nostr.RelayOptions{})
	if err != nil { return nil, err }
	defer r.Close()
	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := r.Publish(ctx2, *ev); err != nil {
		return &Status{Success: false, Message: err.Error()}, nil
	}
	return &Status{Success: true, Message: "ok"}, nil
}
