package node

import (
	"context"
	"errors"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
)

// A request_contact that failed here, before the call — this identity's card could not be read — is
// not ErrNotReached: the doors tell it as this node's failure (internal), never as a peer that could
// not be reached (#131).
func TestARequestThatFailsBeforeTheCallIsNotUnreached(t *testing.T) {
	e, _ := newEnv(t, "alice")
	n, err := New(context.Background(), e.options())
	if err != nil {
		t.Fatal(err)
	}
	err = n.RequestContact(context.Background(), "no-such-account", outbound.Peer{Endpoint: "https://peer.invalid/mcp"}, "", "call-1")
	if err == nil {
		t.Fatal("a request with no card to send was sent")
	}
	if errors.As(err, &ErrNotReached{}) {
		t.Fatalf("a card that could not be read is told as a call that got no answer: %v", err)
	}
}
