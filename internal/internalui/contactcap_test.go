package internalui

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// The owner's refusal at the contact cap is 402, the status the cloud's /v1 gives every plan limit,
// never a 500 that reads as the node failing.
func TestAFullContactListIsPaymentRequiredToThePortal(t *testing.T) {
	if got := pageStatus(fmt.Errorf("x: %w", contacts.ErrContactCap)); got != http.StatusPaymentRequired {
		t.Fatalf("the portal answers a full contact list %d", got)
	}
}

// A refusal coded too_large is 413 on every portal route that reads pageStatus, as POST
// /thread/delete answers a thread_id over 64 bytes: an upload over the identity's storage quota
// answered 400. The control, an argument refusal, stays 400.
func TestTooLargeIs413ToThePortal(t *testing.T) {
	if got := pageStatus(fmt.Errorf("x: %w", messaging.ErrQuota)); got != http.StatusRequestEntityTooLarge {
		t.Errorf("the portal answers a storage quota reached %d", got)
	}
	if got := pageStatus(fmt.Errorf("x: %w", messaging.ErrBadRequest)); got != http.StatusBadRequest {
		t.Errorf("the control: the portal answers a bad request %d", got)
	}
	mux := mediaMux(t, func(context.Context, string, string, messaging.Input, string, string, []byte) (messaging.Result, error) {
		return messaging.Result{}, fmt.Errorf("storing: %w", messaging.ErrQuota)
	})
	rr := upload(t, mux, map[string]string{"contact": "sha256:bob", "msg_id": "m-1"}, "a.txt", []byte("hello"))
	if rr.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rr.Body.String(), `"error"`) {
		t.Errorf("send_media over the quota: %d %s, want 413", rr.Code, rr.Body.String())
	}
}
