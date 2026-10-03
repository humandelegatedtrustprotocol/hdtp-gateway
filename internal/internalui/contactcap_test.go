package internalui

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
)

// The owner's refusal at the contact cap is 402, the status the cloud's /v1 gives every plan limit,
// never a 500 that reads as the node failing.
func TestAFullContactListIsPaymentRequiredToThePortal(t *testing.T) {
	if got := lifecycleStatus(fmt.Errorf("x: %w", contacts.ErrContactCap)); got != http.StatusPaymentRequired {
		t.Fatalf("the portal answers a full contact list %d", got)
	}
}
