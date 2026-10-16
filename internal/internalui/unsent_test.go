package internalui

import (
	"errors"
	"net/http"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
)

// The portal tells a call out that never left as the node coded it (#182): this identity's own
// budget is 429 rate_limited, on a contact's page call and on its refresh; the limits sidecar not
// answering is 502 unavailable. The budget's refusal was a 502 unavailable on the call and a 500 on
// the refresh. The control, a dial that failed, is still 502 unavailable.
func TestThePortalTellsACallThatNeverLeftAsCoded(t *testing.T) {
	limited := refusal.RateLimited((&outbound.RateLimited{RetryAfter: 3}).Sentence(), nil)
	if status, code := contactCallRefusal(limited); status != http.StatusTooManyRequests || code != "rate_limited" {
		t.Errorf("a call this identity's budget refused: %d %s", status, code)
	}
	if status := pageStatus(limited); status != http.StatusTooManyRequests {
		t.Errorf("a refresh this identity's budget refused: %d", status)
	}
	down := refusal.Unavailable(outbound.LimitsUnavailableSentence, nil)
	if status, code := contactCallRefusal(down); status != http.StatusBadGateway || code != "unavailable" {
		t.Errorf("a call with the sidecar down: %d %s", status, code)
	}
	if status := pageStatus(down); status != http.StatusBadGateway {
		t.Errorf("a refresh with the sidecar down: %d", status)
	}
	if status, code := contactCallRefusal(errors.New("outbound: dial: connection refused")); status != http.StatusBadGateway || code != "unavailable" {
		t.Errorf("the control, a dial that failed: %d %s", status, code)
	}
}
