package refusal

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

const canary = "pq: relation contacts_canary_7f3a does not exist"

// Of reads every refusal through %w and errors.Join alike, answers each code with its detail, and
// never carries a canary that was not the node's own words: a marked sentence without its cause, a
// recorded-not-delivered reason without its cause, a store's not-found and anything else as fixed
// phrases. The control, a coded refusal, keeps the node's sentence.
func TestOfAnswersEachRefusalItsCodeAndNoForeignText(t *testing.T) {
	storeFailure := errors.New(canary)
	for _, c := range []struct {
		name         string
		err          error
		code, detail string
	}{
		{"a marked sentence", BadRequest("that card or note is too large", storeFailure), "bad_request", "that card or note is too large"},
		{"a marked sentence, wrapped", fmt.Errorf("adding: %w", BadRequest("an invite link is an https:// URL", nil)), "bad_request", "an invite link is an https:// URL"},
		{"a marked sentence, joined", errors.Join(storeFailure, BadRequest("choose a transport", nil)), "bad_request", "choose a transport"},
		{"recorded, not delivered", Undelivered("unreachable", storeFailure), "unavailable", "recorded, not delivered: unreachable"},
		{"recorded, not delivered, wrapped", fmt.Errorf("send: %w", Undelivered("rate_limited", storeFailure)), "unavailable", "recorded, not delivered: rate_limited"},
		{"a contact not held", fmt.Errorf("%w: no such contact", contacts.ErrUnknownContact), "not_found", "unknown_contact: no such contact"},
		{"a request closed", integrations.ErrRequestClosed, "conflict", integrations.ErrRequestClosed.Error()},
		{"no catalog", integrations.ErrNoCatalog, "conflict", integrations.ErrNoCatalog.Error()},
		{"over the cap", fmt.Errorf("%w: this identity holds 5 contacts", contacts.ErrContactCap), "payment_required", fmt.Sprintf("%v: this identity holds 5 contacts", contacts.ErrContactCap)},
		{"a message too large", fmt.Errorf("%w: text over 16 KiB", messaging.ErrTooLarge), "too_large", "too_large: text over 16 KiB"},
		{"a fetch refused", messaging.FetchRefusal{Code: "permission_denied", Sentence: "media.example resolves to a private address"}, "permission_denied", "media.example resolves to a private address"},
		{"an install refused", identity.RefuseLeaf("chain refused by rule 4", identity.ErrLeafRefused), "bad_request", "identity: chain refused by rule 4: leaf refused"},
		{"a token with no label", auth.ErrLabelRequired, "bad_request", auth.ErrLabelRequired.Error()},
		{"a store's not-found", fmt.Errorf("reading: %w", store.ErrNotFound), "not_found", NotFoundDetail},
		{"a store's failure", fmt.Errorf("reading: %w", storeFailure), "internal", InternalDetail},
		{"a store's failure, joined with nothing coded", errors.Join(storeFailure, errors.New("disk full")), "internal", InternalDetail},
	} {
		code, detail := Of(c.err)
		if code != c.code || detail != c.detail || strings.Contains(detail, canary) {
			t.Errorf("%s: Of = %q %q, want %q %q", c.name, code, detail, c.code, c.detail)
		}
	}
}

// BadRequest and Undelivered keep their cause in Error() (an audit row's why reads it) and out of
// what Sentence and Why read back; neither reads anything from an error that holds no mark.
func TestTheMarksReadBackWithoutTheirCause(t *testing.T) {
	cause := errors.New(canary)
	br := BadRequest("could not reach the invite link", cause)
	if br.Error() != "could not reach the invite link: "+canary {
		t.Errorf("BadRequest's Error() = %q", br.Error())
	}
	if s, ok := Sentence(fmt.Errorf("x: %w", br)); !ok || s != "could not reach the invite link" {
		t.Errorf("Sentence = %q %v", s, ok)
	}
	u := Undelivered("endpoint_refused", cause)
	if u.Error() != canary {
		t.Errorf("Undelivered's Error() = %q", u.Error())
	}
	if w, ok := Why(errors.Join(errors.New("other"), u)); !ok || w != "endpoint_refused" {
		t.Errorf("Why = %q %v", w, ok)
	}
	if _, ok := Sentence(cause); ok {
		t.Error("Sentence read a mark from an error that holds none")
	}
	if _, ok := Why(cause); ok {
		t.Error("Why read a mark from an error that holds none")
	}
}
