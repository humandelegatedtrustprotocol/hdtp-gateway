package refusal

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
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
		{"an install refused", realInstallRefusal(t), "bad_request", "identity: no certificate request is pending for this account; run `account csr` first: leaf refused"},
		{"a token with no label", auth.ErrLabelRequired, "bad_request", auth.ErrLabelRequired.Error()},
		{"a target in the wrong state", fmt.Errorf("unpair: %w", Conflict("x is the selected tunnel", storeFailure)), "conflict", "x is the selected tunnel"},
		{"a target not held", errors.Join(storeFailure, NotFound("unknown account", storeFailure)), "not_found", "unknown account"},
		{"an argument over its bound", errors.Join(storeFailure, TooLarge("the surface is over 16 KiB", storeFailure)), "too_large", "the surface is over 16 KiB"},
		{"a peer not reached", Unavailable("the request did not reach the peer", storeFailure), "unavailable", "the request did not reach the peer"},
		{"a budget that refused", fmt.Errorf("adding: %w", RateLimited("try again in 7 s", storeFailure)), "rate_limited", "try again in 7 s"},
		{"an identity awaiting its wallet", fmt.Errorf("node: a awaits its wallet: %w", identity.ErrNoCertificate), "not_found", "node: a awaits its wallet: identity: no current certificate"},
		{"a slug in use", fmt.Errorf("creating: %w", identity.ErrSlugTaken), "conflict", "creating: identity: that slug is taken"},
		{"an integration not connected", fmt.Errorf("x: %w", integrations.ErrNotConnected), "conflict", "x: integrations: not connected"},
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
// what Of and Why read back; neither reads a mark from an error that holds none.
func TestTheMarksReadBackWithoutTheirCause(t *testing.T) {
	cause := errors.New(canary)
	br := BadRequest("could not reach the invite link", cause)
	if br.Error() != "could not reach the invite link: "+canary {
		t.Errorf("BadRequest's Error() = %q", br.Error())
	}
	if code, s := Of(fmt.Errorf("x: %w", br)); code != "bad_request" || s != "could not reach the invite link" {
		t.Errorf("Of = %q %q", code, s)
	}
	if got := Undelivered("unreachable", nil).Error(); got != "recorded, not delivered: unreachable" {
		t.Errorf("Undelivered with no cause: %q", got)
	}
	u := Undelivered("endpoint_refused", cause)
	if u.Error() != canary {
		t.Errorf("Undelivered's Error() = %q", u.Error())
	}
	if w, ok := Why(errors.Join(errors.New("other"), u)); !ok || w != "endpoint_refused" {
		t.Errorf("Why = %q %v", w, ok)
	}
	if code, _ := Of(cause); code != "internal" {
		t.Error("Of read a mark from an error that holds none")
	}
	if _, ok := Why(cause); ok {
		t.Error("Why read a mark from an error that holds none")
	}
}

// realInstallRefusal is an install refusal the identity package worded, from a real install: an
// answer to an identity with no request pending.
func realInstallRefusal(t *testing.T) error {
	t.Helper()
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "i.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	kr, err := core.OpenKeyring(filepath.Join(t.TempDir(), "k"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	m := &identity.Manager{Store: st, Keyring: kr}
	a, err := m.CreateAccount(ctx, "alina", "Alina Rao", identity.AlgoEd25519)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.InstallLeaf(ctx, a.ID, [][]byte{{1}, {2}}, time.Now())
	if _, ok := identity.Worded(err); !ok {
		t.Fatalf("the install did not answer a worded refusal: %v", err)
	}
	return err
}

// A reason rides beside a refusal and changes nothing of it: Of reads the refusal through it, as it
// is or wrapped, and Reason reads the reason back; a refusal with none has none.
func TestAReasonRidesBesideTheRefusal(t *testing.T) {
	err := fmt.Errorf("put: %w", For("invalid_surface:own_message", BadRequest("an ask ends with the owner's own message", nil)))
	if code, detail := Of(err); code != "bad_request" || detail != "an ask ends with the owner's own message" {
		t.Fatalf("Of through a reason: %s %q", code, detail)
	}
	if r := Reason(err); r != "invalid_surface:own_message" {
		t.Fatalf("Reason: %q", r)
	}
	if r := Reason(BadRequest("no reason", nil)); r != "" {
		t.Fatalf("a refusal with no reason: %q", r)
	}
}
