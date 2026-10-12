package settings

import (
	"context"
	"errors"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
)

type accountsFail struct{ store.Store }

func (accountsFail) ListAccounts(context.Context) ([]store.Account, error) {
	return nil, errors.New("pq: relation contacts_canary_7f3a does not exist")
}

// A pairing whose account list could not be read is a failure of the node, internal, not "create
// an account before pairing": a store that failed has not said there are no accounts. The control,
// a node with no account, is told to create one.
func TestAPairingWhoseAccountsCannotBeReadIsAFailure(t *testing.T) {
	svc, st := presetSvc(t)
	in := internalui.PairInput{PairURL: "https://ingress.example/pair", Token: "t", Subdomain: "me"}
	svc.store = accountsFail{st}
	_, err := svc.Deps().Pair(context.Background(), in)
	if code, detail := refusal.Of(err); code != "internal" || detail != refusal.InternalDetail {
		t.Errorf("an account list that failed: %v → %s %q", err, code, detail)
	}
	svc.store = st
	_, err = svc.Deps().Pair(context.Background(), in)
	if code, s := refusal.Of(err); code != "bad_request" || s != "create an account before pairing" {
		t.Errorf("the control, no account: %v", err)
	}
}
