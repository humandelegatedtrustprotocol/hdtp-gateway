package settings

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
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

// A pairing or an unpairing the target's state or holdings refuse answers the code of that truth,
// not bad_request: an account the caller named that the node does not hold is not_found, a node
// not serving yet and the selected tunnel are conflict. Each keeps its sentence. The control, an
// unpairing of an adapter that is not selected, gets through.
func TestPairAndUnpairRefusalsAnswerTheTargetsCode(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := openStoreAt(t, dir)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alice", DisplayName: "Alice", Algo: "ed25519"}); err != nil {
		t.Fatal(err)
	}
	cfg := &core.Config{DataDir: dir, Tunnel: "ingress-terminate"}
	svc := New(st, openKeyringAt(t, dir), cfg, func(string, string, string) {})
	in := internalui.PairInput{PairURL: "https://ingress.example/pair", Token: "t", Subdomain: "me"}

	named := in
	named.Account = "nosuch"
	_, err := svc.Deps().Pair(ctx, named)
	if code, s := refusal.Of(err); code != "not_found" || s != "unknown account" {
		t.Errorf("an account the node does not hold: %v → %s %q", err, code, s)
	}
	_, err = svc.Deps().Pair(ctx, in)
	if code, s := refusal.Of(err); code != "conflict" || s != "the node is not serving yet" {
		t.Errorf("a node not serving yet: %v → %s %q", err, code, s)
	}
	err = svc.Deps().Unpair(ctx, "ingress-terminate")
	if code, s := refusal.Of(err); code != "conflict" || !strings.HasPrefix(s, "ingress-terminate is the selected tunnel") {
		t.Errorf("the running selection: %v → %s %q", err, code, s)
	}
	if err := st.PutSetting(ctx, store.Setting{Key: "tunnel", Value: "ingress-passthrough"}); err != nil {
		t.Fatal(err)
	}
	err = svc.Deps().Unpair(ctx, "ingress-passthrough")
	if code, s := refusal.Of(err); code != "conflict" || !strings.HasPrefix(s, "ingress-passthrough is the selected tunnel") {
		t.Errorf("the stored selection: %v → %s %q", err, code, s)
	}
	if err := st.PutSetting(ctx, store.Setting{Key: "tunnel", Value: "ingress-terminate"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Deps().Unpair(ctx, "ingress-passthrough"); err != nil {
		t.Errorf("the control, an adapter not selected: %v", err)
	}
}
