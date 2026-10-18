package webhooks

import (
	"context"
	"slices"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// The secret is sealed with the node's keyring and opened for each delivery: the current one, and
// the one a rotation replaced while it is accepted (the cloud's "the secret is sealed under the
// workspace key").
func TestASealedSecretOpensAsItselfAndTheRotatedOneWhileItIsAccepted(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	made, first := f.create(t, "https://hooks.example.test/seal")
	e, _ := f.st.GetWebhookEndpoint(ctx, f.mine, made.ID)
	if got, lost, err := f.svc.SecretsFor(e, now.UnixMilli()); err != nil || lost || !slices.Equal(got, []string{first}) {
		t.Fatalf("before a rotation: %v %v %v", got, lost, err)
	}
	second, until, err := f.svc.Rotate(ctx, f.mine, made.ID)
	if err != nil {
		t.Fatal(err)
	}
	e, _ = f.st.GetWebhookEndpoint(ctx, f.mine, made.ID)
	// The blob that moved to previous_sealed still opens: the dual signature needs it.
	if got, lost, err := f.svc.SecretsFor(e, now.UnixMilli()); err != nil || lost || !slices.Equal(got, []string{second, first}) {
		t.Fatalf("during the window: %v %v %v, want new then old", got, lost, err)
	}
	if got, _, err := f.svc.SecretsFor(e, until); err != nil || !slices.Equal(got, []string{second}) {
		t.Fatalf("at the window's end: %v %v, want the new one alone", got, err)
	}
}

// The account and the endpoint are the additional data: a blob moved to another row, of another
// account or another endpoint, does not open there, rather than opening as somebody else's secret.
func TestASealedSecretOpensOnlyOnItsOwnRow(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	made, _ := f.create(t, "https://hooks.example.test/mine")
	e, _ := f.st.GetWebhookEndpoint(ctx, f.mine, made.ID)
	for name, moved := range map[string]store.WebhookEndpoint{
		"another account":  {ID: e.ID, AccountID: f.theirs, SecretSealed: e.SecretSealed},
		"another endpoint": {ID: "whe_other", AccountID: f.mine, SecretSealed: e.SecretSealed},
		"a malformed blob": {ID: e.ID, AccountID: f.mine, SecretSealed: []byte("short")},
	} {
		if _, _, err := f.svc.SecretsFor(moved, now.UnixMilli()); err == nil {
			t.Errorf("%s: the secret opened", name)
		}
	}
	// A previous secret that will not open is one nobody verifies against: the current one signs
	// alone, and the loss is reported.
	e.PreviousSealed, e.PreviousUntil = []byte("not a sealed secret at all"), now.UnixMilli()+1
	got, lost, err := f.svc.SecretsFor(e, now.UnixMilli())
	if err != nil || !lost || len(got) != 1 {
		t.Fatalf("with a previous secret that will not open: %v %v %v", got, lost, err)
	}
}
