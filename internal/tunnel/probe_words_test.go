package tunnel

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// The probe's Detail, which the settings page shows, is the node's: a chain refused by the rule
// alone, an endpoint that does not answer and a certificate that does not verify in fixed
// phrases, and another instance without the id it echoed (the answerer's to choose). Detail was the
// TLS stack's error and the echoed id. The control, a reachable node, has no detail.
func TestTheProbesDetailIsTheNodesWords(t *testing.T) {
	ctx := context.Background()
	a := serve(t, "Alina", "node-A", nil)
	opts := func(ids ...Served) ProbeOptions {
		return ProbeOptions{Identities: ids, InstanceID: "node-A", Timeout: 3 * time.Second, DialContext: a.dial}
	}
	if r := Probe(ctx, a.base, opts(a.identity)); r.Verdict != VerdictReachable || r.Detail != "" {
		t.Fatalf("the control: %+v", r)
	}
	other := testid.NewWallet(t, "Bharat")
	if r := Probe(ctx, a.base, opts(Served{Root: other.Fpr, Endpoint: a.identity.Endpoint})); !regexp.MustCompile(
		`^the chain served there is not one a peer would accept \(for \S+ at \S+: rule \d+\)$`).MatchString(r.Detail) {
		t.Errorf("another root: %q", r.Detail)
	}
	if r := Probe(ctx, a.base, opts()); r.Detail != "the certificate served there does not verify for this address" {
		t.Errorf("webpki: %q", r.Detail)
	}
	wrong := opts(a.identity)
	wrong.InstanceID = "node-B"
	if r := Probe(ctx, a.base, wrong); r.Detail != "endpoint reaches a different hdtp-gateway instance" {
		t.Errorf("another instance: %q", r.Detail)
	}
	a.srv.Close()
	if r := Probe(ctx, a.base, opts(a.identity)); r.Detail != "the endpoint did not answer the probe" {
		t.Errorf("nothing listens: %q", r.Detail)
	}
}
