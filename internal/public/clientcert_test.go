package public

// `client_cert: required` is PACT §13.4's front-door posture: "a node MAY
// additionally require transport client certificates and refuse a
// certificate-less `sealed_call` with `identity_required`". It is a statement
// about who may knock at all, so what satisfies it has to be something a
// stranger cannot mint.
//
// It was satisfied by ANY self-signed certificate. The facts middleware filled
// `ClientCertFingerprint` from whatever single certificate arrived — a proof
// only while the identity IS a key, which is the generation removed on
// 2026-09-18 — and the gate asked only that the field be non-empty. Two lines
// of openssl walked through the hardened door.

import (
	"context"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core"
)

func TestClientCertRequiredTakesAChainAndNothingElse(t *testing.T) {
	id := &Identifier{AccountID: "acct", Seal: core.SealOptional, Cert: core.ClientCertRequired}
	ctx := context.Background()

	// No certificate at all.
	if _, err := id.PlaintextGateCtx(ctx, TransportFacts{}, "send_message", true); Code(err) != "identity_required" {
		t.Fatalf("no certificate: %v (want identity_required)", err)
	}

	// A lone self-signed certificate. The middleware no longer reports one at
	// all; this asserts the gate independently, so that restoring the branch
	// without restoring the check fails here.
	lone := TransportFacts{ClientCertFingerprint: "sha256:whatever-a-stranger-minted", ClientCertSPKI: []byte("spki")}
	if _, err := id.PlaintextGateCtx(ctx, lone, "send_message", true); Code(err) != "identity_required" {
		t.Fatalf("a lone certificate must not open a client_cert:required door: %v", err)
	}

	// A validated chain — the only proof that names a root.
	chain := TransportFacts{ClientCertFingerprint: "sha256:root", ClientProtocol: 2, ClientLeaf: []byte("leaf")}
	if fpr, err := id.PlaintextGateCtx(ctx, chain, "send_message", true); err != nil || fpr != "sha256:root" {
		t.Fatalf("a validated chain must pass as its root: fpr=%q err=%v", fpr, err)
	}
}

// The middleware half of the same rule: a request that carried one certificate
// leaves no identity behind, so nothing downstream — the tier lookup, the guest
// budget, the session binding — can be handed an unproven fingerprint.
func TestFactsCarryNoIdentityWithoutAChain(t *testing.T) {
	// Covered end to end over a real handshake by
	// TestHandshakeAcceptsEveryCertificateAndBelievesOnlyAChain; this names the
	// invariant so a reader of TransportFacts finds it.
	var f TransportFacts
	if f.ClientCertFingerprint != "" || f.ClientProtocol != 0 {
		t.Fatal("the zero value must be 'nobody'")
	}
}
