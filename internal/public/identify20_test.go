package public

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/policy"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/envelope"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// PACT 2.0 receiving (PACT §13.3, §6.1, §5.3, §14.3, §14.4) against a node
// that has installed a wallet-issued leaf. The peers are built with the
// library — a root each, a leaf per address — exactly as a wallet would.

const (
	endpointMe = "https://me.example/a/me/mcp"
	endpointA  = "https://agent.alina.example/mcp"
	endpointA2 = "https://alina.pact.contact/alina/mcp"
)

type env20 struct {
	st      store.Store
	m       *identity.Manager
	id      *Identifier
	acct    store.Account
	root    *testRoot // our own root, for renewals
	nowAt   time.Time
	sibling []string
}

type testRoot struct {
	key  *pactidentity.PrivateKey
	cert []byte
	fpr  string
}

func newTestRoot(t *testing.T, cn string, at time.Time) *testRoot {
	t.Helper()
	key, err := pactidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pactidentity.BuildRoot(pactidentity.RootOpts{CN: cn, Key: key, NotBefore: at.Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return &testRoot{key: key, cert: cert, fpr: pactidentity.Fingerprint(key.Public.SPKI)}
}

// peer is a 2.0 identity elsewhere: a root and the host key of its current leaf.
type peer struct {
	root *testRoot
	host *pactidentity.PrivateKey
	leaf []byte
}

func (p *peer) chain() [][]byte { return [][]byte{p.leaf, p.root.cert} }
func (p *peer) fpr() string     { return p.root.fpr }

// leafFor issues a leaf under the peer's root for an endpoint, dated from `at`.
func (p *peer) leafFor(t *testing.T, endpoint string, at time.Time) []byte {
	t.Helper()
	der, err := pactidentity.BuildLeaf(pactidentity.LeafOpts{
		CN: "Alina Rao", RootCN: "Alina Rao", RootKey: p.root.key, HostPub: p.host.Public, Endpoint: endpoint,
		NotBefore: at, NotAfter: at.Add(365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func newPeer(t *testing.T, at time.Time) *peer {
	t.Helper()
	host, err := pactidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	p := &peer{root: newTestRoot(t, "Alina Rao", at), host: host}
	p.leaf = p.leafFor(t, endpointA, at.Add(-time.Hour))
	return p
}

func newEnv20(t *testing.T) *env20 {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "id20.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	kr, err := core.OpenKeyring(filepath.Join(t.TempDir(), "k"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	m := &identity.Manager{Store: st, Keyring: kr}
	a, err := m.CreateAccount(ctx, "me", "Me", identity.AlgoEd25519)
	if err != nil {
		t.Fatal(err)
	}
	e := &env20{st: st, m: m, nowAt: fixedNow, root: newTestRoot(t, "Me", fixedNow)}
	e.install(t, identity.PurposeUpgrade, endpointMe)
	e.acct, _ = st.GetAccountByID(ctx, a.ID)
	e.id = &Identifier{
		Store: st, AccountID: a.ID,
		Keypair: func(context.Context, string) (*identity.Keypair, error) {
			keys, err := m.ActiveLeafKeypairs(context.Background(), a.ID, e.nowAt)
			if err != nil {
				return nil, err
			}
			return keys[0].KP, nil
		},
		Seal: core.SealRequired, Cert: core.ClientCertPreferred,
		Now:     func() time.Time { return e.nowAt },
		State20: func(ctx context.Context) (*State20, error) { return e.state(ctx) },
	}
	return e
}

// install runs the CSR round trip of PACT §9 for our account under our root.
func (e *env20) install(t *testing.T, purpose, endpoint string) {
	t.Helper()
	ctx := context.Background()
	accts, _ := e.st.ListAccounts(ctx)
	csr, err := e.m.IssueCSR(ctx, accts[0].ID, purpose, endpoint, e.nowAt)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := pactidentity.IssueFromCSR(csr.CSR, pactidentity.IssueOpts{
		RootCN: "Me", RootKey: e.root.key, RootSPKIs: [][]byte{e.root.key.Public.SPKI}, Now: e.nowAt,
		PreviousNotBefore: csr.PreviousNotBefore, ValidDays: 365,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.InstallLeaf(ctx, accts[0].ID, [][]byte{iss.DER, e.root.cert}, e.nowAt); err != nil {
		t.Fatal(err)
	}
	e.acct, _ = e.st.GetAccountByID(ctx, accts[0].ID)
}

// state is what the node supplies per call (node.state20's shape).
func (e *env20) state(ctx context.Context) (*State20, error) {
	rec, err := e.st.GetAccountByID(ctx, e.acct.ID)
	if err != nil {
		return nil, err
	}
	st := &State20{Protocol: int(rec.Protocol), Endpoint: endpointMe, AcceptNewHosts: rec.AcceptNewHosts, Accept1x: rec.Accept1x, SiblingKids: e.sibling}
	if st.Chain, err = e.m.Chain(ctx, rec.ID); err != nil {
		return nil, err
	}
	if st.Keys, err = e.m.ActiveLeafKeypairs(ctx, rec.ID, e.nowAt); err != nil {
		return nil, err
	}
	st.Former, _ = e.m.FormerKids(ctx, rec.ID)
	return st, nil
}

func (e *env20) currentKey(t *testing.T) *identity.Keypair {
	t.Helper()
	kp, err := e.id.Keypair(context.Background(), e.acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

type seal20Opt func(*pactidentity.SealOpts)

// seal20 seals a `v: 2` request from a peer to our current leaf key.
func (e *env20) seal20(t *testing.T, p *peer, form, tool string, args map[string]any, opts ...seal20Opt) *envelope.Envelope {
	t.Helper()
	kp := e.currentKey(t)
	spki, _ := identity.SPKI(kp)
	recipient, err := pactidentity.ParseSPKI(spki)
	if err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(map[string]any{"name": tool, "arguments": args})
	o := pactidentity.SealOpts{
		RecipientKey: recipient, Sender: p.host, Form: form, SenderChain: p.chain(), Method: "tools/call", Params: params,
		MsgID: "m-" + tool + "-" + form, TS: e.nowAt.Unix(), Exp: e.nowAt.Add(10 * time.Minute).Unix(),
	}
	for _, f := range opts {
		f(&o)
	}
	out, err := pactidentity.SealRequest(o)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	var wire envelope.Envelope
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	return &wire
}

func (e *env20) open(t *testing.T, env *envelope.Envelope, tf TransportFacts) (*EnvelopeFacts, error) {
	t.Helper()
	return e.id.OpenSealed(context.Background(), e.acct.ID, e.acct.Fingerprint, tf, env, DeliveryDirect)
}

// pin records a 2.0 contact as a first chain would have.
func (e *env20) pin(t *testing.T, p *peer, status string) {
	t.Helper()
	leaf, _ := pactidentity.Parse(p.leaf)
	if _, err := e.st.InsertContact(context.Background(), store.Contact{
		AccountID: e.acct.ID, Fingerprint: p.fpr(), SPKI: leaf.SPKI, Status: status, Permissions: []string{"message.text"},
		Protocol: 2, Endpoint: leaf.URIs[0], Leaf: p.leaf, Card: contacts.BuildCard20("Alina Rao", p.leaf, "required"),
	}); err != nil {
		t.Fatal(err)
	}
}

func card20(p *peer) string { return contacts.BuildCard20("Alina Rao", p.leaf, "required") }

func TestV2FirstContactMustRedeemOrRequest(t *testing.T) {
	e := newEnv20(t)
	p := newPeer(t, fixedNow)
	_, err := e.open(t, e.seal20(t, p, "chain", "send_message", map[string]any{"text": "hi"}), TransportFacts{})
	if err == nil || Code(err) != "envelope_invalid" || !strings.Contains(err.Error(), "guest may only redeem or request") {
		t.Fatalf("a stranger's send_message: %v", err)
	}
	f, err := e.open(t, e.seal20(t, p, "chain", "request_contact", map[string]any{"card": card20(p), "note": "hi"}), TransportFacts{})
	if err != nil {
		t.Fatalf("a stranger's request_contact: %v", err)
	}
	leaf, _ := pactidentity.Parse(p.leaf)
	if !f.Guest || f.Tier != policy.TierGuest || f.From != p.fpr() || string(f.SPKI) != string(leaf.SPKI) || f.Endpoint != endpointA || f.Protocol != 2 || f.Card == "" || f.Demote {
		t.Fatalf("guest facts: %+v", f)
	}
	// The card must carry the chain's own leaf.
	other := newPeer(t, fixedNow)
	_, err = e.open(t, e.seal20(t, p, "chain", "request_contact", map[string]any{"card": card20(other)}), TransportFacts{})
	if err == nil || !strings.Contains(err.Error(), "guest card certificate is not the chain's leaf") {
		t.Fatalf("a card carrying another leaf: %v", err)
	}
}

func TestV2PinnedContactBothForms(t *testing.T) {
	e := newEnv20(t)
	p := newPeer(t, fixedNow)
	e.pin(t, p, "active")
	f, err := e.open(t, e.seal20(t, p, "chain", "send_message", map[string]any{"text": "hi"}), TransportFacts{})
	if err != nil || f.Tier != policy.TierContact || f.From != p.fpr() || f.Form != "chain" || f.Guest {
		t.Fatalf("full form from a contact: %v %+v", err, f)
	}
	f, err = e.open(t, e.seal20(t, p, "leaf", "send_message", map[string]any{"text": "hi"}), TransportFacts{})
	if err != nil || f.Tier != policy.TierContact || f.From != p.fpr() || f.Form != "leaf" || f.Endpoint != endpointA {
		t.Fatalf("small form from a contact: %v %+v", err, f)
	}
	// Both proofs present: a client certificate for another key is refused.
	if _, err := e.open(t, e.seal20(t, p, "leaf", "send_message", nil), TransportFacts{ClientCertFingerprint: "sha256:x", ClientCertSPKI: []byte{1, 2, 3}}); err == nil || !strings.Contains(err.Error(), "does not match the envelope's leaf") {
		t.Fatalf("unified identity rule: %v", err)
	}
}

func TestV2SmallFormUnknownBlockedAndBadSignatureAreOneAnswer(t *testing.T) {
	e := newEnv20(t)
	stranger := newPeer(t, fixedNow)
	if _, err := e.open(t, e.seal20(t, stranger, "leaf", "send_message", nil), TransportFacts{}); !errors.Is(err, ErrChainRequired) {
		t.Fatalf("unknown small form: %v", err)
	}
	blocked := newPeer(t, fixedNow)
	e.pin(t, blocked, "blocked")
	if _, err := e.open(t, e.seal20(t, blocked, "leaf", "send_message", nil), TransportFacts{}); !errors.Is(err, ErrChainRequired) {
		t.Fatalf("blocked small form: %v", err)
	}
	// A contact whose held leaf has expired: the small form darkens with it.
	old := newPeer(t, fixedNow.Add(-400*24*time.Hour))
	e.pin(t, old, "active")
	if _, err := e.open(t, e.seal20(t, old, "leaf", "send_message", nil), TransportFacts{}); !errors.Is(err, ErrChainRequired) {
		t.Fatalf("expired held leaf: %v", err)
	}
	// A blocked contact's chain is a guest's (silently).
	f, err := e.open(t, e.seal20(t, blocked, "chain", "request_contact", map[string]any{"card": card20(blocked)}), TransportFacts{})
	if err != nil || f.Tier != policy.TierGuest || !f.Demote || f.Why != "blocked" {
		t.Fatalf("blocked full form: %v %+v", err, f)
	}
}

func TestV2StaleKidIsAnsweredWithTheCurrentChain(t *testing.T) {
	e := newEnv20(t)
	p := newPeer(t, fixedNow)
	e.pin(t, p, "active")
	oldKey := e.currentKey(t)
	// Seal to today's key, then renew: the superseded key still opens.
	env := e.seal20(t, p, "leaf", "send_message", nil)
	e.nowAt = fixedNow.Add(time.Hour)
	e.install(t, identity.PurposeRenew, endpointMe)
	if e.currentKey(t).Fingerprint == oldKey.Fingerprint {
		t.Fatal("a renewal must carry a fresh key")
	}
	e.nowAt = fixedNow
	if f, err := e.open(t, env, TransportFacts{}); err != nil || f.Tier != policy.TierContact {
		t.Fatalf("an envelope to the superseded key: %v %+v", err, f)
	}
	// Past the old leaf's notAfter the key is gone; the kid is remembered.
	e.nowAt = fixedNow.Add(400 * 24 * time.Hour)
	_, err := e.open(t, env, TransportFacts{})
	var renewed *CertificateRenewed
	if !errors.As(err, &renewed) {
		t.Fatalf("stale kid: %v", err)
	}
	chain, _ := e.m.Chain(context.Background(), e.acct.ID)
	if len(renewed.Chain) != 2 || string(renewed.Chain[0]) != string(chain[0]) || string(renewed.Chain[1]) != string(chain[1]) {
		t.Fatal("certificate_renewed must carry the current chain")
	}
	// A kid held for another identity on this origin is never answered with a chain.
	e.sibling = []string{oldKey.Fingerprint}
	if _, err := e.open(t, env, TransportFacts{}); err == nil || !strings.Contains(err.Error(), "held for another identity") {
		t.Fatalf("sibling kid: %v", err)
	}
}

func TestV2NewestLeafWinsAndNewAddresses(t *testing.T) {
	e := newEnv20(t)
	ctx := context.Background()
	p := newPeer(t, fixedNow)
	e.pin(t, p, "active")

	// A renewal at the pinned endpoint replaces the pin on the way through.
	newer := &peer{root: p.root, host: p.host}
	newer.leaf = newer.leafFor(t, endpointA, fixedNow.Add(-30*time.Minute))
	f, err := e.open(t, e.seal20(t, newer, "chain", "send_message", nil), TransportFacts{})
	if err != nil || f.Tier != policy.TierContact {
		t.Fatalf("renewal: %v %+v", err, f)
	}
	if c, _ := e.st.GetContact(ctx, e.acct.ID, p.fpr()); string(c.Leaf) != string(newer.leaf) {
		t.Fatal("the pin did not follow the newer leaf")
	}
	// The older leaf now proves nothing: a guest, whatever its validity (§14.3).
	f, err = e.open(t, e.seal20(t, p, "chain", "request_contact", map[string]any{"card": card20(p)}), TransportFacts{})
	if err != nil || f.Tier != policy.TierGuest || !f.Demote || f.Why != "superseded leaf" {
		t.Fatalf("superseded leaf: %v %+v", err, f)
	}
	// Equal notBefore, different bytes: refused.
	twin := &peer{root: p.root, host: p.host}
	twin.leaf = twin.leafFor(t, endpointA, fixedNow.Add(-30*time.Minute))
	if _, err := e.open(t, e.seal20(t, twin, "chain", "send_message", nil), TransportFacts{}); err == nil || !strings.Contains(err.Error(), "same notBefore") {
		t.Fatalf("conflict: %v", err)
	}

	// A newer leaf at another address under `auto`: re-pinned, and the event told.
	var events []string
	e.id.OnEvent = func(event, root, endpoint string) { events = append(events, event+"@"+endpoint) }
	moved := &peer{root: p.root, host: p.host}
	moved.leaf = moved.leafFor(t, endpointA2, fixedNow.Add(-15*time.Minute))
	f, err = e.open(t, e.seal20(t, moved, "chain", "send_message", nil), TransportFacts{})
	if err != nil || f.Tier != policy.TierContact || f.Endpoint != endpointA2 {
		t.Fatalf("new address under auto: %v %+v", err, f)
	}
	if c, _ := e.st.GetContact(ctx, e.acct.ID, p.fpr()); c.Endpoint != endpointA2 || string(c.Leaf) != string(moved.leaf) {
		t.Fatalf("the pin did not move: %+v", c)
	}
	if fe, _ := e.st.ListFormerEndpoints(ctx, e.acct.ID); len(fe) != 1 || fe[0].Endpoint != endpointA {
		t.Fatalf("the former endpoint was not remembered: %+v", fe)
	}
	if len(events) != 1 || events[0] != "new_address@"+endpointA2 {
		t.Fatalf("events: %v", events)
	}
	// A stranger at that former address is shown beside the contact's name.
	squatter := newPeer(t, fixedNow)
	f, err = e.open(t, e.seal20(t, squatter, "chain", "request_contact", map[string]any{"card": card20(squatter)}), TransportFacts{})
	if err != nil || f.AddressClaim != p.fpr() {
		t.Fatalf("address claim: %v %+v", err, f)
	}

	// Under `ask` the move waits for the owner; every other call is pending.
	if err := e.st.SetAccountHostPolicy(ctx, e.acct.ID, "ask", true); err != nil {
		t.Fatal(err)
	}
	var pendings []string
	e.id.OnPending = func(root, endpoint, why string) { pendings = append(pendings, why) }
	back := &peer{root: p.root, host: p.host}
	back.leaf = back.leafFor(t, endpointA, fixedNow.Add(-5*time.Minute))
	f, err = e.open(t, e.seal20(t, back, "chain", "update_contact", map[string]any{"card": card20(back)}), TransportFacts{})
	if err != nil || f.Tier != TierPendingAddress {
		t.Fatalf("new address under ask: %v %+v", err, f)
	}
	if ps, _ := e.st.ListPendingAddresses(ctx, e.acct.ID); len(ps) != 1 || ps[0].Endpoint != endpointA || ps[0].Why != "ask" || len(pendings) != 1 {
		t.Fatalf("pending address: %+v %v", ps, pendings)
	}
	if c, _ := e.st.GetContact(ctx, e.acct.ID, p.fpr()); c.Endpoint != endpointA2 {
		t.Fatal("under ask the pin must not move until the owner answers")
	}
	// The owner approves: the pin moves, as auto would have.
	cm := &contacts.Manager{Store: e.st}
	if _, err := cm.DecideAddress(ctx, e.acct.ID, p.fpr(), true); err != nil {
		t.Fatal(err)
	}
	if c, _ := e.st.GetContact(ctx, e.acct.ID, p.fpr()); c.Endpoint != endpointA || string(c.Leaf) != string(back.leaf) {
		t.Fatalf("approval did not re-pin: %+v", c)
	}
}

func TestV2TombstoneForcesTheQuestion(t *testing.T) {
	e := newEnv20(t)
	ctx := context.Background()
	p := newPeer(t, fixedNow)
	e.pin(t, p, "active")
	cm := &contacts.Manager{Store: e.st}
	if err := cm.RemoveContact(ctx, e.acct.ID, p.fpr()); err != nil {
		t.Fatal(err)
	}
	if ts, _ := e.st.ListTombstones(ctx, e.acct.ID); len(ts) != 1 {
		t.Fatal("removing a 2.0 contact must leave a tombstone")
	}
	// The same leaf again: a stranger (its leaf is not newer than the one that removed us).
	f, err := e.open(t, e.seal20(t, p, "chain", "request_contact", map[string]any{"card": card20(p)}), TransportFacts{})
	if err != nil || f.Tier != policy.TierGuest {
		t.Fatalf("same leaf after removal: %v %+v", err, f)
	}
	// A newer leaf inside 30 days: asked about, whatever the setting says.
	returned := &peer{root: p.root, host: p.host}
	returned.leaf = returned.leafFor(t, endpointA, fixedNow)
	f, err = e.open(t, e.seal20(t, returned, "chain", "request_contact", map[string]any{"card": card20(returned)}), TransportFacts{})
	if err != nil || f.Tier != TierPendingAddress {
		t.Fatalf("returned after removal: %v %+v", err, f)
	}
	if ps, _ := e.st.ListPendingAddresses(ctx, e.acct.ID); len(ps) != 1 || ps[0].Why != "returned after removal" {
		t.Fatalf("pending: %+v", ps)
	}
	if _, err := cm.DecideAddress(ctx, e.acct.ID, p.fpr(), true); err != nil {
		t.Fatal(err)
	}
	if c, err := e.st.GetContact(ctx, e.acct.ID, p.fpr()); err != nil || c.Status != "active" || c.Protocol != 2 {
		t.Fatalf("approving a returned root re-adds it: %v %+v", err, c)
	}
}

func TestV2LegacyPinUpgradesOnTheFirstChain(t *testing.T) {
	e := newEnv20(t)
	ctx := context.Background()
	p := newPeer(t, fixedNow)
	// A 1.x pin of the peer's LEAF key, as a 1.2 node would hold it.
	leaf, _ := pactidentity.Parse(p.leaf)
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acct.ID, Fingerprint: pactidentity.Fingerprint(leaf.SPKI), SPKI: leaf.SPKI, Status: "active", Permissions: []string{"message.text"}}); err != nil {
		t.Fatal(err)
	}
	f, err := e.open(t, e.seal20(t, p, "chain", "send_message", nil), TransportFacts{})
	if err != nil || f.Tier != policy.TierContact || f.From != p.fpr() {
		t.Fatalf("a chain whose leaf key is a 1.x pin: %v %+v", err, f)
	}
	c, err := e.st.GetContact(ctx, e.acct.ID, p.fpr())
	if err != nil || c.Protocol != 2 || c.Endpoint != endpointA || c.Status != "active" {
		t.Fatalf("the pin was not upgraded: %v %+v", err, c)
	}
}

func TestV1StillServedUntilTheOwnerSaysNot(t *testing.T) {
	e := newEnv20(t)
	ctx := context.Background()
	// A 1.x guest sealing to our leaf key, as 1.2 defines it.
	g, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	me := e.currentKey(t)
	spk := b64u(spkiOf(t, g))
	seal := func() *envelope.Envelope {
		env, err := envelope.Seal(envelope.SealParams{
			Sender: g, RecipientPub: me.Signer.Public(), To: me.Fingerprint, MsgID: "v1", TS: fixedNow.Unix(), Exp: fixedNow.Add(time.Hour).Unix(), CTY: envelope.CTYCall,
		}, payload(t, "tools/call", "redeem_invite", cardFor(g.Fingerprint), spk))
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	f, err := e.open(t, seal(), TransportFacts{})
	if err != nil || !f.Guest || f.From != g.Fingerprint || f.Protocol != 0 {
		t.Fatalf("a 1.x envelope to a 2.0 node: %v %+v", err, f)
	}
	if err := e.st.SetAccountHostPolicy(ctx, e.acct.ID, "auto", false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.open(t, seal(), TransportFacts{}); err == nil || !strings.Contains(err.Error(), "no longer accepts 1.x") {
		t.Fatalf("1.x refused once accept_1x is off: %v", err)
	}
}

func TestV2TransportPinChecks(t *testing.T) {
	// The transport path — a chain as the client certificate — resolves a 2.0
	// caller through the same pin checks as the sealed path (PACT §2, §14.3,
	// §5.3), and what it resolves is what dispatch sees: the composed server's
	// identity, not the gate's discarded return value.
	e := newEnv20(t)
	ctx := context.Background()
	p := newPeer(t, fixedNow)
	leaf, _ := pactidentity.Parse(p.leaf)
	facts := func(l []byte) TransportFacts {
		c, _ := pactidentity.Parse(l)
		return TransportFacts{ClientCertFingerprint: p.fpr(), ClientCertSPKI: c.SPKI, ClientProtocol: 2, ClientLeaf: l, ClientEndpoint: c.URIs[0]}
	}
	e.id.Seal = core.SealOptional
	// Unpinned: the root is the caller, and the store makes it a guest.
	if tc := e.id.ResolveTransport(ctx, facts(p.leaf)); tc.Fingerprint != p.fpr() || tc.Demote || tc.Refusal != "" {
		t.Fatalf("stranger: %+v", tc)
	}
	e.pin(t, p, "active")
	if tc := e.id.ResolveTransport(ctx, facts(p.leaf)); tc.Fingerprint != p.fpr() || tc.Demote {
		t.Fatalf("contact: %+v", tc)
	}
	// A newer leaf at the pinned endpoint is a renewal, learned in passing.
	renewed := &peer{root: p.root, host: p.host}
	renewed.leaf = renewed.leafFor(t, endpointA, fixedNow)
	var events []string
	e.id.OnEvent = func(event, root, endpoint string) { events = append(events, event) }
	if tc := e.id.ResolveTransport(ctx, facts(renewed.leaf)); tc.Fingerprint != p.fpr() {
		t.Fatalf("renewal: %+v", tc)
	}
	if c, _ := e.st.GetContact(ctx, e.acct.ID, p.fpr()); string(c.Leaf) != string(renewed.leaf) || len(events) != 1 || events[0] != "renewal" {
		t.Fatalf("the renewal was not learned: %v", events)
	}
	// The superseded leaf now proves nothing: an anonymous guest, for tools/list
	// as for a call — the gate hands dispatch no identity at all.
	tc := e.id.ResolveTransport(ctx, facts(p.leaf))
	if tc.Fingerprint != "" || !tc.Demote {
		t.Fatalf("a superseded leaf on the transport path: %+v", tc)
	}
	if fpr, err := e.id.PlaintextGateCtx(WithTransportCaller(ctx, tc), facts(p.leaf), "send_message", true); err != nil || fpr != "" {
		t.Fatalf("gate for a superseded leaf: %q %v", fpr, err)
	}
	_ = leaf
	// Blocked: a stranger, indistinguishable from one.
	if err := e.st.UpdateContactStatus(ctx, e.acct.ID, p.fpr(), "blocked"); err != nil {
		t.Fatal(err)
	}
	if tc := e.id.ResolveTransport(ctx, facts(renewed.leaf)); tc.Fingerprint != "" || !tc.Demote {
		t.Fatalf("blocked: %+v", tc)
	}
	if err := e.st.UpdateContactStatus(ctx, e.acct.ID, p.fpr(), "active"); err != nil {
		t.Fatal(err)
	}
	// Another endpoint under auto: re-pinned, the former endpoint kept, the owner told.
	moved := &peer{root: p.root, host: p.host}
	moved.leaf = moved.leafFor(t, endpointA2, fixedNow.Add(time.Minute))
	events = nil
	if tc := e.id.ResolveTransport(ctx, facts(moved.leaf)); tc.Fingerprint != p.fpr() || tc.Demote {
		t.Fatalf("move under auto: %+v", tc)
	}
	if c, _ := e.st.GetContact(ctx, e.acct.ID, p.fpr()); c.Endpoint != endpointA2 || string(c.Leaf) != string(moved.leaf) {
		t.Fatalf("not re-pinned: %+v", c)
	}
	if fe, _ := e.st.ListFormerEndpoints(ctx, e.acct.ID); len(fe) != 1 || fe[0].Endpoint != endpointA || len(events) != 1 || events[0] != "new_address" {
		t.Fatalf("former endpoint / event: %+v %v", fe, events)
	}
	// Another endpoint under ask: parked, nothing runs, update_contact answers pending.
	if err := e.st.SetAccountHostPolicy(ctx, e.acct.ID, "ask", true); err != nil {
		t.Fatal(err)
	}
	back := &peer{root: p.root, host: p.host}
	back.leaf = back.leafFor(t, endpointA, fixedNow.Add(2*time.Minute))
	tc = e.id.ResolveTransport(ctx, facts(back.leaf))
	if tc.Fingerprint != "" || !tc.Demote || tc.Refusal != "pending_approval" {
		t.Fatalf("move under ask: %+v", tc)
	}
	if ps, _ := e.st.ListPendingAddresses(ctx, e.acct.ID); len(ps) != 1 || ps[0].Endpoint != endpointA || ps[0].Why != "ask" {
		t.Fatalf("pending: %+v", ps)
	}
	if c, _ := e.st.GetContact(ctx, e.acct.ID, p.fpr()); c.Endpoint != endpointA2 {
		t.Fatal("under ask the pin must not move")
	}
	gctx := WithTransportCaller(ctx, tc)
	if _, err := e.id.PlaintextGateCtx(gctx, facts(back.leaf), "send_message", true); !errors.Is(err, ErrPendingApproval) {
		t.Fatalf("a call from the unapproved address: %v", err)
	}
	if _, err := e.id.PlaintextGateCtx(gctx, facts(back.leaf), "update_contact", true); !errors.Is(err, ErrPendingStatus) {
		t.Fatalf("update_contact from the unapproved address: %v", err)
	}
	// After a removal, a newer leaf within the window is asked about whatever the setting.
	if err := e.st.SetAccountHostPolicy(ctx, e.acct.ID, "auto", true); err != nil {
		t.Fatal(err)
	}
	if err := e.st.DeletePendingAddress(ctx, e.acct.ID, p.fpr()); err != nil {
		t.Fatal(err)
	}
	cm := &contacts.Manager{Store: e.st}
	if err := cm.RemoveContact(ctx, e.acct.ID, p.fpr()); err != nil {
		t.Fatal(err)
	}
	e.pin(t, p, "active") // the owner re-adds the old pin; the tombstone stands
	returned := &peer{root: p.root, host: p.host}
	returned.leaf = returned.leafFor(t, endpointA2, fixedNow.Add(3*time.Minute))
	if tc := e.id.ResolveTransport(ctx, facts(returned.leaf)); tc.Refusal != "pending_approval" {
		t.Fatalf("returned after removal: %+v", tc)
	}
	if ps, _ := e.st.ListPendingAddresses(ctx, e.acct.ID); len(ps) != 1 || ps[0].Why != "returned after removal" {
		t.Fatalf("tombstone pending: %+v", ps)
	}
}

func TestV2TransportUpgradesALegacyPinAtTheLeafsEndpoint(t *testing.T) {
	// Appendix C row 6 on the transport path: the endpoint pinned is the one
	// the leaf names, so the next resolution is the contact's, not a move.
	e := newEnv20(t)
	ctx := context.Background()
	p := newPeer(t, fixedNow)
	leaf, _ := pactidentity.Parse(p.leaf)
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acct.ID, Fingerprint: pactidentity.Fingerprint(leaf.SPKI), SPKI: leaf.SPKI, Status: "active", Permissions: []string{"message.text"}}); err != nil {
		t.Fatal(err)
	}
	tf := TransportFacts{ClientCertFingerprint: p.fpr(), ClientCertSPKI: leaf.SPKI, ClientProtocol: 2, ClientLeaf: p.leaf, ClientEndpoint: endpointA}
	var events []string
	e.id.OnEvent = func(event, root, endpoint string) { events = append(events, event) }
	for i := 0; i < 2; i++ {
		if tc := e.id.ResolveTransport(ctx, tf); tc.Fingerprint != p.fpr() || tc.Demote || tc.Refusal != "" {
			t.Fatalf("resolution %d: %+v", i, tc)
		}
	}
	c, err := e.st.GetContact(ctx, e.acct.ID, p.fpr())
	if err != nil || c.Protocol != 2 || c.Endpoint != endpointA || string(c.Leaf) != string(p.leaf) {
		t.Fatalf("upgraded pin: %v %+v", err, c)
	}
	if ps, _ := e.st.ListPendingAddresses(ctx, e.acct.ID); len(ps) != 0 || len(events) != 0 {
		t.Fatalf("an upgrade is not a move: %+v %v", ps, events)
	}
}

func TestV2LegacyPinUpgradeIsNotAMove(t *testing.T) {
	// The sealed path's row 6: a 1.x pin met by a first chain carrying an
	// ordinary contact tool is upgraded at the leaf's own endpoint and the
	// call runs as the contact — no pending row, no new_address event.
	e := newEnv20(t)
	ctx := context.Background()
	p := newPeer(t, fixedNow)
	leaf, _ := pactidentity.Parse(p.leaf)
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acct.ID, Fingerprint: pactidentity.Fingerprint(leaf.SPKI), SPKI: leaf.SPKI, Status: "active", Permissions: []string{"message.text"}}); err != nil {
		t.Fatal(err)
	}
	var events, pendings []string
	e.id.OnEvent = func(event, root, endpoint string) { events = append(events, event) }
	e.id.OnPending = func(root, endpoint, why string) { pendings = append(pendings, why) }
	f, err := e.open(t, e.seal20(t, p, "chain", "send_message", map[string]any{"msg_id": "m", "text": "hi"}), TransportFacts{})
	if err != nil || f.Tier != policy.TierContact || f.From != p.fpr() {
		t.Fatalf("first chain after a 1.x pin: %v %+v", err, f)
	}
	if c, _ := e.st.GetContact(ctx, e.acct.ID, p.fpr()); c.Protocol != 2 || c.Endpoint != endpointA {
		t.Fatalf("upgraded pin: %+v", c)
	}
	if ps, _ := e.st.ListPendingAddresses(ctx, e.acct.ID); len(ps) != 0 || len(events) != 0 || len(pendings) != 0 {
		t.Fatalf("an upgrade is not a move: %+v %v %v", ps, events, pendings)
	}
	if fe, _ := e.st.ListFormerEndpoints(ctx, e.acct.ID); len(fe) != 0 {
		t.Fatalf("no former endpoint: %+v", fe)
	}
}
