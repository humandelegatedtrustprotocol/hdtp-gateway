package public

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/policy"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// HDTP 1.0 receiving (HDTP §13.3, §6.1, §5.3, §14.3, §14.4) against a node
// that has installed a wallet-issued leaf. The peers are built with the
// library — a root each, a leaf per address — exactly as a wallet would.

const (
	endpointMe = "https://me.example/a/me/mcp"
	endpointA  = "https://agent.alina.example/mcp"
	endpointA2 = "https://alina.batondeck.com/alina/mcp"
)

type recvEnv struct {
	st      store.Store
	dbPath  string // the SQLite file, for a test that writes what the store's API cannot
	m       *identity.Manager
	id      *Identifier
	acct    store.Account
	root    *testRoot // our own root, for renewals
	nowAt   time.Time
	sibling []string
}

type testRoot struct {
	key  *hdtpidentity.PrivateKey
	cert []byte
	fpr  string
}

func newTestRoot(t testing.TB, cn string, at time.Time) *testRoot {
	t.Helper()
	key, err := hdtpidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := hdtpidentity.BuildRoot(hdtpidentity.RootOpts{CN: cn, Key: key, NotBefore: at.Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return &testRoot{key: key, cert: cert, fpr: hdtpidentity.Fingerprint(key.Public().SPKI)}
}

// peer is an identity elsewhere: a root and the host key of its current leaf.
type peer struct {
	root *testRoot
	host *hdtpidentity.PrivateKey
	leaf []byte
}

func (p *peer) chain() [][]byte { return [][]byte{p.leaf, p.root.cert} }
func (p *peer) fpr() string     { return p.root.fpr }

// leafFor issues a leaf under the peer's root for an endpoint, dated from `at`.
func (p *peer) leafFor(t testing.TB, endpoint string, at time.Time) []byte {
	t.Helper()
	der, err := hdtpidentity.BuildLeaf(hdtpidentity.LeafOpts{
		CN: "Alina Rao", RootCN: "Alina Rao", RootKey: p.root.key, HostPub: p.host.Public(), Endpoint: endpoint,
		NotBefore: at, NotAfter: at.Add(365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func newPeer(t testing.TB, at time.Time) *peer {
	t.Helper()
	host, err := hdtpidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	p := &peer{root: newTestRoot(t, "Alina Rao", at), host: host}
	p.leaf = p.leafFor(t, endpointA, at.Add(-time.Hour))
	return p
}

func newRecvEnv(t testing.TB) *recvEnv {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "recv.db")
	st, err := store.OpenSQLite(dbPath)
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
	e := &recvEnv{st: st, dbPath: dbPath, m: m, nowAt: fixedNow, root: newTestRoot(t, "Me", fixedNow)}
	e.install(t, identity.PurposeSignup, endpointMe)
	e.acct, _ = st.GetAccountByID(ctx, a.ID)
	e.id = &Identifier{
		Store: st, AccountID: a.ID,
		Seal: core.SealRequired, Cert: core.ClientCertPreferred,
		Now:            func() time.Time { return e.nowAt },
		RecipientState: func(ctx context.Context) (*RecipientState, error) { return e.state(ctx) },
	}
	return e
}

// install runs the CSR round trip of HDTP §9 for our account under our root.
func (e *recvEnv) install(t testing.TB, purpose, endpoint string) {
	t.Helper()
	ctx := context.Background()
	accts, _ := e.st.ListAccounts(ctx)
	csr, err := e.m.IssueCSR(ctx, accts[0].ID, purpose, endpoint, e.nowAt)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := hdtpidentity.IssueFromCSR(csr.CSR, hdtpidentity.IssueOpts{
		Root: testid.Root(t, e.root.cert), RootKey: e.root.key, RootSPKIs: [][]byte{e.root.key.Public().SPKI}, Now: e.nowAt,
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

// state is what the node supplies per call (node.recipientState's shape).
func (e *recvEnv) state(ctx context.Context) (*RecipientState, error) {
	rec, err := e.st.GetAccountByID(ctx, e.acct.ID)
	if err != nil {
		return nil, err
	}
	st := &RecipientState{HasRoot: rec.HasRoot(), Endpoint: endpointMe, AcceptNewHosts: rec.AcceptNewHosts, SiblingKids: e.sibling}
	if st.Chain, err = e.m.Chain(ctx, rec.ID); err != nil {
		return nil, err
	}
	if st.Keys, err = e.m.ActiveLeafKeypairs(ctx, rec.ID, e.nowAt); err != nil {
		return nil, err
	}
	st.Former, _ = e.m.FormerKids(ctx, rec.ID, e.nowAt)
	return st, nil
}

// keypair is the account's current leaf key. The tests used to fetch it through
// `Identifier.Keypair`, a field production code set and never read — it outlived the path
// that recorded a re-pinned contact's key on connect.
func (e *recvEnv) keypair(ctx context.Context) (*identity.Keypair, error) {
	keys, err := e.m.ActiveLeafKeypairs(ctx, e.acct.ID, e.nowAt)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("test env: the account holds no live leaf key")
	}
	return keys[0].KP, nil
}

func (e *recvEnv) currentKey(t testing.TB) *identity.Keypair {
	t.Helper()
	kp, err := e.keypair(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

type sealOpt func(*hdtpidentity.SealOpts)

// sealFrom seals a `v: 1` request from a peer to our current leaf key.
func (e *recvEnv) sealFrom(t testing.TB, p *peer, form, tool string, args map[string]any, opts ...sealOpt) *hdtpidentity.Envelope {
	t.Helper()
	kp := e.currentKey(t)
	spki, _ := x509.MarshalPKIXPublicKey(kp.Signer.Public())
	recipient, err := hdtpidentity.ParseSPKI(spki)
	if err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(map[string]any{"name": tool, "arguments": args})
	o := hdtpidentity.SealOpts{
		RecipientKey: recipient, Sender: p.host, Form: form, SenderChain: p.chain(), Method: "tools/call", Params: params,
		MsgID: "m-" + tool + "-" + form, TS: e.nowAt.Unix(), Exp: e.nowAt.Add(10 * time.Minute).Unix(),
	}
	for _, f := range opts {
		f(&o)
	}
	out, err := hdtpidentity.SealRequest(o)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *recvEnv) open(t testing.TB, env *hdtpidentity.Envelope, tf TransportFacts) (*EnvelopeFacts, error) {
	t.Helper()
	return e.id.OpenSealed(context.Background(), e.acct.ID, tf, env)
}

// pin records a contact as a first chain would have.
func (e *recvEnv) pin(t testing.TB, p *peer, status string) {
	t.Helper()
	leaf, _ := hdtpidentity.Parse(p.leaf)
	if _, err := e.st.InsertContact(context.Background(), store.Contact{
		AccountID: e.acct.ID, Fingerprint: p.fpr(), SPKI: leaf.SPKI, Status: status, Permissions: []string{"message.text"},
		Endpoint: leaf.URIs[0], Leaf: p.leaf, Card: cardOf(p),
	}); err != nil {
		t.Fatal(err)
	}
}

func cardOf(p *peer) string {
	card, err := contacts.BuildCard("Alina Rao", p.leaf, "required")
	if err != nil {
		panic(err)
	}
	return card
}

func TestFirstContactMustRedeemOrRequest(t *testing.T) {
	e := newRecvEnv(t)
	p := newPeer(t, fixedNow)
	_, err := e.open(t, e.sealFrom(t, p, "chain", "send_message", map[string]any{"text": "hi"}), TransportFacts{})
	if err == nil || Code(err) != "envelope_invalid" || !strings.Contains(err.Error(), "guest may only redeem or request") {
		t.Fatalf("a stranger's send_message: %v", err)
	}
	f, err := e.open(t, e.sealFrom(t, p, "chain", "request_contact", map[string]any{"card": cardOf(p), "note": "hi"}), TransportFacts{})
	if err != nil {
		t.Fatalf("a stranger's request_contact: %v", err)
	}
	leaf, _ := hdtpidentity.Parse(p.leaf)
	if !f.Guest || f.Tier != policy.TierGuest || f.From != p.fpr() || string(f.SPKI) != string(leaf.SPKI) || f.Endpoint != endpointA || len(f.Leaf) == 0 || f.Card == "" || f.Demote {
		t.Fatalf("guest facts: %+v", f)
	}
	// The card must carry the chain's own leaf.
	other := newPeer(t, fixedNow)
	_, err = e.open(t, e.sealFrom(t, p, "chain", "request_contact", map[string]any{"card": cardOf(other)}), TransportFacts{})
	if err == nil || !strings.Contains(err.Error(), "guest card certificate is not the chain's leaf") {
		t.Fatalf("a card carrying another leaf: %v", err)
	}
}

// A pin this node cannot read is the node's problem, and it is said. The Go port used to step over
// the row and answer `chain_required` as if nothing were wrong, and nothing anywhere recorded that a
// row of the contact book had gone bad — so the contact whose row it was became a stranger for good.
// Decide is handed only the pins a call's proof concerns (pinsFor), so the bad row here is one the
// call names: its fingerprint is the sender's leaf's, and its leaf bytes are not a certificate.
func TestAPinThatWillNotReadIsSaidNotSteppedOver(t *testing.T) {
	e := newRecvEnv(t)
	var rows []string
	e.id.Audit = func(action, resource, outcome string) { rows = append(rows, action+" "+resource+" "+outcome) }
	p := newPeer(t, fixedNow)
	named, _ := hdtpidentity.Parse(p.leaf)
	if _, err := e.st.InsertContact(context.Background(), store.Contact{
		AccountID: e.acct.ID, Fingerprint: "sha256:a-row-gone-bad", Status: "active", Permissions: []string{"message.text"},
		Endpoint: "https://ghost.example/mcp", Leaf: []byte{0x30, 0x03, 0x01, 0x02, 0x03}, SPKI: named.SPKI,
	}); err != nil {
		t.Fatal(err)
	}

	_, err := e.open(t, e.sealFrom(t, p, "leaf", "send_message", map[string]any{"text": "hi"}), TransportFacts{})
	if err == nil || Code(err) != "envelope_invalid" || !strings.Contains(err.Error(), "recipient state unavailable") {
		t.Fatalf("an unreadable pin must refuse the call as state that could not be loaded, got: %v", err)
	}
	if errors.Is(err, ErrChainRequired) {
		t.Fatal("the sender was answered chain_required: the unreadable row was stepped over")
	}
	found := false
	for _, r := range rows {
		found = found || (strings.HasPrefix(r, "identity_state_unreadable account:"+e.acct.ID) && strings.HasSuffix(r, " error"))
	}
	if !found {
		t.Fatalf("the owner was not told: %v", rows)
	}
}

func TestPinnedContactBothForms(t *testing.T) {
	e := newRecvEnv(t)
	p := newPeer(t, fixedNow)
	e.pin(t, p, "active")
	f, err := e.open(t, e.sealFrom(t, p, "chain", "send_message", map[string]any{"text": "hi"}), TransportFacts{})
	if err != nil || f.Tier != policy.TierContact || f.From != p.fpr() || f.Form != "chain" || f.Guest {
		t.Fatalf("full form from a contact: %v %+v", err, f)
	}
	f, err = e.open(t, e.sealFrom(t, p, "leaf", "send_message", map[string]any{"text": "hi"}), TransportFacts{})
	if err != nil || f.Tier != policy.TierContact || f.From != p.fpr() || f.Form != "leaf" || f.Endpoint != endpointA {
		t.Fatalf("small form from a contact: %v %+v", err, f)
	}
	// Both proofs present: a client certificate for another key is refused.
	if _, err := e.open(t, e.sealFrom(t, p, "leaf", "send_message", nil), TransportFacts{ClientCertFingerprint: "sha256:x", ClientCertSPKI: []byte{1, 2, 3}}); err == nil || !strings.Contains(err.Error(), "does not match the envelope's leaf") {
		t.Fatalf("unified identity rule: %v", err)
	}
}

func TestSmallFormUnknownBlockedAndBadSignatureAreOneAnswer(t *testing.T) {
	e := newRecvEnv(t)
	stranger := newPeer(t, fixedNow)
	if _, err := e.open(t, e.sealFrom(t, stranger, "leaf", "send_message", nil), TransportFacts{}); !errors.Is(err, ErrChainRequired) {
		t.Fatalf("unknown small form: %v", err)
	}
	blocked := newPeer(t, fixedNow)
	e.pin(t, blocked, "blocked")
	if _, err := e.open(t, e.sealFrom(t, blocked, "leaf", "send_message", nil), TransportFacts{}); !errors.Is(err, ErrChainRequired) {
		t.Fatalf("blocked small form: %v", err)
	}
	// A contact whose held leaf has expired: the small form darkens with it.
	old := newPeer(t, fixedNow.Add(-400*24*time.Hour))
	e.pin(t, old, "active")
	if _, err := e.open(t, e.sealFrom(t, old, "leaf", "send_message", nil), TransportFacts{}); !errors.Is(err, ErrChainRequired) {
		t.Fatalf("expired held leaf: %v", err)
	}
	// A blocked contact's chain is a guest's (silently).
	f, err := e.open(t, e.sealFrom(t, blocked, "chain", "request_contact", map[string]any{"card": cardOf(blocked)}), TransportFacts{})
	if err != nil || f.Tier != policy.TierGuest || !f.Demote || f.Why != "blocked" {
		t.Fatalf("blocked full form: %v %+v", err, f)
	}
}

func TestStaleKidIsAnsweredWithTheCurrentChain(t *testing.T) {
	e := newRecvEnv(t)
	p := newPeer(t, fixedNow)
	e.pin(t, p, "active")
	oldKey := e.currentKey(t)
	// Seal to today's key, then renew: the superseded key still opens.
	env := e.sealFrom(t, p, "leaf", "send_message", nil)
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

func TestNewestLeafWinsAndNewAddresses(t *testing.T) {
	e := newRecvEnv(t)
	ctx := context.Background()
	p := newPeer(t, fixedNow)
	e.pin(t, p, "active")

	// A renewal at the pinned endpoint replaces the pin on the way through.
	newer := &peer{root: p.root, host: p.host}
	newer.leaf = newer.leafFor(t, endpointA, fixedNow.Add(-30*time.Minute))
	f, err := e.open(t, e.sealFrom(t, newer, "chain", "send_message", nil), TransportFacts{})
	if err != nil || f.Tier != policy.TierContact {
		t.Fatalf("renewal: %v %+v", err, f)
	}
	if c, _ := e.st.GetContact(ctx, e.acct.ID, p.fpr()); string(c.Leaf) != string(newer.leaf) {
		t.Fatal("the pin did not follow the newer leaf")
	}
	// The older leaf now proves nothing: a guest, whatever its validity (§14.3).
	f, err = e.open(t, e.sealFrom(t, p, "chain", "request_contact", map[string]any{"card": cardOf(p)}), TransportFacts{})
	if err != nil || f.Tier != policy.TierGuest || !f.Demote || f.Why != "superseded leaf" {
		t.Fatalf("superseded leaf: %v %+v", err, f)
	}
	if c, _ := e.st.GetContact(ctx, e.acct.ID, p.fpr()); string(c.Leaf) != string(newer.leaf) {
		t.Fatal("a superseded leaf must not roll the pin back")
	}
	// Equal notBefore, different bytes: refused.
	twin := &peer{root: p.root, host: p.host}
	twin.leaf = twin.leafFor(t, endpointA, fixedNow.Add(-30*time.Minute))
	if _, err := e.open(t, e.sealFrom(t, twin, "chain", "send_message", nil), TransportFacts{}); err == nil || !strings.Contains(err.Error(), "same notBefore") {
		t.Fatalf("conflict: %v", err)
	}

	// A newer leaf at another address under `auto`: re-pinned, and the event told.
	var events []string
	e.id.OnEvent = func(event, root, endpoint string) { events = append(events, event+"@"+endpoint) }
	moved := &peer{root: p.root, host: p.host}
	moved.leaf = moved.leafFor(t, endpointA2, fixedNow.Add(-15*time.Minute))
	f, err = e.open(t, e.sealFrom(t, moved, "chain", "send_message", nil), TransportFacts{})
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
	f, err = e.open(t, e.sealFrom(t, squatter, "chain", "request_contact", map[string]any{"card": cardOf(squatter)}), TransportFacts{})
	if err != nil || f.AddressClaim != p.fpr() {
		t.Fatalf("address claim: %v %+v", err, f)
	}

	// Under `ask` the move waits for the owner; every other call is pending.
	if err := e.st.SetAccountHostPolicy(ctx, e.acct.ID, "ask"); err != nil {
		t.Fatal(err)
	}
	var pendings []string
	e.id.OnPending = func(root, endpoint, why string) { pendings = append(pendings, why) }
	back := &peer{root: p.root, host: p.host}
	back.leaf = back.leafFor(t, endpointA, fixedNow.Add(-5*time.Minute))
	f, err = e.open(t, e.sealFrom(t, back, "chain", "update_contact", map[string]any{"card": cardOf(back)}), TransportFacts{})
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

// A renewal carries a fresh key (§2), so once the newer leaf is pinned the older leaf's key
// fingerprint names nothing this account holds for the contact: the small form is answered
// `chain_required`, as a stranger's is, and the only chain its holder can send is the superseded
// one, a guest's (§13.2, §14.3). This is the stolen-leaf-key case after the renewal has reached
// the contact — hdtp-spec's intrusion scenarios "stolen leaf key: after Alina renews, the small
// form naming the old leaf is asked for a chain, and the only chain it has is a guest's" and
// "stale sender: Mallory replays the superseded chain …", on the node — and neither form moves
// the pin.
func TestASupersededLeafNamedByFingerprintIsAskedForItsChain(t *testing.T) {
	e := newRecvEnv(t)
	ctx := context.Background()
	p := newPeer(t, fixedNow)
	e.pin(t, p, "active")
	// The control: before the renewal the small form names the pinned leaf and is the contact's.
	if f, err := e.open(t, e.sealFrom(t, p, "leaf", "send_message", nil), TransportFacts{}); err != nil || f.Tier != policy.TierContact {
		t.Fatalf("the small form before the renewal: %v %+v", err, f)
	}
	freshKey, err := hdtpidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	renewed := &peer{root: p.root, host: freshKey}
	renewed.leaf = renewed.leafFor(t, endpointA, fixedNow.Add(-30*time.Minute))
	if f, err := e.open(t, e.sealFrom(t, renewed, "chain", "send_message", nil), TransportFacts{}); err != nil || f.Tier != policy.TierContact {
		t.Fatalf("the renewal: %v %+v", err, f)
	}
	if c, _ := e.st.GetContact(ctx, e.acct.ID, p.fpr()); string(c.Leaf) != string(renewed.leaf) {
		t.Fatal("the pin did not follow the renewed leaf")
	}
	if _, err := e.open(t, e.sealFrom(t, p, "leaf", "send_message", nil), TransportFacts{}); !errors.Is(err, ErrChainRequired) {
		t.Fatalf("the small form naming the superseded leaf: %v; want chain_required", err)
	}
	f, err := e.open(t, e.sealFrom(t, p, "chain", "request_contact", map[string]any{"card": cardOf(p)}), TransportFacts{})
	if err != nil || f.Tier != policy.TierGuest || !f.Demote || f.Why != "superseded leaf" {
		t.Fatalf("the superseded chain: %v %+v", err, f)
	}
	if c, _ := e.st.GetContact(ctx, e.acct.ID, p.fpr()); string(c.Leaf) != string(renewed.leaf) {
		t.Fatal("neither form of the superseded leaf may roll the pin back")
	}
	// The renewed leaf, named by fingerprint, is the contact's: the key that changed is the one held.
	if f, err := e.open(t, e.sealFrom(t, renewed, "leaf", "send_message", nil), TransportFacts{}); err != nil || f.Tier != policy.TierContact {
		t.Fatalf("the small form naming the renewed leaf: %v %+v", err, f)
	}
}

// A caller from an address the owner has not approved is told once, however many
// times it calls. Every request used to append an audit-chain row and wake the
// owner: a host holding a still-valid leaf for a pinned root — a former host
// after a move — grew both without bound just by continuing to call.
func TestAnUnapprovedAddressIsToldOnce(t *testing.T) {
	e := newRecvEnv(t)
	ctx := context.Background()
	p := newPeer(t, fixedNow.Add(-time.Hour))
	e.pin(t, p, "active")
	if err := e.st.SetAccountHostPolicy(ctx, e.acct.ID, "ask"); err != nil {
		t.Fatal(err)
	}
	var pendings int
	e.id.OnPending = func(string, string, string) { pendings++ }

	moved := &peer{root: p.root, host: p.host}
	moved.leaf = moved.leafFor(t, endpointA2, fixedNow.Add(-5*time.Minute))
	for i := 0; i < 4; i++ {
		f, err := e.open(t, e.sealFrom(t, moved, "chain", "update_contact", map[string]any{"card": cardOf(moved)}), TransportFacts{})
		if err != nil || f.Tier != TierPendingAddress {
			t.Fatalf("call %d: %v %+v", i, err, f)
		}
	}
	if pendings != 1 {
		t.Fatalf("four calls from one unapproved address woke the owner %d times", pendings)
	}
	ps, _ := e.st.ListPendingAddresses(ctx, e.acct.ID)
	if len(ps) != 1 || ps[0].Endpoint != endpointA2 {
		t.Fatalf("one row, the latest state: %+v", ps)
	}
	// A DIFFERENT address from the same root is a new thing to be told about.
	third := &peer{root: p.root, host: p.host}
	third.leaf = third.leafFor(t, "https://alina.third.example/alina/mcp", fixedNow.Add(-4*time.Minute))
	if _, err := e.open(t, e.sealFrom(t, third, "chain", "update_contact", map[string]any{"card": cardOf(third)}), TransportFacts{}); err != nil {
		t.Fatal(err)
	}
	if pendings != 2 {
		t.Fatalf("a different address is a different question: woke %d times", pendings)
	}
}

func TestTombstoneForcesTheQuestion(t *testing.T) {
	e := newRecvEnv(t)
	ctx := context.Background()
	p := newPeer(t, fixedNow)
	e.pin(t, p, "active")
	cm := &contacts.Manager{Store: e.st}
	if err := cm.RemoveContact(ctx, e.acct.ID, p.fpr()); err != nil {
		t.Fatal(err)
	}
	if ts, _ := e.st.ListTombstones(ctx, e.acct.ID); len(ts) != 1 {
		t.Fatal("removing a contact must leave a tombstone")
	}
	// The same leaf again: a stranger (its leaf is not newer than the one that removed us).
	f, err := e.open(t, e.sealFrom(t, p, "chain", "request_contact", map[string]any{"card": cardOf(p)}), TransportFacts{})
	if err != nil || f.Tier != policy.TierGuest {
		t.Fatalf("same leaf after removal: %v %+v", err, f)
	}
	// A newer leaf inside 30 days: asked about, whatever the setting says.
	returned := &peer{root: p.root, host: p.host}
	returned.leaf = returned.leafFor(t, endpointA, fixedNow)
	f, err = e.open(t, e.sealFrom(t, returned, "chain", "request_contact", map[string]any{"card": cardOf(returned)}), TransportFacts{})
	if err != nil || f.Tier != TierPendingAddress {
		t.Fatalf("returned after removal: %v %+v", err, f)
	}
	if ps, _ := e.st.ListPendingAddresses(ctx, e.acct.ID); len(ps) != 1 || ps[0].Why != "returned after removal" {
		t.Fatalf("pending: %+v", ps)
	}
	if _, err := cm.DecideAddress(ctx, e.acct.ID, p.fpr(), true); err != nil {
		t.Fatal(err)
	}
	if c, err := e.st.GetContact(ctx, e.acct.ID, p.fpr()); err != nil || c.Status != "active" || len(c.Leaf) == 0 {
		t.Fatalf("approving a returned root re-adds it: %v %+v", err, c)
	}
}

func TestTransportPinChecks(t *testing.T) {
	// The transport path — a chain as the client certificate — resolves a
	// caller through the same pin checks as the sealed path (HDTP §2, §14.3,
	// §5.3), and what it resolves is what dispatch sees: the composed server's
	// identity, not the gate's discarded return value.
	e := newRecvEnv(t)
	ctx := context.Background()
	p := newPeer(t, fixedNow)
	leaf, _ := hdtpidentity.Parse(p.leaf)
	facts := func(l []byte) TransportFacts {
		c, _ := hdtpidentity.Parse(l)
		return TransportFacts{ClientCertFingerprint: p.fpr(), ClientCertSPKI: c.SPKI, ClientLeaf: l, ClientEndpoint: c.URIs[0]}
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
	if err := e.st.SetAccountHostPolicy(ctx, e.acct.ID, "ask"); err != nil {
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
	if err := e.st.SetAccountHostPolicy(ctx, e.acct.ID, "auto"); err != nil {
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

// respell rewrites one member of an envelope as it travels, leaving every other byte alone.
func respell(t *testing.T, env *hdtpidentity.Envelope, member string, fn func(string) string) *hdtpidentity.Envelope {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m[member] = fn(m[member])
	b, _ = json.Marshal(m)
	var out hdtpidentity.Envelope
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

// An envelope member has ONE spelling on the wire (HDTP §13.1): `sig` covers the DECODED bytes, so
// every other spelling a reader accepts is a second envelope that verifies. The core refuses a last
// character with its unused bits set and a line break inside a member. The node used to decode the
// members itself, leniently, and hand the core a canonical re-encoding — so the core's refusal never
// ran and the node opened both spellings. `enc` is 32 or 65 bytes, so its last character always has
// unused bits.
func TestAnEnvelopeMemberHasOneSpellingOnTheWire(t *testing.T) {
	e := newRecvEnv(t)
	p := newPeer(t, fixedNow)
	e.pin(t, p, "active")
	if f, err := e.open(t, e.sealFrom(t, p, "chain", "send_message", map[string]any{"text": "hi"}), TransportFacts{}); err != nil || f.From != p.fpr() {
		t.Fatalf("the control, in its canonical spelling, must open: %v %+v", err, f)
	}
	spare := func(s string) string {
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		last := strings.IndexByte(alphabet, s[len(s)-1])
		return s[:len(s)-1] + string(alphabet[last|1])
	}
	lineBreak := func(s string) string { return s[:8] + "\r\n" + s[8:] }
	for name, c := range map[string]struct {
		member string
		fn     func(string) string
	}{
		"enc with a spare bit set": {"enc", spare},
		"sig with a line break":    {"sig", lineBreak},
		"ct with a line break":     {"ct", lineBreak},
	} {
		env := respell(t, e.sealFrom(t, p, "chain", "send_message", map[string]any{"text": "hi"}), c.member, c.fn)
		if _, err := e.open(t, env, TransportFacts{}); Code(err) != "envelope_invalid" {
			t.Errorf("%s: opened (%v); a second spelling of an envelope must be refused", name, err)
		}
	}
}

// The core's pin has three states (CONTRACT `Pin`; the identity core 0.4.2 refuses any other as this
// node's unreadable state). A request the owner has not answered is handed to Decide as NO pin —
// what BatonDeck's `pinsOf` hands, the owner's decision of 2026-09-30 — so its requester is decided
// as the stranger SPEC §5.4 says it is: the small form names a leaf nobody pinned and is refused
// `chain_required`; the chain form is decided as a guest's and audited as one; and the effects
// Decide returns for an active pin — the newer leaf a chain carries, a new address under `auto` —
// reach no row the owner has not approved. The three states the core names go as themselves.
//
// Shown red with the mapping this replaced (`pending_in` handed as `active`): one pin, the small
// form `ok`, the actor `contact`, and the renewed leaf written onto the unanswered request.
func TestAPendingRequestIsHandedToDecideWithNoPin(t *testing.T) {
	ctx := context.Background()
	e := newRecvEnv(t)
	p := newPeer(t, fixedNow)
	e.pin(t, p, "pending_in")
	all, err := e.st.ListContacts(ctx, e.acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pins := pinsOf(all); len(pins) != 0 {
		t.Fatalf("a pending_in row was handed to Decide as a pin: %+v", pins)
	}
	for _, status := range []string{"active", "pending_out", "blocked"} {
		row := all[0]
		row.Status = status
		if pins := pinsOf([]store.Contact{row}); len(pins) != 1 || pins[0].Root != p.fpr() || pins[0].State != status {
			t.Fatalf("a %s row's pin: %+v", status, pins)
		}
	}
	// The small form: nothing here holds the leaf it names.
	_, err = e.open(t, e.sealFrom(t, p, "leaf", "request_contact", map[string]any{"card": cardOf(p)}), TransportFacts{})
	if Code(err) != "chain_required" {
		t.Fatalf("the small form from a requester the owner has not answered: %v; want chain_required, as the cloud answers it", err)
	}
	// The chain form: a guest, on the envelope's own proof, and audited as one.
	f, err := e.open(t, e.sealFrom(t, p, "chain", "request_contact", map[string]any{"card": cardOf(p)}), TransportFacts{})
	if err != nil || !f.Guest || f.Tier != policy.TierGuest || f.From != p.fpr() || f.Form != "chain" || f.Endpoint != endpointA || f.Demote {
		t.Fatalf("the chain form from a requester the owner has not answered: %v %+v", err, f)
	}
	if actor := actorOf(f); actor != "guest" {
		t.Fatalf("the audit row's actor for that requester: %q, want guest", actor)
	}
	// Decide's pin effects reach no unanswered request: a renewed leaf, then a leaf for a new
	// address under `auto` (the account's setting as made), each carried by a chain form, and the
	// row is as it was — no repin, no pending address for the owner to answer.
	before, err := e.st.GetContact(ctx, e.acct.ID, p.fpr())
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := e.st.GetAccountByID(ctx, e.acct.ID); a.AcceptNewHosts != "auto" {
		t.Fatalf("the account's new-host policy is %q; the case below needs auto", a.AcceptNewHosts)
	}
	for _, c := range []struct {
		name     string
		endpoint string
	}{{"renewed", endpointA}, {"moved", endpointA2}} {
		newer := &peer{root: p.root, host: p.host, leaf: p.leafFor(t, c.endpoint, fixedNow)}
		withID := func(o *hdtpidentity.SealOpts) { o.MsgID = "m-" + c.name }
		f, err := e.open(t, e.sealFrom(t, newer, "chain", "request_contact", map[string]any{"card": cardOf(newer)}, withID), TransportFacts{})
		if err != nil || !f.Guest || f.Endpoint != c.endpoint {
			t.Fatalf("the %s leaf's chain form from that requester: %v %+v", c.name, err, f)
		}
	}
	after, err := e.st.GetContact(ctx, e.acct.ID, p.fpr())
	if err != nil {
		t.Fatal(err)
	}
	if string(after.Leaf) != string(before.Leaf) || after.Endpoint != before.Endpoint || after.Status != before.Status || after.PinnedAt != before.PinnedAt {
		t.Fatalf("Decide's effects reached a request the owner has not answered:\n before %+v\n after  %+v", before, after)
	}
	if pending, _ := e.st.ListPendingAddresses(ctx, e.acct.ID); len(pending) != 0 {
		t.Fatalf("a new address was noted for a request the owner has not answered: %+v", pending)
	}
}

// forceContactStatus puts a contact in a state the store's own API cannot write: the schema holds
// a contact's status to the four (the schema's CHECK, both engines), so a row in any other
// state is a hand-edited store's, and this is that hand — raw SQL, in a test only, with the
// constraint switched off for the one connection that writes it.
func forceContactStatus(t testing.TB, dbPath, accountID, root, status string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)&_pragma=ignore_check_constraints(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE contacts SET status = ? WHERE account_id = ? AND fingerprint = ?`, status, accountID, root); err != nil {
		t.Fatal(err)
	}
}

// A contact row in a state this node does not know — neither a state a pin has nor a request
// awaiting the owner — is handed to Decide as no pin, as a request is: the store's probe still
// finds the row (PinCandidates), pinsOf leaves it out, its small form is `chain_required` and its
// chain form is decided as a stranger's, and no effect reaches the row. The store's own API
// cannot write such a row (the schema's CHECK refuses the move, shown first), so the test writes
// it as a hand-edited store would. UnknownContactState, the reading internal/storecheck counts
// by, is held to pinsOf here: true for that row's state, false for each state pinsOf hands over
// or leaves out as a request.
//
// Shown red with pinsOf's state filter removed (the mutation): the row is handed over as a pin in
// state frozen.
func TestARowInAStateThisNodeDoesNotKnowIsHandedToDecideAsNoPin(t *testing.T) {
	ctx := context.Background()
	e := newRecvEnv(t)
	p := newPeer(t, fixedNow)
	e.pin(t, p, "active")
	// The control: as an active contact, the row is one pin and the small form is decided on it.
	if f, err := e.open(t, e.sealFrom(t, p, "leaf", "send_message", map[string]any{"text": "hi"}), TransportFacts{}); err != nil || f.Tier != policy.TierContact {
		t.Fatalf("the control, an active contact's small form: %v %+v", err, f)
	}
	if err := e.st.UpdateContactStatus(ctx, e.acct.ID, p.fpr(), "frozen"); err == nil {
		t.Fatal("the store moved a contact to state frozen; the schema's CHECK admits only the four")
	}
	forceContactStatus(t, e.dbPath, e.acct.ID, p.fpr(), "frozen")
	leaf, _ := hdtpidentity.Parse(p.leaf)
	cands, err := e.st.PinCandidates(ctx, e.acct.ID, "", "", hdtpidentity.Fingerprint(leaf.SPKI))
	if err != nil || len(cands) != 1 || cands[0].Status != "frozen" {
		t.Fatalf("the store's probe for the leaf the small form names: %v %+v; want the row, in state frozen", err, cands)
	}
	if pins := pinsOf(cands); len(pins) != 0 {
		t.Fatalf("a row in state frozen was handed to Decide as a pin: %+v", pins)
	}
	for status, unknown := range map[string]bool{"active": false, "pending_out": false, "blocked": false, "pending_in": false, "frozen": true, "": true} {
		if UnknownContactState(status) != unknown {
			t.Errorf("UnknownContactState(%q) = %v, want %v", status, !unknown, unknown)
		}
	}
	withID := func(id string) sealOpt { return func(o *hdtpidentity.SealOpts) { o.MsgID = id } }
	_, err = e.open(t, e.sealFrom(t, p, "leaf", "send_message", map[string]any{"text": "hi"}, withID("m-frozen-leaf")), TransportFacts{})
	if Code(err) != "chain_required" {
		t.Fatalf("the small form from the row's holder: %v; want chain_required, as for a request the owner has not answered", err)
	}
	f, err := e.open(t, e.sealFrom(t, p, "chain", "request_contact", map[string]any{"card": cardOf(p)}, withID("m-frozen-chain")), TransportFacts{})
	if err != nil || !f.Guest || f.Tier != policy.TierGuest || f.From != p.fpr() || f.Form != "chain" {
		t.Fatalf("the chain form from the row's holder: %v %+v; want a stranger's", err, f)
	}
	if c, err := e.st.GetContact(ctx, e.acct.ID, p.fpr()); err != nil || c.Status != "frozen" || string(c.Leaf) != string(p.leaf) {
		t.Fatalf("an effect reached the row: %v %+v", err, c)
	}
}
