package integrationtest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/internalui"
	"github.com/pact-cloud/pact-gateway/internal/messaging"
	"github.com/pact-cloud/pact-gateway/internal/outbound"
	"github.com/pact-cloud/pact-gateway/internal/public"
	"github.com/pact-cloud/pact-gateway/internal/testid"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// node is a whole pact-gateway node in-process: store, identity, public TLS
// listener with the real per-caller server pool, the guest/contact tool set,
// sealed_call at every tier, and the invite landing page.
type pactNode struct {
	leafDER  []byte
	rootFpr  string
	rootCert []byte
	t        *testing.T
	st       store.Store
	acct     store.Account
	kp       *identity.Keypair
	cert     tls.Certificate
	cm       *contacts.Manager
	msg      *messaging.Service
	pool     *public.Pool
	srv      *httptest.Server
	landing  *httptest.Server
	endpoint string
	seal     core.Seal
}

func startPactNode(t *testing.T, slug string, seal core.Seal) *pactNode {
	t.Helper()
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), slug+".db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	// A 2.0 node serves under a leaf its person's root issued, and that leaf names
	// the address it answers at. It CANNOT name a loopback address (PACT §14.2
	// rule 5), so the node advertises a public-looking name and `pactNet` maps that
	// name to the httptest listener — the same trick internal/node's exit demo uses,
	// and the only way to run 2.0 hermetically.
	rootKey, err := pactidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := pactidentity.BuildRoot(pactidentity.RootOpts{
		CN: strings.ToUpper(slug), Key: rootKey, NotBefore: time.Now().Add(-24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	hostSPKI, err := x509.MarshalPKIXPublicKey(kp.Signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	hostPub, err := pactidentity.ParseSPKI(hostSPKI)
	if err != nil {
		t.Fatal(err)
	}
	advertised := "https://" + slug + ".pact.example"
	leafDER, err := pactidentity.BuildLeaf(pactidentity.LeafOpts{
		CN: strings.ToUpper(slug), RootCN: strings.ToUpper(slug), RootKey: rootKey, HostPub: hostPub,
		URIs: []string{advertised + "/a/" + slug + "/mcp"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{leafDER, rootCert}, PrivateKey: kp.Signer}
	kp.Leaf, kp.Root = leafDER, rootCert
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: slug, DisplayName: strings.ToUpper(slug), Algo: "p256"})
	if err := st.SetAccountKey(ctx, a.ID, kp.Fingerprint, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAccountRoot(ctx, a.ID, pactidentity.Fingerprint(rootKey.Public().SPKI), rootCert); err != nil {
		t.Fatal(err)
	}
	if seal != "" {
		if err := st.UpdateAccountSeal(ctx, a.ID, string(seal)); err != nil {
			t.Fatal(err)
		}
	}
	a, _ = st.GetAccountByID(ctx, a.ID)

	n := &pactNode{t: t, st: st, acct: a, kp: kp, cert: cert, seal: seal,
		leafDER: leafDER, rootFpr: pactidentity.Fingerprint(rootKey.Public().SPKI), rootCert: rootCert,
		cm:  &contacts.Manager{Store: st},
		msg: &messaging.Service{Store: st, Bus: messaging.NewBus(st)}}

	reg := &public.Registry{}
	n.pool = public.NewPool(reg, public.StoreResolver(st), 16)
	// The PRODUCTION tool set (P6-01): these integration tests exercise the same
	// handlers the binary serves, not harness look-alikes.
	reg.Add(public.BuiltinEntries(public.ToolDeps{
		AccountID: a.ID,
		Contacts:  n.cm,
		Messages:  n.msg,
		Media:     &messaging.MediaService{Store: st, Blobs: messaging.BlobDir{Root: filepath.Join(t.TempDir(), "blobs")}},
		Card: func(context.Context) (string, string, error) {
			card, err := n.card()
			return card, "sig", err
		},
		Invalidate: func(ctx context.Context, accountID, fpr string) error {
			return n.pool.Invalidate(ctx, accountID, fpr)
		},
		// The node's own chain and endpoint. Without these the tool surface cannot
		// tell that it speaks 2.0, and a guest arriving with a valid chain is read as
		// having proved nothing.
		Chain:    func(context.Context) ([][]byte, error) { return [][]byte{n.leafDER, n.rootCert}, nil },
		Endpoint: func() string { return n.endpoint },
	})...)
	ident := &public.Identifier{
		Store:     st,
		AccountID: a.ID,
		Seal:      seal, Cert: core.ClientCertPreferred,
		// What a `v: 2` envelope is decided against (PACT §13.3). Without it the
		// identifier refuses every envelope as "does not speak 2.0" — which is the
		// right answer for an identity with no leaf, and the wrong one here.
		RecipientState: func(context.Context) (*public.RecipientState, error) {
			// The key in every form a LeafKey holds, as the host's own read opens it.
			der, err := identity.MarshalPKCS8(kp)
			if err != nil {
				return nil, err
			}
			lib, err := pactidentity.ParsePKCS8(der)
			if err != nil {
				return nil, err
			}
			return &public.RecipientState{
				HasRoot: true, Endpoint: n.endpoint, AcceptNewHosts: "auto",
				Chain: [][]byte{n.leafDER, n.rootCert},
				Keys: []identity.LeafKey{{
					Kid: kp.Fingerprint, Leaf: n.leafDER, KP: kp, PKCS8: der, Lib: lib, Current: true,
					NotAfter: time.Now().AddDate(1, 0, 0), Endpoint: n.endpoint,
				}},
			}, nil
		},
	}
	// the plaintext seal/client_cert gate every call passes through (SPEC §5.1)
	n.pool.Gate = ident.PoolGate()
	reg.Add(public.SealedEntries(public.SealedDeps{
		Pool: n.pool, Identifier: ident, AccountID: a.ID,
		Idem: st,
	})...)

	// the public surface: MCP over TLS, per-caller server chosen by client cert
	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		f := public.FactsFrom(r.Context())
		srv, err := n.pool.ServerFor(r.Context(), a.ID, f.ClientCertFingerprint)
		if err != nil {
			return nil
		}
		return srv
	}, &mcp.StreamableHTTPOptions{
		// The advertised Host with a loopback socket is precisely what the SDK's
		// DNS-rebinding protection refuses (E14), and it is what a 2.0 leaf forces:
		// the certificate cannot name a loopback address. Production disables the
		// guard on the public surface for the same reason — it is always TLS and
		// presents the node's own chain, so a rebinding page cannot complete a
		// handshake for its name.
		DisableLocalhostProtection: true,
	})
	ps := &public.Server{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
		Accounts:       func() []string { return []string{slug} },
		MCP:            mcpHandler,
		Invite:         http.NotFoundHandler(),
	}
	srv := httptest.NewUnstartedServer(ps.Handler())
	// httptest.StartTLS injects its OWN certificate when Certificates is empty,
	// and a client dialing by IP sends no SNI — so GetCertificate would never
	// run and peers would see httptest's key instead of the node's. Production
	// leaves Certificates empty (GetCertificate always runs); the harness pins
	// the node's own certificate explicitly.
	tc := ps.TLSConfig()
	tc.Certificates = []tls.Certificate{cert}
	srv.TLS = tc
	srv.StartTLS()
	t.Cleanup(srv.Close)
	n.srv = srv
	// The node ADVERTISES the name its leaf carries and LISTENS on loopback; the map
	// is what joins the two. Callers dial the advertised address, so the chain's
	// subjectAltName and the endpoint agree, which is what §14.2 rule 5 requires.
	n.endpoint = advertised + "/a/" + slug + "/mcp"
	pactNet.set(slug+".pact.example:443", srv.Listener.Addr().String())

	// the invite landing page (P1-13), now carrying the issuer's key
	idm := &identity.Manager{Store: st}
	_ = idm
	lmux := http.NewServeMux()
	lmux.Handle("/i/{token}", internalui.LandingHandler(internalui.LandingDeps{
		Store: st,
		SignCard: func(accountID string) (string, string, error) {
			card, err := n.card()
			return card, "sig", err
		},
		Chain: func(string) ([][]byte, error) { return [][]byte{leafDER, rootCert}, nil },
	}))
	ls := httptest.NewServer(lmux)
	t.Cleanup(ls.Close)
	n.landing = ls
	return n
}

func (n *pactNode) card() (string, error) {
	return contacts.BuildCard(n.acct.DisplayName, n.leafDER, string(n.seal))
}

// asPeer is what another node holds of this one: the root it pins, the leaf it
// presents, and the address its leaf names.
func (n *pactNode) asPeer(seal string) outbound.Peer {
	return outbound.Peer{
		Endpoint: n.endpoint, Root: n.rootFpr,
		Leaf: n.leafDER, Seal: seal,
	}
}

func (n *pactNode) client() *outbound.Client {
	pool := x509.NewCertPool()
	return &outbound.Client{Keypair: n.kp, Cert: n.cert, Roots: pool, DialContext: pactNet.dial}
}

// pactNet stands in for DNS: a leaf must name a routable-looking address, and these
// nodes listen on loopback. It maps the advertised name to the real listener.
var pactNet = &dialMap{hosts: map[string]string{}}

type dialMap struct {
	mu    sync.Mutex
	hosts map[string]string
}

func (d *dialMap) set(name, addr string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hosts[name] = addr
}

func (d *dialMap) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	target, ok := d.hosts[addr]
	d.mu.Unlock()
	if !ok {
		target = addr
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, target)
}

// fetchInvite is the redeemer's pre-redemption step: the landing page hands over
// the issuer's signed card AND its key, which the redeemer verifies by hashing.
func fetchInvite(t *testing.T, landingURL, token string) (card string, spki []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", landingURL+"/i/"+token, nil)
	req.Header.Set("Accept", "application/pact-invite+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("landing page: %d %s", resp.StatusCode, b)
	}
	// PACT §4: the machine view is exactly {card, card_sig, chain}. Anything else is an
	// extension this redeemer must not depend on — it used to demand a fourth member, `spki`.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(b, &members); err != nil {
		t.Fatalf("invite doc: %s", b)
	}
	for k := range members {
		if k != "card" && k != "card_sig" && k != "chain" {
			t.Fatalf("the landing serves a member PACT §4 does not define: %q", k)
		}
	}
	var doc struct {
		Card    string   `json:"card"`
		CardSig string   `json:"card_sig"`
		Chain   []string `json:"chain"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || doc.Card == "" || doc.CardSig == "" {
		t.Fatalf("invite doc: %s", b)
	}
	if len(doc.Chain) != 2 {
		t.Fatalf("the landing must serve the issuer's [leaf, root] (PACT §4), got %d certificates: %s", len(doc.Chain), b)
	}
	// The redeemer's own checks, as §4 states them: validate the chain, and require its leaf
	// to byte-equal the card's X-PACT-CERT. The key to seal to is that leaf's.
	issuer, err := contacts.ValidateInbound(doc.Card)
	if err != nil {
		t.Fatalf("the landing page served a card that does not validate: %v", err)
	}
	chain := [][]byte{testid.DER(t, doc.Chain[0]), testid.DER(t, doc.Chain[1])}
	vr := pactidentity.ValidateChain(chain, pactidentity.ChainOpts{Now: time.Now(), ExpectedRoot: issuer.Key, ExpectedEndpoint: issuer.Endpoint})
	if !vr.OK {
		t.Fatalf("the landing's chain fails rule %d: %s", vr.Rule, vr.Reason)
	}
	if !bytes.Equal(chain[0], issuer.Cert) {
		t.Fatal("the chain's leaf is not the certificate the card carries (PACT §4)")
	}
	spki = vr.LeafKey.SPKI
	return doc.Card, spki
}

// P1 exit (PLAN P1-11): A invites, B redeems, both pin each other, B messages A
// plaintext-mTLS, A replies sealed — run once with A at seal=optional and once
// at seal=required, where B must auto-seal even to redeem.
func TestP1ExitTwoNodesPairAndMessage(t *testing.T) {
	for _, sealMode := range []core.Seal{core.SealOptional, core.SealRequired} {
		t.Run(string(sealMode), func(t *testing.T) {
			ctx := context.Background()
			alice := startPactNode(t, "alice", sealMode)
			bob := startPactNode(t, "bob", core.SealOptional)

			// A mints an auto-accepting invite
			token, _, err := alice.cm.CreateInvite(ctx, alice.acct.ID, contacts.InviteOptions{
				AutoAccept: true, MaxUses: 1, Preset: "friend", Label: "for bob",
			})
			if err != nil {
				t.Fatal(err)
			}
			// B reads the landing page: card + key, before redeeming
			aliceCard, _ := fetchInvite(t, alice.landing.URL, token)
			bobCard, _ := bob.card()
			peer := alice.asPeer(string(sealMode))

			// B redeems — sealed when A requires it, plaintext otherwise
			var res *mcp.CallToolResult
			args := map[string]any{"token": token, "card": bobCard}
			if sealMode == core.SealRequired {
				res, err = bob.client().SealedCall(ctx, peer, "redeem_invite", args, "redeem-1")
			} else {
				res, err = bob.client().CallTool(ctx, peer, "redeem_invite", args, outbound.CallOptions{Plaintext: true})
			}
			if err != nil {
				t.Fatalf("redeem: %v", err)
			}
			if res.IsError {
				t.Fatalf("redeem refused: %s", res.Content[0].(*mcp.TextContent).Text)
			}
			var redeemed struct {
				Status string   `json:"status"`
				Card   string   `json:"card"`
				Chain  []string `json:"chain"`
			}
			if err := json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &redeemed); err != nil {
				t.Fatal(err)
			}
			if redeemed.Status != "accepted" {
				t.Fatalf("status: %s", redeemed.Status)
			}
			// A pinned B, with the FULL key (not just its hash)
			bobOnA, err := alice.st.GetContact(ctx, alice.acct.ID, bob.rootFpr)
			if err != nil || bobOnA.Status != "active" || len(bobOnA.SPKI) == 0 {
				t.Fatalf("A did not pin B: %+v %v", bobOnA, err)
			}
			// B pins A from the redemption answer, the way PACT §6.1 lays it out: the signed card,
			// and the CHAIN that proves it. The chain validates to the root the card names at the
			// address it names, its leaf is the certificate on the card, and the key B pins is
			// that leaf's. This read a `spki` member instead, which §6.1 does not define.
			answered, err := contacts.ValidateInbound(redeemed.Card)
			if err != nil {
				t.Fatalf("the redemption answer's card does not validate: %v", err)
			}
			if len(redeemed.Chain) != 2 {
				t.Fatalf("the redemption answer must carry A's [leaf, root], got %d certificates", len(redeemed.Chain))
			}
			answeredChain := [][]byte{testid.DER(t, redeemed.Chain[0]), testid.DER(t, redeemed.Chain[1])}
			avr := pactidentity.ValidateChain(answeredChain, pactidentity.ChainOpts{Now: time.Now(), ExpectedRoot: answered.Key, ExpectedEndpoint: answered.Endpoint})
			if !avr.OK {
				t.Fatalf("the redemption answer's chain fails rule %d: %s", avr.Rule, avr.Reason)
			}
			if !bytes.Equal(answeredChain[0], answered.Cert) {
				t.Fatal("the chain the redemption answered with does not carry the certificate its card does")
			}
			gotSPKI := avr.LeafKey.SPKI
			if answered.Key != alice.rootFpr {
				t.Fatalf("the answer's card names %s, not A's root %s", answered.Key, alice.rootFpr)
			}
			if _, err := bob.st.InsertContact(ctx, store.Contact{
				AccountID: bob.acct.ID, Fingerprint: alice.rootFpr, SPKI: gotSPKI,
				Status: "active", Card: redeemed.Card, Permissions: []string{"message.text"},
				PinnedAt: time.Now().Unix(),
				Leaf:     answered.Cert, Endpoint: answered.Endpoint,
			}); err != nil {
				t.Fatal(err)
			}
			_ = aliceCard

			// B → A: plaintext mTLS when allowed, sealed when A requires it
			msgArgs := map[string]any{"msg_id": "b-1", "text": "hello alice"}
			if sealMode == core.SealRequired {
				res, err = bob.client().SealedCall(ctx, peer, "send_message", msgArgs, "b-1")
			} else {
				res, err = bob.client().CallTool(ctx, peer, "send_message", msgArgs, outbound.CallOptions{Plaintext: true})
			}
			if err != nil {
				t.Fatalf("B→A message: %v", err)
			}
			if res.IsError {
				t.Fatalf("B→A refused: %s", res.Content[0].(*mcp.TextContent).Text)
			}
			var delivered struct {
				Status   string `json:"status"`
				ThreadID string `json:"thread_id"`
			}
			_ = json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &delivered)
			if delivered.Status != "delivered" || delivered.ThreadID == "" {
				t.Fatalf("delivery: %+v", delivered)
			}

			// A → B: always SEALED (B pinned A's key, A pinned B's)
			bobPeer := bob.asPeer(string(core.SealOptional))
			reply, err := alice.client().SealedCall(ctx, bobPeer, "send_message",
				map[string]any{"msg_id": "a-1", "text": "hi bob"}, "a-1")
			if err != nil {
				t.Fatalf("A→B sealed reply: %v", err)
			}
			if reply.IsError {
				t.Fatalf("A→B refused: %s", reply.Content[0].(*mcp.TextContent).Text)
			}

			// both stored, on the right threads, attributed to the right peers
			aThreads, _ := alice.st.ListThreadsByAccount(ctx, alice.acct.ID)
			bThreads, _ := bob.st.ListThreadsByAccount(ctx, bob.acct.ID)
			if len(aThreads) != 1 || len(bThreads) != 1 {
				t.Fatalf("threads: A=%d B=%d", len(aThreads), len(bThreads))
			}
			aMsgs, _ := alice.msg.Thread(ctx, alice.acct.ID, aThreads[0].ID)
			bMsgs, _ := bob.msg.Thread(ctx, bob.acct.ID, bThreads[0].ID)
			if len(aMsgs) != 1 || aMsgs[0].Body != "hello alice" || aMsgs[0].ContactFpr != bob.rootFpr {
				t.Fatalf("A's message: %+v", aMsgs)
			}
			if len(bMsgs) != 1 || bMsgs[0].Body != "hi bob" || bMsgs[0].ContactFpr != alice.rootFpr {
				t.Fatalf("B's message: %+v", bMsgs)
			}

			// and a plaintext substantive call to a seal=required node is refused
			if sealMode == core.SealRequired {
				_, err := bob.client().CallTool(ctx, peer, "send_message",
					map[string]any{"msg_id": "b-2", "text": "unsealed"}, outbound.CallOptions{Plaintext: true})
				if err == nil {
					t.Fatal("plaintext accepted by a seal=required peer")
				}
			}
		})
	}
}
