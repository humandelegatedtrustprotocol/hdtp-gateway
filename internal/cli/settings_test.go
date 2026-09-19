package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/descope/virtualwebauthn"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/ingress"
	"github.com/tech-sumit/pact-gateway/internal/internalui/auth"
	"github.com/tech-sumit/pact-gateway/internal/outbound"
	"github.com/tech-sumit/pact-gateway/internal/tunnel"
)

// portal drives the settings page the way a browser would, carrying the CSRF
// cookie the middleware sets.
type portal struct {
	t    *testing.T
	base string
	c    *http.Client
	csrf string
}

// portals keeps one driver per node. A node has one owner and one authenticator
// in these tests, exactly as a person has one browser: a second driver could not
// register (the wizard closes after the first passkey) and could not sign in
// either, since the credential lives in the first one's authenticator.
var portals = map[string]*portal{}

func newPortal(t *testing.T, base string) *portal {
	t.Helper()
	key := base // cache under what the CALLER passed, not the rewritten host
	if p, ok := portals[key]; ok {
		p.t = t
		return p
	}
	// A loopback portal presents itself as `localhost`: an IP is not a valid
	// WebAuthn RP ID, so registration is refused on any other loopback name
	// (OriginPolicy). The driver therefore reaches the same socket by that name.
	base = strings.Replace(base, "127.0.0.1", "localhost", 1)
	jar := &cookieJar{}
	p := &portal{t: t, base: base, c: &http.Client{Timeout: 15 * time.Second, Jar: jar}}
	p.get("/api/session") // open route; seeds the CSRF cookie
	// Match by PREFIX: each node suffixes its cookie names with its own tag so
	// two nodes on one host do not overwrite each other's (cookies ignore
	// ports). A driver pinned to the bare name stops finding it.
	for _, c := range jar.cookies {
		if strings.HasPrefix(c.Name, "pact_csrf") {
			p.csrf = c.Value
		}
	}
	if p.csrf == "" {
		t.Fatal("portal never set a CSRF cookie")
	}
	// SPEC §8.3: a session on every bind, loopback included. A driver that only
	// carried a CSRF cookie is now exactly as unauthenticated as a stranger, so
	// it does what an owner does — claims the node with a passkey. This also
	// means these tests exercise the real first-run path on every run.
	p.registerPasskey(t)
	portals[key] = p
	return p
}

// registerPasskey runs the first-run WebAuthn ceremony against the live node and
// leaves the session cookie in the jar.
func (p *portal) registerPasskey(t *testing.T) {
	t.Helper()
	rp := virtualwebauthn.RelyingParty{Name: "pact-gateway", ID: "localhost", Origin: p.base}
	authn := virtualwebauthn.NewAuthenticator()

	body := p.raw(t, "POST", "/setup/begin", nil)
	var begin struct {
		Ceremony string          `json:"ceremony"`
		Options  json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal([]byte(body), &begin); err != nil {
		t.Fatalf("setup/begin did not answer a ceremony: %v — %s", err, firstLine(body))
	}
	parsed, err := virtualwebauthn.ParseAttestationOptions(string(begin.Options))
	if err != nil {
		t.Fatalf("attestation options: %v", err)
	}
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	att := virtualwebauthn.CreateAttestationResponse(rp, authn, cred, *parsed)
	p.raw(t, "POST", "/setup/finish?ceremony="+begin.Ceremony+"&tag=test+driver", []byte(att))

	for _, c := range jarOf(p).cookies {
		if strings.HasPrefix(c.Name, "pact_session") && c.Value != "" {
			return
		}
	}
	t.Fatal("registering a passkey did not sign the driver in")
}

func jarOf(p *portal) *cookieJar { return p.c.Jar.(*cookieJar) }

// raw issues a request with the CSRF header and a byte body, returning the body.
func (p *portal) raw(t *testing.T, method, path string, body []byte) string {
	t.Helper()
	req, err := http.NewRequest(method, p.base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Pact-Csrf", p.csrf)
	for _, c := range jarOf(p).cookies {
		req.AddCookie(c)
	}
	res, err := p.c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		t.Fatalf("%s %s: %d %s", method, path, res.StatusCode, firstLine(string(b)))
	}
	return string(b)
}

func (p *portal) get(path string) string {
	p.t.Helper()
	res, err := p.c.Get(p.base + path)
	if err != nil {
		p.t.Fatalf("GET %s: %v", path, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		p.t.Fatalf("GET %s: %d %s", path, res.StatusCode, firstLine(string(b)))
	}
	return string(b)
}

func (p *portal) post(path string, form url.Values) string {
	p.t.Helper()
	form.Set("csrf", p.csrf)
	res, err := p.c.PostForm(p.base+path, form)
	if err != nil {
		p.t.Fatalf("POST %s: %v", path, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		p.t.Fatalf("POST %s: %d %s", path, res.StatusCode, firstLine(string(b)))
	}
	return string(b)
}

// cookieJar is the smallest jar that keeps one host's cookies.
type cookieJar struct{ cookies []*http.Cookie }

func (j *cookieJar) SetCookies(_ *url.URL, cs []*http.Cookie) { j.cookies = append(j.cookies, cs...) }
func (j *cookieJar) Cookies(*url.URL) []*http.Cookie          { return j.cookies }

func seedAccount(t *testing.T, dir, slug string) store.Account {
	t.Helper()
	ctx := context.Background()
	st := migrated(t, dir)
	defer st.Close()
	idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
	a, err := idm.CreateAccount(ctx, slug, strings.ToUpper(slug), identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	return issueLeafFor(t, idm, a, configPublicURL(t, dir))
}

// AC (P7-01): a knob saved in the portal persists across a restart and the
// resolved config re-derives from it — a tunnel chosen in the page forces the
// same knobs an environment-set one would.
func TestSettingsPersistAcrossRestartAndReDerive(t *testing.T) {
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	cfg := map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "seal": "optional", "client_cert": "preferred",
	}
	b, _ := json.Marshal(cfg)
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	seedAccount(t, dir, "alice")
	r := startServeAt(t, dir, cfgPath, internal, public)

	p := newPortal(t, "http://"+r.internal)
	page := p.get("/api/settings")
	if !strings.Contains(page, "Sealed envelopes") || !strings.Contains(page, "adapter_settings") {
		t.Fatalf("settings payload is missing its controls:\n%s", firstLine(page))
	}

	// choose an EDGE adapter and a stricter gateway; both are restart-scoped
	body := p.post("/settings", url.Values{
		"tunnel": {"cloudflare"}, "seal": {"required"},
		"public_url": {"https://" + public}, "client_cert": {"preferred"},
	})
	if !strings.Contains(body, "Restart the node") {
		t.Fatalf("a restart-scoped change did not say so:\n%s", firstLine(body))
	}

	// restart: the stored values are read back and re-derived
	r.stop()
	loaded, err := core.Load(cfgPath, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	st := openStoreAt(t, dir)
	svc := &settingsService{store: st, kr: openKeyringAt(t, dir), cfg: loaded}
	stored, err := svc.values(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.ApplyStoreSettings(stored); err != nil {
		t.Fatal(err)
	}
	// the adapter the OWNER picked derives the mode and forces the knobs
	if loaded.Tunnel != "cloudflare" || loaded.Mode != core.ModeEdge {
		t.Fatalf("mode not derived from the saved adapter: %+v", loaded)
	}
	if loaded.Seal != core.SealRequired || loaded.ClientCert != core.ClientCertOff {
		t.Fatalf("edge knobs not forced after the store overlay: seal=%s cert=%s", loaded.Seal, loaded.ClientCert)
	}
	if loaded.Tunnel != "cloudflare" || loaded.Mode != core.ModeEdge {
		t.Fatalf("the adapter choice did not persist and re-derive: %+v", loaded)
	}
}

// AC (P7-01): a knob the environment pinned renders locked WITH the reason and
// cannot be changed through a hand-crafted POST either.
func TestEnvPinnedKnobIsLockedAndUnwritable(t *testing.T) {
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public,
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	seedAccount(t, dir, "alice")

	t.Setenv("PACT_SEAL", "required")
	r := startServeAt(t, dir, cfgPath, internal, public)
	p := newPortal(t, "http://"+r.internal)

	page := p.get("/api/settings")
	if !strings.Contains(page, "pinned by the environment (PACT_SEAL)") {
		t.Fatalf("env-pinned seal did not say why it is locked:\n%s", page)
	}
	// a POST that tries anyway changes nothing
	p.post("/settings", url.Values{"seal": {"none"}, "public_url": {"https://" + public}})
	st := openStoreAt(t, dir)
	rows, err := st.ListSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Key == "seal" {
			t.Fatalf("an environment-pinned knob was written: %+v", row)
		}
	}
}

// AC (P7-01): a saved secret is sealed at rest and never rendered back.
func TestAdapterSecretIsSealedAndNeverRendered(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public,
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	seedAccount(t, dir, "alice")
	r := startServeAt(t, dir, cfgPath, internal, public)
	p := newPortal(t, "http://"+r.internal)

	const secret = "tskey-auth-SUPERSECRET-do-not-log"
	body := p.post("/settings/adapter", url.Values{
		"key": {"tunnel.tailscale.auth_key"}, "value": {secret},
	})
	if strings.Contains(body, secret) {
		t.Fatal("the page echoed the secret back")
	}
	if !strings.Contains(body, "tunnel.tailscale.auth_key") ||
		!strings.Contains(body, `"secret":true`) || !strings.Contains(body, `"set":true`) {
		t.Fatalf("the stored key is not listed as a set secret:\n%s", body)
	}
	// re-render: still no value
	if page := p.get("/api/settings"); strings.Contains(page, secret) {
		t.Fatal("the secret came back on a later render")
	}
	// at rest: ciphertext, not the value
	st := openStoreAt(t, dir)
	rows, err := st.ListSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		if row.Key != "tunnel.tailscale.auth_key" {
			continue
		}
		found = true
		if !row.Secret || strings.Contains(row.Value, "SUPERSECRET") {
			t.Fatalf("secret stored in the clear: %+v", row)
		}
	}
	if !found {
		t.Fatal("the setting was not stored at all")
	}
	// and the audit chain records the key, never the value
	events, err := st.ListAuditEvents(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if strings.Contains(e.Resource+e.Details+e.Outcome, "SUPERSECRET") {
			t.Fatalf("audit row carries the secret: %+v", e)
		}
	}
}

// AC (P7-01): changing seal takes effect on the next call — no restart — and
// the card advertises exactly what the gate enforces.
func TestSealChangeAppliesLiveAndCardMatchesTheGate(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "client_cert": "preferred",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	acct := seedAccount(t, dir, "alice")
	seedSetting(t, dir, "seal", "optional")
	r := startServeAt(t, dir, cfgPath, internal, public)

	// a pinned contact, so the call is a real one rather than a guest refusal
	kp, cert := peerIdentity(t, "bob")
	st := openStoreAt(t, dir)
	if _, err := st.InsertContact(ctx, store.Contact{
		AccountID: acct.ID, Fingerprint: kp.Fingerprint, SPKI: mustSPKI(t, kp),
		Leaf: kp.Host.LeafDER, Endpoint: kp.Endpoint,
		Status: "active", Permissions: []string{"message.text"},
	}); err != nil {
		t.Fatal(err)
	}
	peer, dial := nodePeer(t, dir, acct, r.public)
	client := &outbound.Client{Keypair: kp.KP, Cert: cert, Roots: x509.NewCertPool(), DialContext: dial}

	// while seal is optional, a plaintext message lands
	res, err := client.CallTool(ctx, peer, "send_message",
		map[string]any{"msg_id": "m-1", "text": "before"}, outbound.CallOptions{Plaintext: true})
	if err != nil || res.IsError {
		t.Fatalf("plaintext call under seal=optional: %v %+v", err, res)
	}

	// flip it in the portal
	p := newPortal(t, "http://"+r.internal)
	body := p.post("/settings", url.Values{"seal": {"required"}, "public_url": {"https://" + public}})
	if strings.Contains(body, "Restart the node for seal") {
		t.Fatal("seal was reported as restart-scoped; it applies live")
	}

	// the very next plaintext call is refused, with no restart in between —
	// and refused with the RIGHT code, not merely denied
	after, err := client.CallTool(ctx, peer, "send_message",
		map[string]any{"msg_id": "m-2", "text": "after"}, outbound.CallOptions{Plaintext: true})
	if err != nil {
		t.Fatalf("send_message after the flip: %v", err)
	}
	if !after.IsError || !strings.Contains(textOf(after), "seal_required") {
		t.Fatalf("a plaintext call survived seal=required: %s", textOf(after))
	}
	// ...and the card now advertises what the gate enforces
	card, err := client.CallTool(ctx, peer, "get_card", map[string]any{}, outbound.CallOptions{Plaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	if !card.IsError {
		t.Fatal("get_card should also be gated once sealing is required")
	}
	// read the card through the store instead: the account row moved too
	a, err := st.GetAccountByID(ctx, acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.Seal != "required" {
		t.Fatalf("the account row still says seal=%s: the card would advertise a lie", a.Seal)
	}
}

// NOT COVERED HERE, deliberately: an endpoint change reaching a real peer.
//
// The campaign needs the peer's chain to validate, and PACT §14.2 rule 5 refuses a
// leaf whose subjectAltName is a loopback, link-local or private address. A test
// that binds to 127.0.0.1 therefore cannot present a chain that validates — no
// matter that the pin and the SAN agree — so a hermetic two-node test over real
// TLS is not possible at this level any more. It is proven instead by
// `internal/node.TestPact20ExitDemo`, which stands three whole nodes up in one
// process behind a dial map so their leaves can name real hosts, and over the wire
// by the Docker harness. Adding a dial seam to the CLI for tests was considered
// and rejected: the harness notes retire exactly that kind of knob ("E11 is
// retired. Do not add clock_offset_seconds").

// `recordingPeer`/`newRecordingPeer` went with that test on 2026-09-18: a peer's whole node, built
// listener-first because a 2.0 leaf names the address it answers at, driving the fan-out over real
// TLS. With the test retired they were a fixture for nothing, which reads as coverage and is not.

// AC (P7-01): a restart-scoped save is visible in the page immediately — the
// control shows what was chosen and names what is still running. A save the
// owner cannot see is indistinguishable from one that did not happen.
func TestRestartScopedSaveShowsAsPending(t *testing.T) {
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "seal": "optional",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	seedAccount(t, dir, "alice")
	r := startServeAt(t, dir, cfgPath, internal, public)
	p := newPortal(t, "http://"+r.internal)

	// client_cert is restart-scoped and NOT pinned by the config file, so it is a
	// knob the portal may actually write. public_url is file-pinned in this test.
	p.post("/settings", url.Values{"client_cert": {"required"}})
	page := p.get("/api/settings")
	if !strings.Contains(page, `"key":"client_cert","value":"required"`) {
		t.Fatalf("the saved value is not shown in the control:\n%s", page)
	}
	if !strings.Contains(page, `"pending":true`) {
		t.Fatalf("the payload does not say the change is not live yet:\n%s", page)
	}
}

// AC (P7-01): the audit chain distinguishes what the owner did from what a peer
// did. A chain that calls every write a peer action cannot answer the question
// an operator asks after an incident.
func TestOwnerActionsAreAuditedAsOwner(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "seal": "optional", "client_cert": "preferred",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	acct := seedAccount(t, dir, "alice")
	r := startServeAt(t, dir, cfgPath, internal, public)

	// an owner action…
	p := newPortal(t, "http://"+r.internal)
	// A knob the config file does NOT pin: seal and client_cert are both in the
	// file above, and the file wins over the portal (SPEC §12.2), so posting one of
	// those would be refused and audited as nothing.
	p.post("/settings", url.Values{"limit.contact_per_hour": {"90"}})

	// …and a peer action
	kp, cert := peerIdentity(t, "bob")
	peer, dial := nodePeer(t, dir, acct, r.public)
	client := &outbound.Client{Keypair: kp.KP, Cert: cert, Roots: x509.NewCertPool(), DialContext: dial}
	pres, perr := client.CallTool(ctx, peer, "send_message", map[string]any{"msg_id": "x", "text": "hi"}, outbound.CallOptions{Plaintext: true})
	_, _ = pres, perr

	st := openStoreAt(t, dir)
	rows, err := st.ListAuditEvents(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	// The store's vocabulary is owner|token|contact|guest|cli|system. An
	// unknown caller is a guest; the portal is the owner.
	var owner, caller int
	for _, row := range rows {
		switch row.ActorKind {
		case "owner":
			owner++
		case "contact", "guest":
			caller++
		}
	}
	if out := r.out.String(); strings.Contains(out, "audit:") {
		t.Fatalf("an audit write failed while serving:\n%s", out)
	}
	if owner == 0 {
		t.Fatalf("no owner-attributed audit events among %d rows", len(rows))
	}
	if caller == 0 {
		t.Fatalf("no caller-attributed audit events among %d rows", len(rows))
	}
	// the settings change specifically is the owner's
	found := false
	for _, row := range rows {
		if strings.HasPrefix(row.Action, "settings_") {
			found = true
			if row.ActorKind != "owner" {
				t.Fatalf("a settings change was attributed to %q: %+v", row.ActorKind, row)
			}
		}
	}
	if !found {
		t.Fatal("the settings change was not audited at all")
	}
}

// AC (P8-01, defect #1): there are three card emitters — the served card, the
// portal card page (and /card.vcf), and the move campaign's fan-out. All three must
// render the SAME card. Two of them used to read the raw account row, so a
// forced mode or a live seal change could make the portal show, and the fan-out
// ship, a policy the gate does not enforce.
func TestEveryCardEmitterAgreesWithTheServedCard(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"client_cert": "preferred",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	acct := seedAccount(t, dir, "alice")
	seedSetting(t, dir, "seal", "optional")
	seedSetting(t, dir, "public_url", "https://"+public)
	r := startServeAt(t, dir, cfgPath, internal, public)

	// a pinned contact, so get_card is reachable
	kp, cert := peerIdentity(t, "bob")
	st := openStoreAt(t, dir)
	if _, err := st.InsertContact(ctx, store.Contact{
		AccountID: acct.ID, Fingerprint: kp.Fingerprint, SPKI: mustSPKI(t, kp),
		Leaf: kp.Host.LeafDER, Endpoint: kp.Endpoint,
		Status: "active", Permissions: []string{"message.text"},
	}); err != nil {
		t.Fatal(err)
	}
	peer, dial := nodePeer(t, dir, acct, r.public)
	client := &outbound.Client{Keypair: kp.KP, Cert: cert, Roots: x509.NewCertPool(), DialContext: dial}

	served := func() string {
		t.Helper()
		res, err := client.CallTool(ctx, peer, "get_card", map[string]any{}, outbound.CallOptions{Plaintext: true})
		if err != nil || res.IsError {
			t.Fatalf("get_card: %v %+v", err, res)
		}
		var out struct {
			Card string `json:"card"`
		}
		if err := json.Unmarshal([]byte(textOf(res)), &out); err != nil {
			t.Fatalf("card body: %s", textOf(res))
		}
		return out.Card
	}
	p := newPortal(t, "http://"+r.internal)
	portalVCF := func() string {
		t.Helper()
		return p.get("/card.vcf?account=" + acct.ID)
	}

	if a, b := served(), portalVCF(); a != b {
		t.Fatalf("the portal shows a different card than peers receive:\n--- served ---\n%s\n--- portal ---\n%s", a, b)
	}

	// Change the endpoint live. The card must NOT follow it: a card's address comes
	// from the leaf's subjectAltName (PACT §14.1), and a config knob cannot re-issue
	// a certificate. Moving is a new leaf for a new address and an `update_contact`
	// campaign from there (§5.3) — deliberately not something a text field can do.
	// What must still hold is that both emitters agree, whatever the config says.
	before := served()
	p.post("/settings", url.Values{"public_url": {"https://moved.example.com"}})
	if served() != before {
		t.Fatalf("a public_url change moved the served card; only a new leaf may:\n--- before ---\n%s\n--- after ---\n%s", before, served())
	}
	if a, b := served(), portalVCF(); a != b {
		t.Fatalf("after a live public_url change the portal card drifted:\n--- served ---\n%s\n--- portal ---\n%s", a, b)
	}
}

// AC (P8-01, defect #2): every audit write must carry an actor kind the store
// accepts. A kind outside owner|token|contact|guest|cli|system fails the CHECK
// constraint and the append is LOST — which is what happened silently between
// P6-03 and P7-01, reported only to stderr that nothing read. The sink clamps to
// `system` rather than emitting a row that dies on the way in.
func TestAuditActorKindIsAlwaysWritable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := migrated(t, dir)
	defer st.Close()

	var stderr bytes.Buffer
	sink := auditWriter(ctx, st, &stderr)
	kinded := sink.kinded()

	// in-set kinds are written verbatim; anything else degrades to `system`
	for _, kind := range []string{"owner", "token", "contact", "guest", "cli", "system"} {
		kinded(kind, "probe", "resource:"+kind, "ok")
	}
	for _, bad := range []string{"peer", "", "PENDING", "admin", "root", "Owner"} {
		kinded(bad, "probe_bad", "resource:"+bad, "ok")
	}

	// stderr now carries the live event mirror as well as failures, so "empty" is
	// no longer the same question. A FAILURE is the line prefixed `audit:`.
	for _, line := range strings.Split(stderr.String(), "\n") {
		if strings.HasPrefix(line, "audit:") {
			t.Fatalf("an audit append failed instead of being clamped: %s", line)
		}
	}
	rows, err := st.ListAuditEvents(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 12 {
		t.Fatalf("wrote %d rows, want 12 — a rejected append is a hole in the chain", len(rows))
	}
	allowed := map[string]bool{
		"owner": true, "token": true, "contact": true, "guest": true, "cli": true, "system": true,
	}
	clamped := 0
	for _, r := range rows {
		if !allowed[r.ActorKind] {
			t.Fatalf("row stored with an actor kind the schema forbids: %+v", r)
		}
		if r.Action == "probe_bad" {
			if r.ActorKind != "system" {
				t.Fatalf("an out-of-set kind became %q, want system: %+v", r.ActorKind, r)
			}
			clamped++
		}
	}
	if clamped != 6 {
		t.Fatalf("clamped %d rows, want 6", clamped)
	}
}

// AC (P7-02): the ingress adapters are registered, so they already appear in the
// Settings dropdown and already pass validation — an owner can select one, save,
// restart, and watch `serve` die with "ingress pairing needs subdomain". Saving
// an ingress adapter without a completed pairing must be refused at save time,
// where the owner can act on it, not at the next boot.
func TestSelectingAnIngressAdapterWithoutPairingIsRefused(t *testing.T) {
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "seal": "optional",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	seedAccount(t, dir, "alice")
	r := startServeAt(t, dir, cfgPath, internal, public)
	p := newPortal(t, "http://"+r.internal)

	for _, adapter := range []string{"ingress-passthrough", "ingress-terminate"} {
		body := p.post("/settings", url.Values{"tunnel": {adapter}})
		if !strings.Contains(body, "pair") {
			t.Fatalf("%s was accepted with no pairing; the next start would fail fatally:\n%s",
				adapter, firstLine(body))
		}
		st := openStoreAt(t, dir)
		rows, err := st.ListSettings(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.Key == "tunnel" && row.Value == adapter {
				t.Fatalf("%s was persisted despite being unusable", adapter)
			}
		}
	}
}

// AC (P7-02): pairing from the portal against a real ingress stores the adapter
// configuration, selects the adapter, and sets the public URL — and refuses
// cleanly on a fingerprint mismatch or a replayed token without leaving half a
// configuration behind for the next boot to trip over.
func TestIngressPairingFromThePortal(t *testing.T) {
	ctx := context.Background()

	// a real ingress: registry + pairing server over TLS, requesting client certs
	ingKP, ingCert := selfSigned(t, "ingress")
	reg := ingress.NewMemoryRegistry(nil)
	ps := &ingress.PairingServer{
		Registry: reg, Domain: "example.test", IngressFingerprint: ingKP.Fingerprint,
		DataPlaneAddr: "127.0.0.1", DataPlanePort: 7000, DataPlaneToken: "dp-token",
	}
	isrv := httptest.NewUnstartedServer(ps.Handler())
	isrv.TLS = &tls.Config{Certificates: []tls.Certificate{ingCert}, ClientAuth: tls.RequestClientCert}
	isrv.StartTLS()
	defer isrv.Close()
	pairURL := isrv.URL + "/pair"

	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "seal": "optional",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	seedAccount(t, dir, "alice")
	r := startServeAt(t, dir, cfgPath, internal, public)
	p := newPortal(t, "http://"+r.internal)

	mint := func() string {
		tok, err := reg.MintToken(time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	form := func(token, fpr string) url.Values {
		return url.Values{
			"pair_url": {pairURL}, "token": {token}, "subdomain": {"alice"},
			"mode": {"passthrough"}, "ingress_fingerprint": {fpr},
		}
	}

	// a fingerprint mismatch aborts before anything is stored
	body := p.post("/settings/pair", form(mint(), "sha256:definitely-not-the-ingress"))
	if !strings.Contains(body, "refused") {
		t.Fatalf("a mismatched fingerprint was accepted:\n%s", firstLine(body))
	}
	st := openStoreAt(t, dir)
	rows, err := st.ListSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if strings.HasPrefix(row.Key, "tunnel.ingress-") {
			t.Fatalf("a refused pairing left configuration behind: %+v", row)
		}
	}

	// the real thing
	token := mint()
	body = p.post("/settings/pair", form(token, ingKP.Fingerprint))
	if !strings.Contains(body, "alice.example.test") || !strings.Contains(body, "Restart") {
		t.Fatalf("pairing did not report success:\n%s", body)
	}
	stored := map[string]store.Setting{}
	rows, _ = st.ListSettings(ctx)
	for _, row := range rows {
		stored[row.Key] = row
	}
	for _, want := range []string{"subdomain", "domain", "data_plane_addr", "data_plane_port", "node_fpr"} {
		if stored["tunnel.ingress-passthrough."+want].Value == "" {
			t.Fatalf("pairing did not store %s: %+v", want, stored)
		}
	}
	// the two credentials are sealed, and never rendered
	for _, secret := range []string{"data_plane_token", "node_secret"} {
		row := stored["tunnel.ingress-passthrough."+secret]
		if !row.Secret {
			t.Fatalf("%s stored in the clear: %+v", secret, row)
		}
	}
	if page := p.get("/api/settings"); strings.Contains(page, "dp-token") {
		t.Fatal("the page rendered the data-plane token")
	}
	// the adapter is now selected and the public URL follows the assigned name
	if stored["tunnel"].Value != "ingress-passthrough" {
		t.Fatalf("adapter not selected: %+v", stored["tunnel"])
	}
	if stored["public_url"].Value != "https://alice.example.test" {
		t.Fatalf("public_url not set from the assigned name: %+v", stored["public_url"])
	}

	// the token was single-use
	body = p.post("/settings/pair", form(token, ingKP.Fingerprint))
	if !strings.Contains(body, "refused") {
		t.Fatalf("a replayed token was accepted:\n%s", firstLine(body))
	}

	// unpair is refused while that adapter is selected, and works once it is not
	if body = p.post("/settings/unpair", url.Values{"adapter": {"ingress-passthrough"}}); !strings.Contains(body, "could not unpair") {
		t.Fatalf("unpaired the adapter the node is about to start with:\n%s", firstLine(body))
	}

	// the TERMINATE path maps to the other adapter — the one that derives edge
	// mode and forces seal=required/client_cert=off, so a mode-mapping error
	// here is security-relevant rather than cosmetic.
	term := form(mint(), ingKP.Fingerprint)
	term.Set("subdomain", "bob")
	term.Set("mode", "terminate")
	body = p.post("/settings/pair", term)
	if !strings.Contains(body, "bob.example.test") || !strings.Contains(body, "ingress-terminate") {
		t.Fatalf("terminate pairing did not land on ingress-terminate:\n%s", firstLine(body))
	}
	rows, _ = st.ListSettings(ctx)
	stored = map[string]store.Setting{}
	for _, row := range rows {
		stored[row.Key] = row
	}
	if stored["tunnel.ingress-terminate.subdomain"].Value != "bob" {
		t.Fatalf("terminate pairing stored nothing: %+v", stored)
	}
	if edge, err := tunnel.TerminatesAtEdge("ingress-terminate"); err != nil || !edge {
		t.Fatalf("ingress-terminate must derive edge mode: %v %v", edge, err)
	}
}

// AC (P7-04): the storage section persists a per-account quota and retention
// window, and the quota the node enforces is the one that was saved.
func TestStorageSettingsPersistAndApply(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "seal": "optional",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	acct := seedAccount(t, dir, "alice")
	r := startServeAt(t, dir, cfgPath, internal, public)
	p := newPortal(t, "http://"+r.internal)

	page := p.get("/api/settings")
	if !strings.Contains(page, `"show_storage":true`) || !strings.Contains(page, `"quota_gib"`) {
		t.Fatalf("the storage section is missing from the payload:\n%s", firstLine(page))
	}
	// the default is retention 0 = unlimited, carried as data; the view says
	// "keep forever" (held by the bundle contract below)
	if !strings.Contains(page, `"retention_days":0`) {
		t.Fatalf("the payload does not carry the unlimited default:\n%s", firstLine(page))
	}

	body := p.post("/settings/storage", url.Values{
		"account": {acct.ID}, "quota_gib": {"2"}, "retention_days": {"30"},
	})
	if !strings.Contains(body, "permanently and locally") {
		t.Fatalf("a destructive setting saved without saying so:\n%s", firstLine(body))
	}
	st := openStoreAt(t, dir)
	rows, err := st.ListSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, row := range rows {
		got[row.Key] = row.Value
	}
	if got[StorageKeyQuota(acct.ID)] != strconv.FormatInt(2<<30, 10) {
		t.Fatalf("quota not stored in bytes: %q", got[StorageKeyQuota(acct.ID)])
	}
	if got[StorageKeyRetention(acct.ID)] != "30" {
		t.Fatalf("retention not stored: %q", got[StorageKeyRetention(acct.ID)])
	}
	// nonsense is refused rather than stored
	if body := p.post("/settings/storage", url.Values{
		"account": {acct.ID}, "quota_gib": {"-1"}, "retention_days": {"x"},
	}); !strings.Contains(body, "whole numbers") {
		t.Fatalf("negative quota accepted:\n%s", firstLine(body))
	}
}

// AC (P7-03b): the owners page lists and removes passkeys, mints a bearer token
// shown exactly once, and revoking it stops a live owner-MCP session.
func TestOwnersPageTokensAndPasskeys(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "seal": "optional",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	seedAccount(t, dir, "alice")
	// an owner exists so a token has somebody to belong to
	st0 := migrated(t, dir)
	if _, err := st0.CreateOwnerWithID(ctx, "", "Owner"); err != nil {
		t.Fatal(err)
	}
	st0.Close()

	r := startServeAt(t, dir, cfgPath, internal, public)
	p := newPortal(t, "http://"+r.internal)

	page := p.get("/api/owners")
	if !strings.Contains(page, `"passkeys"`) || !strings.Contains(page, `"tokens"`) {
		t.Fatalf("the owners payload did not render:\n%s", firstLine(page))
	}

	// mint a token: the create response carries its ONE appearance, in a field
	// the view renders under the shown-once warning (the warning copy itself is
	// bundle-held: web/src/views/owners.tsx says "shown once, store it now").
	body := p.post("/owners/tokens/create", url.Values{"label": {"laptop agent"}})
	var minted struct {
		NewToken string `json:"new_token"`
	}
	if err := json.Unmarshal([]byte(body), &minted); err != nil || !strings.HasPrefix(minted.NewToken, "pact_") {
		t.Fatalf("no token in the create response: %v\n%s", err, firstLine(body))
	}
	token := minted.NewToken
	// it works against the owner MCP…
	cs, err := dialOwnerMCP(ctx, "http://"+r.internal+"/owner/mcp", "Bearer "+token)
	if err != nil {
		t.Fatalf("the minted token was refused: %v", err)
	}
	cs.Close()
	// …and never appears again
	if page := p.get("/api/owners"); strings.Contains(page, token) {
		t.Fatal("the token was shown a second time")
	}

	// revoke it, and it stops working
	st := openStoreAt(t, dir)
	toks, err := st.ListTokens(ctx)
	if err != nil || len(toks) != 1 {
		t.Fatalf("tokens: %d %v", len(toks), err)
	}
	body = p.post("/owners/tokens/"+toks[0].ID+"/revoke", url.Values{})
	if !strings.Contains(body, `"revoked":true`) {
		t.Fatalf("revoke did not report:\n%s", firstLine(body))
	}
	if _, err := dialOwnerMCP(ctx, "http://"+r.internal+"/owner/mcp", "Bearer "+token); err == nil {
		t.Fatal("a revoked token still opened an owner-MCP session")
	}
	// and the audit trail records the id, never the token
	rows, err := st.ListAuditEvents(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	sawCreate := false
	for _, row := range rows {
		if strings.Contains(row.Resource+row.Details, token) {
			t.Fatalf("the audit chain carries the token: %+v", row)
		}
		if row.Action == "token_create" {
			sawCreate = true
			if row.ActorKind != "owner" {
				t.Fatalf("token creation attributed to %q", row.ActorKind)
			}
		}
	}
	if !sawCreate {
		t.Fatal("token creation was not audited")
	}
}

// AC (P9-01): the owner MCP exposes the tools SPEC §8.4 names and §8.6 requires
// — and still cannot register a passkey, which §8.6 keeps portal-only.
func TestOwnerMCPHasTheSpecTools(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "seal": "optional",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var token string
	acct := seedAccount(t, dir, "alice")
	func() {
		st := migrated(t, dir)
		defer st.Close()
		owner, err := st.CreateOwnerWithID(ctx, "", "Owner")
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AddMembership(ctx, owner.ID, acct.ID, "admin"); err != nil {
			t.Fatal(err)
		}
		tok := &auth.TokenService{Store: st}
		token, _, err = tok.Create(ctx, owner.ID, "agent", "")
		if err != nil {
			t.Fatal(err)
		}
	}()

	r := startServeAt(t, dir, cfgPath, internal, public)
	cs, err := dialOwnerMCP(ctx, "http://"+r.internal+"/owner/mcp", "Bearer "+token)
	if err != nil {
		t.Fatalf("owner MCP: %v", err)
	}
	defer cs.Close()
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, tool := range list.Tools {
		have[tool.Name] = true
	}
	for _, want := range []string{"audit_query", "call_contact", "export_card", "list_passkeys", "remove_passkey"} {
		if !have[want] {
			t.Fatalf("SPEC §8.4/§8.6 names %s and the owner MCP does not expose it: %v", want, have)
		}
	}
	// §8.6: registration is portal-only. No tool may create a credential.
	for name := range have {
		if strings.Contains(name, "register") || strings.Contains(name, "create_passkey") {
			t.Fatalf("the owner MCP exposes %s; SPEC §8.6 keeps registration portal-only", name)
		}
	}

	// export_card returns the same card peers receive
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "export_card", Arguments: map[string]any{"account_id": acct.ID},
	})
	if err != nil || res.IsError {
		t.Fatalf("export_card: %v %s", err, textOf(res))
	}
	if !strings.Contains(textOf(res), "X-PACT-CERT") {
		t.Fatalf("export_card returned no card: %s", textOf(res))
	}

	// audit_query returns rows and honours its filter
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "audit_query", Arguments: map[string]any{"actor": "system", "limit": 5},
	})
	if err != nil || res.IsError {
		t.Fatalf("audit_query: %v %s", err, textOf(res))
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(textOf(res)), &rows); err != nil {
		t.Fatalf("audit_query body: %s", textOf(res))
	}
	for _, row := range rows {
		if row["ActorKind"] != nil && row["ActorKind"] != "system" {
			t.Fatalf("audit_query ignored its filter: %+v", row)
		}
	}

	// call_contact refuses somebody who is not an active contact
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "call_contact", Arguments: map[string]any{
			"account_id": acct.ID, "contact_fpr": "sha256:stranger", "tool": "send_message",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(textOf(res), "unknown_contact") {
		t.Fatalf("call_contact reached a non-contact: %s", textOf(res))
	}
}

// AC (P9-02): `/` shows the resolved posture, the identities and recent
// activity — and still routes to the wizard while no passkey exists, because
// that gate is what stops a node being claimed by whoever finds it first.
func TestDashboardShowsStateAndKeepsTheWizardGate(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "seal": "optional", "client_cert": "preferred",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	acct := seedAccount(t, dir, "alice")
	r := startServeAt(t, dir, cfgPath, internal, public)
	p := newPortal(t, "http://"+r.internal)

	// no passkey yet: the wizard still owns the page
	page := p.get("/")
	if strings.Contains(page, "Dashboard") {
		t.Fatalf("the dashboard replaced the setup gate:\n%s", firstLine(page))
	}

	// register one, and the dashboard appears
	st := openStoreAt(t, dir)
	owner, err := st.CreateOwnerWithID(ctx, "", "Owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InsertCredential(ctx, store.Credential{
		OwnerID: owner.ID, Kind: "passkey", Tag: "laptop", Data: []byte("{}"),
	}); err != nil {
		t.Fatal(err)
	}
	// a contact and a pending request, so the counts have something to show
	kp, _ := peerIdentity(t, "bob")
	if _, err := st.InsertContact(ctx, store.Contact{
		AccountID: acct.ID, Fingerprint: kp.Fingerprint, SPKI: mustSPKI(t, kp),
		Leaf: kp.Host.LeafDER, Endpoint: kp.Endpoint,
		Status: "active", Permissions: []string{"message.text"},
	}); err != nil {
		t.Fatal(err)
	}

	page = p.get("/api/dashboard")
	for _, want := range []string{"alice", acct.Fingerprint, "optional", "preferred"} {
		if !strings.Contains(page, want) {
			t.Fatalf("the dashboard payload does not carry %q:\n%s", want, page)
		}
	}
	if !strings.Contains(page, "https://"+public) {
		t.Fatalf("the dashboard does not show where people reach this node:\n%s", firstLine(page))
	}
	// The onward navigation lives in the SPA shell now — one component, so a
	// route missing from it is missing everywhere. Held by the route list in
	// internalui's TestEveryNavRouteServesTheShell; nothing to assert here.
}

// AC (P9-03): a restart reconnects what the owner configured. Without this every
// stored integration stayed disconnected until somebody pressed "connect" in the
// portal again, so every tool they back answered `unavailable` forever.
func TestStoredIntegrationsReconnectOnStartup(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "seal": "optional",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	acct := seedAccount(t, dir, "alice")
	// an integration whose upstream is NOT running: startup must not block on it
	func() {
		st := migrated(t, dir)
		defer st.Close()
		if _, err := st.InsertIntegration(ctx, store.Integration{
			AccountID: acct.ID, Slug: "calendar", Transport: "streamable-http",
			Endpoint: "http://127.0.0.1:1/mcp", AuthKind: "none", Status: "disabled",
		}); err != nil {
			t.Fatal(err)
		}
	}()

	// the node still comes up — a dead dependency is not a startup failure
	r := startServeAt(t, dir, cfgPath, internal, public)
	if code := getStatus(t, "http://"+r.internal+"/healthz"); code != 200 {
		t.Fatalf("a down integration blocked startup: %d", code)
	}

	// and the attempt is recorded, so an operator can see it is retrying
	st := openStoreAt(t, dir)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		rows, _ := st.ListAuditEvents(ctx, "")
		for _, row := range rows {
			if row.Action == "integration_connect" {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("startup never attempted to connect the stored integration")
}

// seedSetting writes an owner-set value the way the portal would, BEFORE the
// node starts. Tests that change a knob at runtime must seed it here rather than
// in config.json: SPEC §12.2 puts the file ABOVE the store, so a file-pinned
// knob is deliberately not owner-settable (P10-10d).
func seedSetting(t *testing.T, dir, key, value string) {
	t.Helper()
	st := migrated(t, dir)
	defer st.Close()
	if err := st.PutSetting(context.Background(), store.Setting{Key: key, Value: value}); err != nil {
		t.Fatal(err)
	}
}
