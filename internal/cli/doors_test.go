package cli

// The node's own doors under attack, on a running node (`serve` in-process, the composition an
// owner gets): the portal and the owner MCP, each attack beside the control that must get through.
//
// What each holds, and against which claim:
//   - docs/threat-model.md, boundary 2: "CSRF on state change" — every mutating portal route, read
//     out of the source so that a new one is covered the day it is written, refuses a request with
//     no token, a wrong one, and one forged from another origin of the same SITE (another port on
//     localhost reads the non-HttpOnly CSRF cookie, because cookies are not isolated by port, and
//     SameSite=Strict does not stop a same-site POST);
//   - no portal answer lets another origin read it (no Access-Control-Allow-Origin, preflight
//     included);
//   - boundary 4, "Account → account: nothing crosses" — an account the signed-in owner does not
//     administer is not found on every door that names one, in the query or in the form, and each
//     refusal is on the audit trail; the owner MCP answers another identity's account exactly as it
//     answers one that does not exist, on every tool that takes one, and shows none of it;
//   - bodies are bounded where they enter: the owner MCP and the public listener refuse a body past
//     their cap by the bytes that arrive, whatever the request says its length is.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/node"
)

// doorsNode is a running node with two owners, each administering one identity.
type doorsNode struct {
	r            *running
	st           store.Store
	base         string
	sessionName  string
	csrfName     string
	me           string
	mine, theirs store.Account
	scopedToken  string // me, narrowed to mine
	nodeToken    string // me, node-wide: still only what me administers
	revokedToken string
	sessions     *auth.Service
	ownerMCPURL  string
	publicURL    string
}

func startDoorsNode(t *testing.T) *doorsNode {
	t.Helper()
	ctx := context.Background()
	d := &doorsNode{}
	d.r = runServeWith(t, nil, func(t *testing.T, dir string) {
		st, err := store.OpenSQLite(filepath.Join(dir, "hdtp.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if err := st.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
		for _, s := range []struct {
			slug string
			into *store.Account
		}{{"mine", &d.mine}, {"theirs", &d.theirs}} {
			a, err := idm.CreateAccount(ctx, s.slug, strings.ToUpper(s.slug[:1])+s.slug[1:], identity.AlgoEd25519)
			if err != nil {
				t.Fatal(err)
			}
			*s.into = issueLeafFor(t, idm, a, configPublicURL(t, dir))
		}
		me, err := st.CreateOwnerWithID(ctx, "", "Me")
		if err != nil {
			t.Fatal(err)
		}
		other, err := st.CreateOwnerWithID(ctx, "", "Them")
		if err != nil {
			t.Fatal(err)
		}
		d.me = me.ID
		if err := st.AddMembership(ctx, me.ID, d.mine.ID, "admin"); err != nil {
			t.Fatal(err)
		}
		if err := st.AddMembership(ctx, other.ID, d.theirs.ID, "admin"); err != nil {
			t.Fatal(err)
		}
		tok := &auth.TokenService{Store: st}
		if d.scopedToken, _, err = tok.Create(ctx, me.ID, "scoped", d.mine.ID); err != nil {
			t.Fatal(err)
		}
		if d.nodeToken, _, err = tok.Create(ctx, me.ID, "node", ""); err != nil {
			t.Fatal(err)
		}
		var id string
		if d.revokedToken, id, err = tok.Create(ctx, me.ID, "revoked", ""); err != nil {
			t.Fatal(err)
		}
		if err := tok.Revoke(ctx, id); err != nil {
			t.Fatal(err)
		}
	})
	d.st = openStoreAt(t, d.r.dir)
	cfg, err := loadConfig(filepath.Join(d.r.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	d.base = "http://" + d.r.internal
	d.sessionName, d.csrfName = "hdtp_session_"+cfg.Tag(), "hdtp_csrf_"+cfg.Tag()
	d.sessions = auth.New(d.st)
	d.ownerMCPURL = d.base + "/owner/mcp"
	d.publicURL = "https://" + d.r.public + "/a/mine/mcp"
	return d
}

// session is a fresh signed-in browser for `me`: a session cookie and a CSRF cookie. Fresh per use,
// because a control that reaches /logout ends the session it was sent with.
func (d *doorsNode) session(t *testing.T) (*http.Cookie, *http.Cookie) {
	t.Helper()
	tok, err := d.sessions.MintSession(context.Background(), d.me)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: d.sessionName, Value: tok}, &http.Cookie{Name: d.csrfName, Value: "0123456789abcdef0123456789abcdef"}
}

type answer struct {
	status int
	header http.Header
	body   string
}

func (d *doorsNode) send(t *testing.T, method, path string, body io.Reader, header map[string]string, cookies ...*http.Cookie) answer {
	t.Helper()
	req, err := http.NewRequest(method, d.base+path, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return answer{res.StatusCode, res.Header, string(b)}
}

// portalRoutes is every route the portal registers for a method, read from the source that registers
// it (internal/internalui), with each path parameter filled in. A route added there is attacked here
// the day it is added.
func portalRoutes(t *testing.T, methods string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "internalui", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`"(` + methods + `) (/[^"]*)"`)
	param := regexp.MustCompile(`\{[^}]*\}`)
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			seen[m[1]+" "+param.ReplaceAllString(m[2], "x")] = true
		}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatalf("no %s routes read from internal/internalui: this test is looking in the wrong place", methods)
	}
	return out
}

const (
	csrfRefusal  = "csrf token missing or wrong"
	crossRefusal = "cross-site request refused"
)

func refusedAsForgery(a answer) bool {
	return a.status == http.StatusForbidden && (strings.Contains(a.body, csrfRefusal) || strings.Contains(a.body, crossRefusal))
}

func TestEveryMutatingPortalRouteRefusesAForgedRequest(t *testing.T) {
	d := startDoorsNode(t)
	routes := portalRoutes(t, "POST|PUT|PATCH|DELETE")
	t.Logf("%d mutating routes", len(routes))
	form := func(csrf string) io.Reader {
		v := url.Values{"account": {d.mine.ID}}
		if csrf != "" {
			v.Set("csrf", csrf)
		}
		return strings.NewReader(v.Encode())
	}
	formType := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	with := func(extra map[string]string) map[string]string {
		h := copyHeader(formType)
		for k, v := range extra {
			h[k] = v
		}
		return h
	}
	forgeries := func() int {
		evs, err := d.st.ListAuditEvents(context.Background(), "")
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range evs {
			if e.Action == "portal_request" && (e.Outcome == "csrf" || e.Outcome == "cross_site") {
				n++
			}
		}
		return n
	}
	for _, route := range routes {
		method, path, _ := strings.Cut(route, " ")
		t.Run(route, func(t *testing.T) {
			before := forgeries()
			defer func() {
				// Five forgeries above, each refused and each on the trail; the controls write none.
				if got := forgeries() - before; got != 5 {
					t.Errorf("%d audit rows for five refused forgeries", got)
				}
			}()
			sess, csrf := d.session(t)
			if a := d.send(t, method, path, form(""), formType, sess, csrf); !refusedAsForgery(a) {
				t.Errorf("no CSRF token: %d %q", a.status, trimBody(a.body))
			}
			if a := d.send(t, method, path, form("not-the-token"), formType, sess, csrf); !refusedAsForgery(a) {
				t.Errorf("a wrong CSRF token: %d %q", a.status, trimBody(a.body))
			}
			// Another origin of the same site: a page on another port of localhost reads the CSRF
			// cookie (not HttpOnly, not isolated by port) and posts a form. The browser sends the
			// Strict session cookie (same site) and says where the request came from.
			if a := d.send(t, method, path, form(csrf.Value), with(map[string]string{
				"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "navigate", "Origin": "http://localhost:3000",
			}), sess, csrf); !refusedAsForgery(a) {
				t.Errorf("a same-site form carrying the CSRF value it read: %d %q", a.status, trimBody(a.body))
			}
			if a := d.send(t, method, path, form(csrf.Value), with(map[string]string{
				"Sec-Fetch-Site": "cross-site", "Origin": "null",
			}), sess, csrf); !refusedAsForgery(a) {
				t.Errorf("a cross-site form, Origin null: %d %q", a.status, trimBody(a.body))
			}
			// A browser too old for Fetch Metadata still names a foreign origin.
			if a := d.send(t, method, path, form(csrf.Value), with(map[string]string{"Origin": "http://localhost:3000"}), sess, csrf); !refusedAsForgery(a) {
				t.Errorf("a foreign Origin with no Fetch Metadata: %d %q", a.status, trimBody(a.body))
			}
			// The controls, which must get past the forgery checks: the portal's own page (same
			// origin; under the portal's no-referrer its Origin is `null`), and a client that is no
			// browser at all (no Fetch Metadata, no Origin) holding the token.
			sess, csrf = d.session(t)
			if a := d.send(t, method, path, form(csrf.Value), with(map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "null"}), sess, csrf); refusedAsForgery(a) {
				t.Errorf("the portal's own same-origin request was refused: %q", trimBody(a.body))
			}
			sess, csrf = d.session(t)
			if a := d.send(t, method, path, form(csrf.Value), formType, sess, csrf); refusedAsForgery(a) {
				t.Errorf("a non-browser client holding the token was refused: %q", trimBody(a.body))
			}
		})
	}
}

// A repeated csrf field is judged by its first value: the one the page wrote. A forger who could put
// a valid value anywhere in the form has the token already, so the order decides nothing for them;
// what must not happen is a wrong first value let through by a right second.
func TestARepeatedCSRFFieldIsJudgedByItsFirstValue(t *testing.T) {
	d := startDoorsNode(t)
	const route = "/invites/create"
	sess, csrf := d.session(t)
	body := func(values ...string) io.Reader {
		v := url.Values{"account": {d.mine.ID}, "csrf": values}
		return strings.NewReader(v.Encode())
	}
	h := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if a := d.send(t, "POST", route, body("wrong", csrf.Value), h, sess, csrf); !refusedAsForgery(a) {
		t.Errorf("a wrong first csrf followed by the right one: %d %q", a.status, trimBody(a.body))
	}
	if a := d.send(t, "POST", route, body(csrf.Value, "wrong"), h, sess, csrf); refusedAsForgery(a) || a.status >= 400 {
		t.Errorf("the right first csrf: %d %q", a.status, trimBody(a.body))
	}
}

// No answer of the portal lets another origin read it: no Access-Control-Allow-Origin, on a preflight
// or on the answer itself, for any route.
func TestNoPortalAnswerAllowsAnotherOrigin(t *testing.T) {
	d := startDoorsNode(t)
	for _, route := range append(portalRoutes(t, "GET"), portalRoutes(t, "POST|PUT|PATCH|DELETE")...) {
		method, path, _ := strings.Cut(route, " ")
		sess, csrf := d.session(t)
		for _, a := range []answer{
			d.send(t, "OPTIONS", path, nil, map[string]string{
				"Origin": "https://evil.example", "Access-Control-Request-Method": method,
				"Access-Control-Request-Headers": "x-hdtp-csrf",
			}, sess, csrf),
			d.send(t, method, path, nil, map[string]string{"Origin": "https://evil.example", "X-HDTP-Csrf": csrf.Value}, sess, csrf),
		} {
			for _, h := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Headers"} {
				if v := a.header.Get(h); v != "" {
					t.Errorf("%s answers %s: %s", route, h, v)
				}
			}
		}
	}
}

// An account the signed-in owner does not administer is not found, however the request names it: in
// the query, in the form, or in the form beside one of their own in the query. Each refusal writes
// one audit row. The control: their own account is served.
func TestAnotherOwnersAccountIsNotFoundAndTheRefusalAudited(t *testing.T) {
	d := startDoorsNode(t)
	ctx := context.Background()
	rows := func() int {
		evs, err := d.st.ListAuditEvents(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range evs {
			if e.Action == "portal_request" && e.Outcome == "refused" && strings.Contains(e.Resource, "account:"+d.theirs.ID) {
				n++
			}
		}
		return n
	}
	// The control.
	sess, csrf := d.session(t)
	if a := d.send(t, "GET", "/api/contacts?account="+d.mine.ID, nil, nil, sess, csrf); a.status != 200 {
		t.Fatalf("the owner's own contacts: %d %q", a.status, trimBody(a.body))
	}
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	for _, route := range append(portalRoutes(t, "GET"), portalRoutes(t, "POST|PUT|PATCH|DELETE")...) {
		method, path, _ := strings.Cut(route, " ")
		if slices.Contains([]string{"/login", "/login/begin", "/login/finish", "/setup", "/setup/begin", "/setup/finish", "/healthz", "/logout"}, path) ||
			strings.HasPrefix(path, "/wallet/") {
			continue // no session is asked for, or none is kept: nothing there is about an account
		}
		t.Run(route, func(t *testing.T) {
			type naming struct {
				why   string
				query string
				body  url.Values
			}
			cases := []naming{{"in the query", "?account=" + d.theirs.ID, nil}}
			if method != "GET" {
				cases = append(cases,
					naming{"in the form", "", url.Values{"account": {d.theirs.ID}}},
					naming{"in the form, beside their own in the query", "?account=" + d.mine.ID, url.Values{"account": {d.theirs.ID}}},
					naming{"as the form's second value", "", url.Values{"account": {d.mine.ID, d.theirs.ID}}},
				)
			}
			for _, c := range cases {
				sess, csrf := d.session(t)
				before := rows()
				var body io.Reader
				h := map[string]string{"X-HDTP-Csrf": csrf.Value}
				if c.body != nil {
					body = strings.NewReader(c.body.Encode())
					h["Content-Type"] = form["Content-Type"]
				}
				a := d.send(t, method, path+c.query, body, h, sess, csrf)
				if a.status != http.StatusNotFound {
					t.Errorf("another owner's account %s: %d %q", c.why, a.status, trimBody(a.body))
				}
				if strings.Contains(a.body, d.theirs.Slug) || strings.Contains(a.body, d.theirs.DisplayName) {
					t.Errorf("another owner's account %s: the answer names it: %q", c.why, trimBody(a.body))
				}
				if got := rows() - before; got != 1 {
					t.Errorf("another owner's account %s: %d audit rows for the refusal, want 1", c.why, got)
				}
			}
		})
	}
}

// The owner MCP answers another identity's account exactly as it answers one that does not exist —
// on every tool that takes an account, for a token narrowed to one account and for a node-wide token
// whose owner administers only that one — and the answer carries nothing of it. Every refusal is on
// the trail. The control: the same tool on the owner's own account is not refused for its account.
func TestTheOwnerMCPNeverReachesAnotherIdentity(t *testing.T) {
	d := startDoorsNode(t)
	ctx := context.Background()
	list, err := dialOwnerMCP(ctx, d.ownerMCPURL, "Bearer "+d.nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer list.Close()
	tools, err := list.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var scoped []string
	schemas := map[string]toolSchema{}
	for _, tl := range tools.Tools {
		raw, _ := json.Marshal(tl.InputSchema)
		var schema toolSchema
		_ = json.Unmarshal(raw, &schema)
		if _, ok := schema.Properties["account_id"]; ok {
			scoped = append(scoped, tl.Name)
			schemas[tl.Name] = schema
		}
	}
	if len(scoped) == 0 {
		t.Fatalf("no tool of %d takes an account_id: the schema is not being read", len(tools.Tools))
	}
	t.Logf("%d of %d tools take an account", len(scoped), len(tools.Tools))
	refusedRows := func() int {
		evs, err := d.st.ListAuditEvents(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range evs {
			if e.Action == "owner_mcp_call" && e.Outcome == "refused" {
				n++
			}
		}
		return n
	}
	text := func(res *mcp.CallToolResult) string {
		var b strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				b.WriteString(tc.Text)
			}
		}
		return b.String()
	}
	for _, token := range []struct{ name, bearer string }{{"narrowed", d.scopedToken}, {"node-wide", d.nodeToken}} {
		cs, err := dialOwnerMCP(ctx, d.ownerMCPURL, "Bearer "+token.bearer)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range scoped {
			call := func(account string) (*mcp.CallToolResult, error) {
				args := filled(schemas[name])
				args["account_id"] = account
				return cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
			}
			before := refusedRows()
			theirs, err1 := call(d.theirs.ID)
			nobody, err2 := call("00000000000000000000000000000000")
			if err1 != nil || err2 != nil {
				t.Errorf("%s %s: %v / %v", token.name, name, err1, err2)
				continue
			}
			if !theirs.IsError || text(theirs) != text(nobody) || theirs.IsError != nobody.IsError {
				t.Errorf("%s %s: another identity's account answered %q, one that does not exist %q", token.name, name, text(theirs), text(nobody))
			}
			if s := text(theirs); strings.Contains(s, d.theirs.Slug) || strings.Contains(s, d.theirs.DisplayName) {
				t.Errorf("%s %s: the refusal names the other identity: %q", token.name, name, s)
			}
			if got := refusedRows() - before; got != 2 {
				t.Errorf("%s %s: %d refused rows for two refusals", token.name, name, got)
			}
			own, err := call(d.mine.ID)
			if err != nil {
				t.Errorf("%s %s on its own account: %v", token.name, name, err)
			} else if own.IsError && text(own) == text(theirs) {
				t.Errorf("%s %s: the owner's own account answered as another's: %q", token.name, name, text(own))
			}
		}
		cs.Close()
	}
	// A revoked token and none at all reach nothing.
	for _, bearer := range []string{"", "Bearer " + d.revokedToken} {
		if cs, err := dialOwnerMCP(ctx, d.ownerMCPURL, bearer); err == nil {
			cs.Close()
			t.Errorf("the owner MCP accepted %q", bearer)
		}
	}
}

// toolSchema is what these tests read of a tool's input schema.
type toolSchema struct {
	Properties map[string]struct {
		Type any `json:"type"`
	} `json:"properties"`
	Required []string `json:"required"`
}

// filled is an argument object carrying every property the schema requires, each a plausible value
// of its type, so that a call is judged on its account and not refused by the schema first.
func filled(s toolSchema) map[string]any {
	out := map[string]any{}
	for _, name := range s.Required {
		typ := fmt.Sprint(s.Properties[name].Type)
		switch {
		case strings.Contains(typ, "array"):
			out[name] = []any{}
		case strings.Contains(typ, "integer"), strings.Contains(typ, "number"):
			out[name] = 1
		case strings.Contains(typ, "boolean"):
			out[name] = false
		case strings.Contains(typ, "object"):
			out[name] = map[string]any{}
		default:
			out[name] = "x"
		}
	}
	return out
}

// chunked is a body of n bytes with no length declared: what arrives is all the server can count.
type chunked struct{ n int }

func (c *chunked) Read(p []byte) (int, error) {
	if c.n <= 0 {
		return 0, io.EOF
	}
	k := min(len(p), c.n)
	for i := range p[:k] {
		p[i] = ' '
	}
	c.n -= k
	return k, nil
}

// Bodies are bounded where they enter, by the bytes that arrive: the owner MCP at
// OwnerMCPMaxBodyBytes, the public listener at node.MaxBodyBytes (SPEC §5.7: 8 MiB, sized for 5 MiB of
// inline media). At each door a handshake padded to the byte just under the cap is answered — the
// control, and the half that found the listener refusing everything past the MCP SDK's own 4 MiB — and
// one byte past it, sent with no declared length, is refused 413 too_large.
func TestBodiesPastTheCapAreRefusedByTheBytesThatArrive(t *testing.T) {
	d := startDoorsNode(t)
	handshake := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	insecure := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- the node's own self-issued certificate, in a test
	}}
	post := func(c *http.Client, u, bearer string, body io.Reader, length int64) (int, string, error) {
		req, err := http.NewRequest("POST", u, body)
		if err != nil {
			return 0, "", err
		}
		req.ContentLength = length
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		res, err := c.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return res.StatusCode, string(b), nil
	}
	for _, door := range []struct {
		name, url, bearer string
		client            *http.Client
		limit             int64
	}{
		{"owner MCP", d.ownerMCPURL, d.nodeToken, http.DefaultClient, OwnerMCPMaxBodyBytes},
		{"public listener", d.publicURL, "", insecure, node.MaxBodyBytes},
	} {
		// JSON allows whitespace after the value: the same handshake, one byte short of the cap.
		padded := handshake + strings.Repeat(" ", int(door.limit)-len(handshake))
		if code, body, err := post(door.client, door.url, door.bearer, strings.NewReader(padded), -1); err != nil || code != 200 {
			t.Errorf("%s: a handshake of exactly the cap (%d bytes) answered %d %q (%v)", door.name, door.limit, code, trimBody(body), err)
		}
		code, body, err := post(door.client, door.url, door.bearer, &chunked{int(door.limit) + 1}, -1)
		if err != nil || code != http.StatusRequestEntityTooLarge || !strings.Contains(body, "too_large") {
			t.Errorf("%s: %d bytes with no declared length answered %d %q (%v), want 413 too_large", door.name, door.limit+1, code, trimBody(body), err)
		}
	}
}

func copyHeader(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func trimBody(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		return s[:160] + fmt.Sprintf("… (%d bytes)", len(s))
	}
	return s
}
