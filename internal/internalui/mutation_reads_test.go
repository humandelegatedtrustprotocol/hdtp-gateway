package internalui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
)

// armingStore is a canaryStore whose token writes succeed and then fail the read named by arm, so
// the read fails after the mutation and not before it.
type armingStore struct {
	*canaryStore
	arm string
}

func (a *armingStore) InsertToken(ctx context.Context, id, owner, label string, sum []byte, account string, at int64) error {
	if err := a.Store.InsertToken(ctx, id, owner, label, sum, account, at); err != nil {
		return err
	}
	a.fail[a.arm] = true
	return nil
}

func (a *armingStore) RevokeToken(ctx context.Context, id string, at int64) error {
	if err := a.Store.RevokeToken(ctx, id, at); err != nil {
		return err
	}
	a.fail[a.arm] = true
	return nil
}

func (c *canaryStore) ListMembershipsByOwner(ctx context.Context, owner string) ([]store.Membership, error) {
	if err := c.err("ListMembershipsByOwner"); err != nil {
		return nil, err
	}
	return c.Store.ListMembershipsByOwner(ctx, owner)
}

func (e *portalEnv) postPage(t *testing.T, path string, form url.Values, session *http.Cookie) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Host = "localhost:8080"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "hdtp_csrf", Value: "tok"})
	req.Header.Set("X-HDTP-Csrf", "tok")
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), pageCanary) {
		t.Errorf("POST %s answered the store's text: %s", path, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// A token create, a revoke and a passkey removal that succeeded keep their answer when a read of the
// page after them fails: 200 with page_error "store", the notice, and a new token's one appearance,
// and none of the lists, which were not read. They answered 500 {"error":"store"}, and the token,
// shown nowhere else, was lost. The control, nothing failing, is the whole page.
func TestAnOwnersMutationKeepsItsAnswerWhenThePageCannotBeRead(t *testing.T) {
	ctx := context.Background()
	var as *armingStore
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		as = &armingStore{canaryStore: &canaryStore{Store: st, fail: map[string]bool{}}}
		MountOwnerPages(mux, OwnersDeps{Store: as, Tokens: &auth.TokenService{Store: as}, Passkeys: auth.New(as).ListPasskeys,
			Remove: func(context.Context, string) error { as.fail[as.arm] = true; return nil }})
	})
	me, session := e.signIn(t, "Me")
	for _, read := range []string{"ListCredentialsByKind", "ListTokens", "ListAccounts", "ListMembershipsByOwner"} {
		as.arm = read
		as.fail = map[string]bool{}
		code, body := e.postPage(t, "/owners/tokens/create", url.Values{"label": {"agent-" + read}}, session)
		tok, _ := body["new_token"].(string)
		if code != http.StatusOK || body["page_error"] != "store" || tok == "" || body["tokens"] != nil {
			t.Errorf("token create, %s failing after it: %d %v; want 200, page_error store, the new token, no lists", read, code, body)
		}
		as.fail = map[string]bool{}
		_, id, err := (&auth.TokenService{Store: e.st}).Create(ctx, me, "revoke-"+read, "")
		if err != nil {
			t.Fatal(err)
		}
		as.fail = map[string]bool{}
		code, body = e.postPage(t, "/owners/tokens/"+id+"/revoke", url.Values{}, session)
		if code != http.StatusOK || body["page_error"] != "store" || !strings.HasPrefix(str(body["notice"]), "Token revoked") {
			t.Errorf("token revoke, %s failing after it: %d %v; want 200, page_error store, its notice", read, code, body)
		}
		as.fail = map[string]bool{}
		code, body = e.postPage(t, "/owners/passkeys/pk1/remove", url.Values{}, session)
		if code != http.StatusOK || body["page_error"] != "store" || body["notice"] != "Passkey removed." {
			t.Errorf("passkey remove, %s failing after it: %d %v; want 200, page_error store, its notice", read, code, body)
		}
	}
	as.arm, as.fail = "", map[string]bool{}
	code, body := e.postPage(t, "/owners/tokens/create", url.Values{"label": {"control"}}, session)
	if code != http.StatusOK || body["page_error"] != nil || body["new_token"] == "" || body["tokens"] == nil {
		t.Errorf("the control, nothing failing: %d %v; want the whole page and the token", code, body)
	}
}

// A pairing, a preset save and a preset delete that succeeded keep their answer when a read of the
// Settings page after them fails: 200 with page_error "store" and the notice (a trust-on-first-use
// pairing's ingress key, whose one-time token is spent), and none of the lists. They answered 500
// {"error":"store"}. A refused post keeps its status and its refusal the same way. The control,
// nothing failing, is the whole page.
func TestASettingsMutationKeepsItsAnswerWhenThePageCannotBeRead(t *testing.T) {
	var cs *canaryStore
	arm := ""
	armed := func() { cs.fail[arm] = true }
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		cs = &canaryStore{Store: st, fail: map[string]bool{}}
		failing := func(m string) error { return cs.err(m) }
		MountSettingsPages(mux, SettingsDeps{Owners: cs, Effective: func() []core.Effective { return nil },
			Pending: func(context.Context) (map[string]string, error) { return map[string]string{}, failing("Pending") },
			AdapterSettings: func(context.Context) ([]AdapterSetting, error) {
				return []AdapterSetting{{Key: "tunnel.x.y", Set: true}}, failing("AdapterSettings")
			},
			Paired:   func(context.Context) (map[string]bool, error) { return map[string]bool{}, failing("Paired") },
			Accounts: func(context.Context) ([]AccountChoice, error) { return nil, failing("Accounts") },
			Storage:  func(context.Context) ([]StorageRow, error) { return nil, failing("Storage") },
			Pair: func(_ context.Context, in PairInput) (PairResult, error) {
				if in.Subdomain == "taken" {
					armed()
					return PairResult{}, refusal.Conflict("the node is not serving yet", nil)
				}
				armed()
				return PairResult{PublicName: "me.example", Adapter: "ingress-passthrough", Fingerprint: "sha256:canary-key"}, nil
			},
			Unpair: func(context.Context, string) error { return nil },
			Presets: func(context.Context) (map[string][]string, error) {
				return map[string][]string{"p": {}}, failing("Presets")
			},
			SavePreset:   func(context.Context, string, []string) error { armed(); return nil },
			DeletePreset: func(context.Context, string) error { armed(); return nil },
		})
	})
	_, session := e.signIn(t, "Me")
	pairForm := func(sub string) url.Values {
		return url.Values{"pair_url": {"https://ingress.example/pair"}, "token": {"t"}, "subdomain": {sub}}
	}
	posts := []struct {
		what, path string
		form       url.Values
		status     int
		says       string
		refused    bool
	}{
		{"a pairing on first use", "/settings/pair", pairForm("me"), http.StatusOK, "The ingress key is sha256:canary-key", false},
		{"a refused pairing", "/settings/pair", pairForm("taken"), http.StatusConflict, "pairing refused", true},
		{"a preset save", "/settings/presets", url.Values{"name": {"family"}, "perm": {"message.text"}}, http.StatusOK, "Preset saved.", false},
		{"a preset delete", "/settings/presets/family/delete", url.Values{}, http.StatusOK, "Preset deleted.", false},
	}
	for _, read := range []string{"Pending", "AdapterSettings", "Paired", "Presets", "Accounts", "ListMembershipsByOwner", "Storage"} {
		arm = read
		for _, p := range posts {
			cs.fail = map[string]bool{}
			code, body := e.postPage(t, p.path, p.form, session)
			notice := str(body["notice"])
			if code != p.status || body["page_error"] != "store" || !strings.Contains(notice, p.says) || body["error"] != p.refused || body["presets"] != nil || body["reach"] != nil {
				t.Errorf("%s, %s failing after it: %d %v; want %d, page_error store, %q, error %v, no lists", p.what, read, code, body, p.status, p.says, p.refused)
			}
		}
	}
	arm, cs.fail = "", map[string]bool{}
	code, body := e.postPage(t, "/settings/pair", pairForm("me"), session)
	if code != http.StatusOK || body["page_error"] != nil || body["presets"] == nil || !strings.Contains(str(body["notice"]), "sha256:canary-key") {
		t.Errorf("the control, nothing failing: %d %v; want the whole page and the notice", code, body)
	}
}

// str is v when it is a string, "" otherwise.
func str(v any) string {
	s, _ := v.(string)
	return s
}

// A read of the owners or the Settings page answers a failed read 500 whatever its method: the mux
// serves HEAD from the GET pattern, and a HEAD that answered by method was a 200 with page_error,
// as if it were a post. The control, nothing failing, is a 200.
func TestAReadOfThePageAnswersAFailedRead500ForEveryMethod(t *testing.T) {
	var cs *canaryStore
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		cs = &canaryStore{Store: st, fail: map[string]bool{}}
		MountOwnerPages(mux, OwnersDeps{Store: cs, Tokens: &auth.TokenService{Store: cs}, Passkeys: auth.New(cs).ListPasskeys})
		MountSettingsPages(mux, SettingsDeps{Owners: cs, Effective: func() []core.Effective { return nil },
			Pending: func(context.Context) (map[string]string, error) { return map[string]string{}, cs.err("Pending") }})
	})
	_, session := e.signIn(t, "Me")
	for _, page := range []struct{ path, read string }{{"/api/settings", "Pending"}, {"/api/owners", "ListTokens"}} {
		for _, m := range []string{http.MethodGet, http.MethodHead} {
			cs.fail = map[string]bool{page.read: true}
			rec := e.do(t, m, page.path, nil, []*http.Cookie{session})
			if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "page_error") {
				t.Errorf("%s %s, %s failing: %d %s; want 500 {\"error\":\"store\"}", m, page.path, page.read, rec.Code, rec.Body.String())
			}
			cs.fail = map[string]bool{}
			if rec := e.do(t, m, page.path, nil, []*http.Cookie{session}); rec.Code != http.StatusOK {
				t.Errorf("the control, %s %s with nothing failing: %d; want 200", m, page.path, rec.Code)
			}
		}
	}
}

// Selecting an ingress tunnel when the pairings cannot be read answers the store's failure: 500 with
// page_error "store", nothing saved, audited "error". The failed read was taken as "not paired" and
// answered as the owner's mistake (a 200 telling them to pair first, audited bad_request). A save
// stores every knob the form submitted or none: the portal posts public_url beside the tunnel, and
// public_url comes first, so a refusal of the tunnel (the pairing read, an unpaired adapter, the
// validator) must leave public_url unsaved too, with the refusal its one audit row. Each key was
// saved as it was checked, so public_url was stored with no row. The control saves both, one row.
func TestSelectingAnIngressTunnelAnswersAFailedPairingRead(t *testing.T) {
	var cs *canaryStore
	var saved, outcomes []string
	paired := map[string]bool{"ingress-passthrough": true}
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		cs = &canaryStore{Store: st, fail: map[string]bool{}}
		MountSettingsPages(mux, SettingsDeps{Owners: cs,
			Effective: func() []core.Effective { return []core.Effective{{Key: "public_url"}, {Key: "tunnel"}} },
			Save: func(_ context.Context, values []SettingValue) error {
				for _, v := range values {
					saved = append(saved, v.Key+"="+v.Value)
				}
				return nil
			},
			Paired: func(context.Context) (map[string]bool, error) {
				if err := cs.err("Paired"); err != nil {
					return nil, err
				}
				return paired, nil
			},
			Audit: func(action, resource, outcome string) { outcomes = append(outcomes, action+" "+resource+" "+outcome) },
		})
	})
	_, session := e.signIn(t, "Me")
	for _, c := range []struct {
		name, tunnel, failing string
		status                int
		audited               string
	}{
		{"the pairings failing", "ingress-passthrough", "Paired", http.StatusInternalServerError, "settings_save key:tunnel value:ingress-passthrough error"},
		{"an adapter not paired", "ingress-terminate", "", http.StatusOK, "settings_save key:tunnel value:ingress-terminate bad_request"},
		{"a value the validator refuses", "nonesuch", "", http.StatusOK, "settings_save key:tunnel bad_request"},
	} {
		cs.fail, saved, outcomes = map[string]bool{c.failing: c.failing != ""}, nil, nil
		code, body := e.postPage(t, "/settings", url.Values{"public_url": {"https://n.example"}, "tunnel": {c.tunnel}}, session)
		if code != c.status || body["error"] != true || len(saved) != 0 || strings.Join(outcomes, ",") != c.audited {
			t.Errorf("public_url and tunnel %s, %s: %d %v, saved %v, audited %v; want %d, error, nothing saved, audited %q only",
				c.tunnel, c.name, code, body, saved, outcomes, c.status, c.audited)
		}
		if c.failing != "" && body["page_error"] != "store" {
			t.Errorf("%s: page_error %v; want store", c.name, body["page_error"])
		}
	}
	cs.fail, outcomes, saved = map[string]bool{}, nil, nil
	code, body := e.postPage(t, "/settings", url.Values{"public_url": {"https://n.example"}, "tunnel": {"ingress-passthrough"}}, session)
	if code != http.StatusOK || body["error"] != false || strings.Join(saved, ",") != "public_url=https://n.example,tunnel=ingress-passthrough" ||
		strings.Join(outcomes, ",") != "settings_save keys:public_url,tunnel ok" {
		t.Errorf("the control, the pairing read: %d %v, saved %v, audited %v; want 200, both saved, one ok row", code, body, saved, outcomes)
	}
}
