package internalui

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
)

func (c *canaryStore) ListTokens(ctx context.Context) ([]store.Token, error) {
	if err := c.err("ListTokens"); err != nil {
		return nil, err
	}
	return c.Store.ListTokens(ctx)
}

func (c *canaryStore) ListCredentialsByKind(ctx context.Context, kind string) ([]store.Credential, error) {
	if err := c.err("ListCredentialsByKind"); err != nil {
		return nil, err
	}
	return c.Store.ListCredentialsByKind(ctx, kind)
}

func (c *canaryStore) ListSettings(ctx context.Context) ([]store.Setting, error) {
	if err := c.err("ListSettings"); err != nil {
		return nil, err
	}
	return c.Store.ListSettings(ctx)
}

// The owners page and the Settings page answer 500 when a list they render cannot be read: the
// owners page's passkeys and tokens, and Settings' stored values, adapter credentials, pairings and
// presets. Each was read with its error dropped, so a failed read rendered as nothing registered,
// nothing stored, nothing paired. Each row's control, nothing failing, is a 200 carrying the row.
func TestTheOwnersAndSettingsPagesAnswerAFailedReadAs500(t *testing.T) {
	ctx := context.Background()
	var cs *canaryStore
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		cs = &canaryStore{Store: st, fail: map[string]bool{}}
		MountOwnerPages(mux, OwnersDeps{Store: st, Tokens: &auth.TokenService{Store: cs}, Passkeys: auth.New(cs).ListPasskeys})
		settingRows := func(ctx context.Context, failAs string) ([]store.Setting, error) {
			if err := cs.err(failAs); err != nil {
				return nil, err
			}
			return cs.ListSettings(ctx)
		}
		MountSettingsPages(mux, SettingsDeps{Owners: st, Effective: func() []core.Effective { return nil },
			Pending: func(ctx context.Context) (map[string]string, error) {
				rows, err := settingRows(ctx, "Pending")
				out := map[string]string{}
				for _, r := range rows {
					out[r.Key] = r.Value
				}
				return out, err
			},
			AdapterSettings: func(ctx context.Context) ([]AdapterSetting, error) {
				rows, err := settingRows(ctx, "AdapterSettings")
				var out []AdapterSetting
				for _, r := range rows {
					out = append(out, AdapterSetting{Key: r.Key, Set: true})
				}
				return out, err
			},
			Paired: func(ctx context.Context) (map[string]bool, error) {
				if _, err := settingRows(ctx, "Paired"); err != nil {
					return nil, err
				}
				return map[string]bool{"ingress-passthrough": true}, nil
			},
			Pair:   func(context.Context, PairInput) (PairResult, error) { return PairResult{}, nil },
			Unpair: func(context.Context, string) error { return nil },
			Presets: func(context.Context) (map[string][]string, error) {
				if err := cs.err("Presets"); err != nil {
					return nil, err
				}
				return map[string][]string{"canary-preset": {"message.text"}}, nil
			},
			SavePreset:   func(context.Context, string, []string) error { return nil },
			DeletePreset: func(context.Context, string) error { return nil },
		})
	})
	me, session := e.signIn(t, "Me")
	if _, _, err := (&auth.TokenService{Store: e.st}).Create(ctx, me, "canary-token", ""); err != nil {
		t.Fatal(err)
	}
	if err := e.st.PutSetting(ctx, store.Setting{Key: "tunnel.ingress-passthrough.subdomain", Value: "me"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path, fail, shows string
	}{
		{"/api/owners", "ListTokens", "canary-token"},
		{"/api/owners", "ListCredentialsByKind", `"passkeys":[]`},
		{"/api/settings", "Pending", "tunnel.ingress-passthrough.subdomain"},
		{"/api/settings", "AdapterSettings", `"adapter_settings":[{`},
		{"/api/settings", "Paired", `"paired":{"ingress-passthrough":true}`},
		{"/api/settings", "Presets", "canary-preset"},
	} {
		cs.fail = map[string]bool{c.fail: true}
		rec := e.do(t, http.MethodGet, c.path, nil, []*http.Cookie{session})
		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), pageCanary) {
			t.Errorf("GET %s with %s failing: %d %s; want 500 with no store text", c.path, c.fail, rec.Code, rec.Body.String())
		}
		cs.fail = map[string]bool{}
		if rec := e.do(t, http.MethodGet, c.path, nil, []*http.Cookie{session}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), c.shows) {
			t.Errorf("GET %s, the control: %d %s; want %s", c.path, rec.Code, rec.Body.String(), c.shows)
		}
	}
}
