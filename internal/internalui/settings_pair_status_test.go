package internalui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
)

// A refused pairing or unpairing answers its code's status (pageStatus), as the contacts and
// messages actions do, with the page's state and the notice beside it: not_found 404, conflict 409,
// bad_request 400, a failure of the node 500. The control, a pairing and an unpairing that get
// through, answer 200.
func TestARefusedPairingOrUnpairingAnswersItsCodesStatus(t *testing.T) {
	deps := func(err error) SettingsDeps {
		return SettingsDeps{
			Effective: func() []core.Effective { return []core.Effective{{Key: "seal"}} },
			Pair: func(context.Context, PairInput) (PairResult, error) {
				return PairResult{PublicName: "me.example", Adapter: "x"}, err
			},
			Unpair: func(context.Context, string) error { return err },
		}
	}
	post := func(d SettingsDeps, path string, form url.Values) *httptest.ResponseRecorder {
		mux := http.NewServeMux()
		MountSettingsPages(mux, d)
		req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	pair := url.Values{"pair_url": {"https://ingress.example/pair"}, "token": {"t"}, "subdomain": {"me"}}
	unpair := url.Values{"adapter": {"x"}}
	for _, c := range []struct {
		name   string
		err    error
		status int
	}{
		{"not found", fmt.Errorf("pairing: %w", store.ErrNotFound), http.StatusNotFound},
		{"conflict", fmt.Errorf("unpair: %w", contacts.ErrWrongState), http.StatusConflict},
		{"bad request", refusal.BadRequest("create an account before pairing", nil), http.StatusBadRequest},
		{"a failure of the node", errors.New("pq: canary"), http.StatusInternalServerError},
		{"the control", nil, http.StatusOK},
	} {
		for path, form := range map[string]url.Values{"/settings/pair": pair, "/settings/unpair": unpair} {
			rr := post(deps(c.err), path, form)
			if rr.Code != c.status || !strings.Contains(rr.Body.String(), `"reach"`) {
				t.Errorf("%s %s: %d, want %d with the page's state: %s", path, c.name, rr.Code, c.status, rr.Body.String())
			}
			if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
				t.Errorf("%s %s: Cache-Control %q", path, c.name, cc)
			}
		}
	}
}
