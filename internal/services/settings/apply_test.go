package settings

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// accountsFailOnce is the store with its first ListAccounts refused: what the seal's apply reads to
// re-seal every account.
type accountsFailOnce struct {
	store.Store
	mu     sync.Mutex
	failed bool
}

func (f *accountsFailOnce) ListAccounts(ctx context.Context) ([]store.Account, error) {
	f.mu.Lock()
	first := !f.failed
	f.failed = true
	f.mu.Unlock()
	if first {
		return nil, errors.New("injected: the store refused the read")
	}
	return f.Store.ListAccounts(ctx)
}

// A save whose first knob cannot be applied to the running node still applies the second and
// announces both, since both are stored; the portal says what was saved and what was not applied,
// and audits the write ok beside the failed apply.
func TestAKnobThatCannotBeAppliedLeavesTheOthersApplied(t *testing.T) {
	dir := t.TempDir()
	a, _, aRows, bus := processOver(t, dir, true, func(st store.Store) store.Store { return &accountsFailOnce{Store: st} })
	b, _, _ := process(t, dir, false)
	events, unsubscribe := bus.SubscribeSized("", 64)
	defer unsubscribe()

	mux := http.NewServeMux()
	internalui.MountSettingsPages(mux, a.Deps())
	form := url.Values{"seal": {"required"}, "limit.contacts": {"7"}}
	req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var page struct {
		Notice string `json:"notice"`
		Error  bool   `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("%d %s: %v", rec.Code, rec.Body, err)
	}
	if want := "Saved seal, limit.contacts; could not apply seal: the node could not complete this."; page.Notice != want || !page.Error {
		t.Errorf("notice %q (error %v), want %q (error true)", page.Notice, page.Error, want)
	}
	aRows.mu.Lock()
	audited := slices.Clone(aRows.rows)
	aRows.mu.Unlock()
	for _, want := range []string{"settings_save keys:seal,limit.contacts ok", "settings_apply keys:seal error"} {
		if !slices.Contains(audited, want) {
			t.Errorf("audit %v has no %q", audited, want)
		}
	}
	if slices.Contains(audited, "settings_save keys:seal,limit.contacts error") {
		t.Errorf("audit %v says the stored save failed", audited)
	}
	if now := settingValues(t, a.store); now["seal"] != "required" || now["limit.contacts"] != "7" {
		t.Errorf("stored %v, want both", now)
	}
	if n := a.ContactCap(); n != 7 {
		t.Errorf("the saving process's contact cap is %d: it did not apply limit.contacts, saved after the seal it could not apply", n)
	}
	published := map[string]bool{}
	eventually(t, "both stored keys announced", func() bool {
		for {
			select {
			case e := <-events:
				if e.Kind == messaging.EventSettings {
					published[e.Ref] = true
				}
				continue
			default:
			}
			return published["seal"] && published["limit.contacts"]
		}
	})
	eventually(t, "the other process taking limit.contacts", func() bool { return b.ContactCap() == 7 })
}
