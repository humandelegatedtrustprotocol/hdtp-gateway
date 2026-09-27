package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// refusingProgress is a store that does everything except record a campaign's progress.
type refusingProgress struct{ store.Store }

func (refusingProgress) UpsertMoveFanout(context.Context, store.MoveFanout) error {
	return errors.New("disk full")
}

// A move campaign's progress rows ARE its durability: "re-run to resume" means read them. The
// write's error was discarded (`_ =`), so a store that could not record looked exactly like one
// that had. Two outcomes have to stay apart: contacts that were not reached, which is ordinary and
// is what the counts are for, and progress that could not be written, which is a fault.
func TestAMoveCampaignSaysWhenItCannotRecordItsProgress(t *testing.T) {
	m, a := leafEnv(t)
	ctx := context.Background()
	for _, fpr := range []string{"sha256:one", "sha256:two"} {
		if _, err := m.Store.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: fpr, Status: "active", Endpoint: "https://" + fpr[7:] + ".example/mcp", Leaf: []byte("leaf")}); err != nil {
			t.Fatal(err)
		}
	}
	camp := Campaign{AccountID: a.ID, NewKid: "sha256:new-leaf"}
	var rows []string
	audit := func(action, resource, outcome string) { rows = append(rows, action+" "+resource+" → "+outcome) }
	now := func() time.Time { return time.Unix(1790000000, 0) }

	// 1. One contact unreachable: counts, and the sentinel — not a fault.
	reached := 0
	ann := &Announcer{Manager: m, Audit: audit, Now: now}
	done, failed, err := ann.Fanout(ctx, camp, "card", func(_ context.Context, c store.Contact, _ string) (string, error) {
		if c.Fingerprint == "sha256:two" {
			return "", errors.New("offline")
		}
		reached++
		return "updated", nil
	})
	if done != 1 || failed != 1 || !errors.Is(err, ErrFanoutIncomplete) {
		t.Fatalf("one reached, one not: done=%d failed=%d err=%v", done, failed, err)
	}
	// And it resumes: the one already told is not told again.
	reached = 0
	done, failed, err = ann.Fanout(ctx, camp, "card", func(context.Context, store.Contact, string) (string, error) { reached++; return "updated", nil })
	if done != 2 || failed != 0 || err != nil || reached != 1 {
		t.Fatalf("the resume must reach only the contact that was missed: done=%d failed=%d err=%v calls=%d", done, failed, err, reached)
	}

	// 2. A store that refuses the progress write. The contacts are still told; the record is what
	// is lost, and that has to come back as an error that is NOT the ordinary one.
	broken := &Announcer{Manager: &Manager{Store: refusingProgress{m.Store}, Keyring: m.Keyring}, Audit: audit, Now: now}
	rows = nil
	_, _, err = broken.Fanout(ctx, Campaign{AccountID: a.ID, NewKid: "sha256:another-leaf"}, "card", func(context.Context, store.Contact, string) (string, error) { return "updated", nil })
	if err == nil || errors.Is(err, ErrFanoutIncomplete) {
		t.Fatalf("progress that could not be recorded was reported as %v", err)
	}
	said := 0
	for _, r := range rows {
		if strings.Contains(r, "progress not recorded") && strings.HasSuffix(r, "→ error") {
			said++
		}
	}
	if said != 2 {
		t.Fatalf("each contact whose progress was lost must be on the chain, once: %d of 2\n%s", said, strings.Join(rows, "\n"))
	}
}

// An import's contacts are owed this host's handshake (PACT §9.2), whatever their status, unless
// the owner blocked them: the campaign after the next leaf walks them beside the active contacts,
// records each outcome as what it was, and clears the mark of every one it told — so the campaign
// after that one walks only the active contacts again.
func TestTheCampaignWalksAnImportsContactsOnceAndNeverABlockedOne(t *testing.T) {
	m, a := leafEnv(t)
	ctx := context.Background()
	made := func(fpr, status string) {
		if _, err := m.Store.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: fpr, Status: status, Endpoint: "https://x.example/mcp", Leaf: []byte("leaf")}); err != nil {
			t.Fatal(err)
		}
	}
	imported := func(fpr, status string) {
		if err := m.Store.ImportContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: fpr, Status: status, TrustFlag: "messages_only", Endpoint: "https://x.example/mcp", Leaf: []byte("leaf")}); err != nil {
			t.Fatal(err)
		}
	}
	made("sha256:here-active", "active")
	made("sha256:here-pending", "pending_out")
	imported("sha256:came-active", "active")
	imported("sha256:came-pending", "pending_out")
	imported("sha256:came-blocked", "blocked")
	// And one whose leaf did not travel: nothing can be sealed to it.
	if err := m.Store.ImportContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:came-leafless", Status: "active", TrustFlag: "messages_only", Endpoint: "https://x.example/mcp"}); err != nil {
		t.Fatal(err)
	}

	var rows []string
	audit := func(action, resource, outcome string) { rows = append(rows, action+" "+resource+" → "+outcome) }
	ann := &Announcer{Manager: m, Audit: audit, Now: func() time.Time { return time.Unix(1790000000, 0) }}
	walk := func(kid string) map[string]bool {
		called := map[string]bool{}
		_, _, err := ann.Fanout(ctx, Campaign{AccountID: a.ID, NewKid: kid}, "card", func(_ context.Context, c store.Contact, _ string) (string, error) {
			called[c.Fingerprint] = true
			if c.Fingerprint == "sha256:came-pending" {
				return "requested", nil
			}
			return "updated", nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return called
	}
	called := walk("sha256:first")
	want := map[string]bool{"sha256:here-active": true, "sha256:came-active": true, "sha256:came-pending": true}
	if len(called) != len(want) {
		t.Fatalf("the first campaign after an import called %v, want exactly %v", called, want)
	}
	for fpr := range want {
		if !called[fpr] {
			t.Fatalf("the first campaign after an import did not call %s: %v", fpr, called)
		}
	}
	if !strings.Contains(strings.Join(rows, "\n"), "contact:sha256:came-pending → requested") {
		t.Fatalf("the audit row must name what became of the contact:\n%s", strings.Join(rows, "\n"))
	}
	if !strings.Contains(strings.Join(rows, "\n"), "contact:sha256:came-leafless why:no leaf held → unreached") {
		t.Fatalf("a contact with no leaf must be recorded as unreached, once:\n%s", strings.Join(rows, "\n"))
	}
	progress, err := m.Store.ListMoveFanout(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	recorded := false
	for _, p := range progress {
		if p.ContactFpr == "sha256:came-leafless" {
			recorded = p.Status == FanoutUnreached && p.LeafKid == "sha256:first"
		}
	}
	if !recorded {
		t.Fatalf("the leafless contact has no unreached progress row: %+v", progress)
	}
	for _, fpr := range []string{"sha256:came-active", "sha256:came-pending", "sha256:came-leafless"} {
		if c, _ := m.Store.GetContact(ctx, a.ID, fpr); c.HandshakeDue {
			t.Fatalf("%s was told and is still marked as owed a handshake", fpr)
		}
	}
	// The next campaign is an ordinary one: the active contacts, and nobody the import owed.
	called = walk("sha256:second")
	if len(called) != 2 || !called["sha256:here-active"] || !called["sha256:came-active"] {
		t.Fatalf("the campaign after the handshake called %v, want the two active contacts with a leaf", called)
	}
	// A re-run of the same campaign records nothing new about the contact it cannot reach.
	rows = nil
	walk("sha256:second")
	if strings.Contains(strings.Join(rows, "\n"), "came-leafless") {
		t.Fatalf("a re-run recorded the unreachable contact again:\n%s", strings.Join(rows, "\n"))
	}
}

// HandshakesTried counts the owed contacts the campaign of ONE leaf has tried and not reached: what
// `account announce` resumes, as against those waiting for a leaf. Measured after a real move
// (pact-cloud's live-local L5): four imported contacts at unreachable addresses were told to wait
// for a new leaf that was already installed.
func TestHandshakesTriedCountsWhatThisLeafsCampaignMissed(t *testing.T) {
	m, a := leafEnv(t)
	ctx := context.Background()
	for _, fpr := range []string{"sha256:reached", "sha256:missed", "sha256:untried"} {
		if err := m.Store.ImportContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: fpr, Status: "active", TrustFlag: "messages_only", Endpoint: "https://x.example/mcp", Leaf: []byte("leaf")}); err != nil {
			t.Fatal(err)
		}
	}
	ann := &Announcer{Manager: m, Now: func() time.Time { return time.Unix(1790000000, 0) }}
	camp := Campaign{AccountID: a.ID, NewKid: "sha256:this-leaf"}
	_, _, _ = ann.Fanout(ctx, camp, "card", func(_ context.Context, c store.Contact, _ string) (string, error) {
		switch c.Fingerprint {
		case "sha256:missed":
			return "", errors.New("offline")
		case "sha256:untried":
			return "", errors.New("offline")
		}
		return "updated", nil
	})
	// One of the two misses is recorded as another leaf's: owed, and not tried by THIS leaf.
	if err := m.Store.UpsertMoveFanout(ctx, store.MoveFanout{AccountID: a.ID, ContactFpr: "sha256:untried", LeafKid: "sha256:older-leaf", Status: "pending", Attempts: 1}); err != nil {
		t.Fatal(err)
	}
	owed, err := m.HandshakesOwed(ctx, a.ID)
	if err != nil || owed != 2 {
		t.Fatalf("owed %d (%v), want the two not reached", owed, err)
	}
	tried, err := m.HandshakesTried(ctx, a.ID, "sha256:this-leaf")
	if err != nil || tried != 1 {
		t.Fatalf("tried by this leaf %d (%v), want the one its campaign missed", tried, err)
	}
	if n, _ := m.HandshakesTried(ctx, a.ID, ""); n != 0 {
		t.Fatalf("with no leaf nothing is tried: %d", n)
	}
}
