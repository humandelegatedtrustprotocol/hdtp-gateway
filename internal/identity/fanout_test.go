package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
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
		if _, err := m.Store.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: fpr, Status: "active", Endpoint: "https://" + fpr[7:] + ".example/mcp"}); err != nil {
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
	done, failed, err := ann.Fanout(ctx, camp, "card", func(_ context.Context, c store.Contact, _ string) error {
		if c.Fingerprint == "sha256:two" {
			return errors.New("offline")
		}
		reached++
		return nil
	})
	if done != 1 || failed != 1 || !errors.Is(err, ErrFanoutIncomplete) {
		t.Fatalf("one reached, one not: done=%d failed=%d err=%v", done, failed, err)
	}
	// And it resumes: the one already told is not told again.
	reached = 0
	done, failed, err = ann.Fanout(ctx, camp, "card", func(context.Context, store.Contact, string) error { reached++; return nil })
	if done != 2 || failed != 0 || err != nil || reached != 1 {
		t.Fatalf("the resume must reach only the contact that was missed: done=%d failed=%d err=%v calls=%d", done, failed, err, reached)
	}

	// 2. A store that refuses the progress write. The contacts are still told; the record is what
	// is lost, and that has to come back as an error that is NOT the ordinary one.
	broken := &Announcer{Manager: &Manager{Store: refusingProgress{m.Store}, Keyring: m.Keyring}, Audit: audit, Now: now}
	rows = nil
	_, _, err = broken.Fanout(ctx, Campaign{AccountID: a.ID, NewKid: "sha256:another-leaf"}, "card", func(context.Context, store.Contact, string) error { return nil })
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
