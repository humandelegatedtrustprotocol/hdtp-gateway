package internalui

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// contactLabelFixture is testdata/contact_labels.json: the cases labelContacts must
// answer, and the look-alike table it compares names through. BatonDeck's portal
// runs the same file against its port of this rule (portal/src/contact_labels.ts), its
// copy held byte for byte to this one by the cloud's scripts/check-harvested.mjs, so
// the two ports cannot call one contact list two different ways.
type contactLabelFixture struct {
	LookAlikes [][2]string `json:"look_alikes"`
	Cases      []struct {
		Case     string `json:"case"`
		Contacts []struct {
			Fingerprint string `json:"fingerprint"`
			DisplayName string `json:"display_name"`
			Petname     string `json:"petname"`
		} `json:"contacts"`
		Labels map[string]string `json:"labels"`
	} `json:"cases"`
}

func readContactLabelFixture(t *testing.T) contactLabelFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/contact_labels.json")
	if err != nil {
		t.Fatal(err)
	}
	var f contactLabelFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestTheLookAlikeTableIsTheFixtures(t *testing.T) {
	f := readContactLabelFixture(t)
	if !reflect.DeepEqual(f.LookAlikes, lookAlikePairs) {
		t.Fatalf("labels.go's look-alike table and testdata/contact_labels.json differ: change both, and the cloud's copy with them\n go:      %q\n fixture: %q", lookAlikePairs, f.LookAlikes)
	}
}

func TestContactLabelsAnswerTheSharedCases(t *testing.T) {
	f := readContactLabelFixture(t)
	if len(f.Cases) == 0 {
		t.Fatal("the fixture has no cases")
	}
	for _, c := range f.Cases {
		t.Run(c.Case, func(t *testing.T) {
			cs := make([]store.Contact, 0, len(c.Contacts))
			for _, x := range c.Contacts {
				cs = append(cs, store.Contact{Fingerprint: x.Fingerprint, DisplayName: x.DisplayName, Petname: x.Petname})
			}
			got := labelContacts(cs)
			if len(got) != len(c.Labels) {
				t.Fatalf("%d labels for %d expected", len(got), len(c.Labels))
			}
			for fpr, want := range c.Labels {
				want = strings.ReplaceAll(want, "{short}", shortFpr(fpr))
				if got[fpr] != want {
					t.Errorf("%s: got %q, want %q", fpr, got[fpr], want)
				}
			}
		})
	}
}
