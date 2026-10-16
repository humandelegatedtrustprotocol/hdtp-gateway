// Package journeys holds the node's half of the journey list both hosts are proven against.
package journeys

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/registry"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

type journey struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Node         []string `json:"node"`
	NodePending  string   `json:"node_pending"`
	Cloud        []string `json:"cloud"`
	CloudPending string   `json:"cloud_pending"`
}

func load(t *testing.T) []journey {
	t.Helper()
	b, err := os.ReadFile("journeys.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ Journeys []journey }
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f.Journeys
}

// Every journey is proven on the node by scenarios that exist, or says why it is not yet; ids are
// unique; and a journey is not both proven and pending.
func TestEveryJourneyIsProvenOnTheNodeOrSaysWhyNot(t *testing.T) {
	entries, err := registry.Scan("..")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, e := range entries {
		ids[e.ID] = true
	}
	js := load(t)
	if len(js) < 20 {
		t.Fatalf("%d journeys: the list is not being read", len(js))
	}
	seen := map[string]bool{}
	shape := regexp.MustCompile(`^J[0-9]+$`)
	for _, j := range js {
		if !shape.MatchString(j.ID) || seen[j.ID] || j.Name == "" {
			t.Errorf("journey %q: an id J<n>, unique, with a name", j.ID)
		}
		seen[j.ID] = true
		switch {
		case len(j.Node) == 0 && len(j.NodePending) < 20:
			t.Errorf("%s (%s) has no node scenario and no reason", j.ID, j.Name)
		case len(j.Node) > 0 && j.NodePending != "":
			t.Errorf("%s is proven on the node and says it is pending", j.ID)
		}
		for _, s := range j.Node {
			if !ids[s] {
				t.Errorf("%s names %s, which is not a scenario of the harness", j.ID, s)
			}
		}
		if len(j.Cloud) == 0 && len(j.CloudPending) < 20 {
			t.Errorf("%s (%s) has no cloud scenario and no reason", j.ID, j.Name)
		}
	}
}

// The cloud's copy is these bytes: one list, two copies, held to each other. The batondeck checkout
// is found as every sibling guard finds it (testid.SiblingFile); without one the test skips (saying
// so under -v) and fails under the pre-push hook.
func TestTheCloudsCopyIsThisList(t *testing.T) {
	ours, err := os.ReadFile("journeys.json")
	if err != nil {
		t.Fatal(err)
	}
	theirs := testid.SiblingFile(t, "batondeck", "gateway/e2e/tables/journeys.json", "the cloud's copy of the journeys is unchecked")
	if !bytes.Equal(ours, theirs) {
		t.Error("batondeck's gateway/e2e/tables/journeys.json differs from harness/journeys/journeys.json: one list, two copies")
	}
}
