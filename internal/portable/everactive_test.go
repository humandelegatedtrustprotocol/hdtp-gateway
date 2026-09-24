package portable

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/testid"
)

// Review of #22, finding 1: an archive carried a contact's status and not whether it was ever a
// contact, and the import derived that from the status. A contact the owner blocked on the other
// host arrived blocked and "never active", and unblocking it here DELETED it — grant, trust and pin —
// instead of restoring it. The archive now carries the fact, and an unblock after an import does
// what it would have done on the host that made the archive.
func TestAnUnblockAfterAnImportRestoresAContactAndForgetsARejection(t *testing.T) {
	for _, eng := range engines(t) {
		t.Run(eng.name, func(t *testing.T) {
			ctx := context.Background()
			src := newEnv(t, eng.open)
			_, peer, _ := seed(t, src)
			a, err := src.st.GetAccountBySlug(ctx, "alina")
			must(t, err)
			// The seeded peer was a contact; the owner blocked it.
			must(t, src.st.UpdateContactStatus(ctx, a.ID, peer.Fpr, "blocked"))
			// A request the owner rejected: never a contact, though this node pins a pending row.
			stranger := testid.NewWallet(t, "Stranger")
			_, err = src.st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: stranger.Fpr, SPKI: []byte{7}, Status: "pending_in", CreatedAt: 12, PinnedAt: 12})
			must(t, err)
			must(t, src.st.UpdateContactStatus(ctx, a.ID, stranger.Fpr, "blocked"))

			archive, _ := export(t, src)
			imported := importInto(t, eng.open, archive)
			unblocked(t, imported, peer.Fpr, stranger.Fpr)
		})
	}
}

// The cloud's `leave` writes this archive without ever_active (pact-cloud gateway/src/leave/
// convert.ts). Its pinned_at is written by activation alone, so a blocked row with a pin was a
// contact the owner blocked, and one without was a rejection.
func TestAnArchiveWithoutEverActiveIsReadByItsPin(t *testing.T) {
	ctx := context.Background()
	src := newEnv(t, sqliteStore)
	_, peer, _ := seed(t, src)
	a, err := src.st.GetAccountBySlug(ctx, "alina")
	must(t, err)
	must(t, src.st.UpdateContactStatus(ctx, a.ID, peer.Fpr, "blocked"))
	stranger := testid.NewWallet(t, "Stranger")
	_, err = src.st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: stranger.Fpr, SPKI: []byte{7}, Status: "blocked", CreatedAt: 12})
	must(t, err)

	archive, _ := export(t, src)
	names, body := members(t, archive)
	var out []string
	for _, line := range strings.Split(strings.TrimRight(string(body["data.jsonl"]), "\n"), "\n") {
		var v map[string]any
		must(t, json.Unmarshal([]byte(line), &v))
		if v["kind"] == "contact" {
			if _, ok := v["ever_active"]; !ok {
				t.Fatalf("this node's export left ever_active out: %s", line)
			}
			delete(v, "ever_active") // as the cloud writes it
		}
		b, _ := json.Marshal(v)
		out = append(out, string(b))
	}
	body["data.jsonl"] = []byte(strings.Join(out, "\n") + "\n")
	var m Manifest
	must(t, json.Unmarshal(body["MANIFEST.json"], &m))
	m.DataSHA256 = sha256hex(body["data.jsonl"])
	body["MANIFEST.json"], _ = json.Marshal(m)

	imported := importInto(t, sqliteStore, repack(t, names, body))
	unblocked(t, imported, peer.Fpr, stranger.Fpr)
}

type importedNode struct {
	st      store.Store
	account string
}

func importInto(t *testing.T, open func(t *testing.T) store.Store, archive []byte) importedNode {
	t.Helper()
	dst := newEnv(t, open)
	ctx := context.Background()
	if _, err := Import(ctx, dst.st, dst.blobs, bytes.NewReader(archive)); err != nil {
		t.Fatalf("import: %v", err)
	}
	a, err := dst.st.GetAccountBySlug(ctx, "alina")
	must(t, err)
	return importedNode{st: dst.st, account: a.ID}
}

// unblocked unblocks both rows on the importing node: the contact comes back as it was, and the
// rejected request is forgotten.
func unblocked(t *testing.T, n importedNode, contact, rejected string) {
	t.Helper()
	ctx := context.Background()
	o := contacts.Owner{Manager: &contacts.Manager{Store: n.st}}
	if d, err := o.Unblock(ctx, n.account, contact); err != nil || d.Status != "active" {
		t.Fatalf("unblocking the contact the owner blocked: %+v %v", d, err)
	}
	c, err := n.st.GetContact(ctx, n.account, contact)
	if err != nil || c.Status != "active" || c.Preset != "close" || c.TrustFlag != "may_instruct" {
		t.Fatalf("the contact did not come back as it was: %+v %v", c, err)
	}
	if d, err := o.Unblock(ctx, n.account, rejected); err != nil || d.Status != "none" {
		t.Fatalf("unblocking a rejected request (the control): %+v %v", d, err)
	}
	if _, err := n.st.GetContact(ctx, n.account, rejected); err == nil {
		t.Fatal("a rejected request was restored rather than forgotten")
	}
}
