package cli

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/portable"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
	hdtpidentity "github.com/pact-cloud/pact-identity/go"
)

// The review of 2026-09-28 on the two verbs.

// exportedNode is a node holding a certified identity "alice", one contact, and one conversation.
func exportedNode(t *testing.T) (idNode, store.Store, store.Account, string) {
	t.Helper()
	n := newIDNode(t, "old")
	ctx := context.Background()
	st := openStoreAt(t, n.dir)
	if _, err := (&identity.Manager{Store: st, Keyring: openKeyringAt(t, n.dir)}).CreateAccount(ctx, "alice", "Alice", identity.AlgoEd25519); err != nil {
		t.Fatal(err)
	}
	st.Close()
	newTestWallet(t, "Alice").certifyUnder(t, n, "alice", identity.PurposeSignup, "https://agent.alice.example/a/alice/mcp", time.Now())
	st = openStoreAt(t, n.dir)
	a, _ := st.GetAccountBySlug(ctx, "alice")
	peer := testid.NewWallet(t, "Bharat")
	ph := peer.Issue(t, "https://bharat.example/a/bharat/mcp")
	if _, err := st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: peer.Fpr, SPKI: ph.Key.Public().SPKI, Status: "active",
		Endpoint: ph.Endpoint, Leaf: ph.LeafDER, RootCert: peer.RootDER, DisplayName: "Bharat"}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertThread(ctx, store.Thread{ID: "t1", AccountID: a.ID, ContactFpr: peer.Fpr, CreatedAt: 1790000000, LastAt: 1790000010}); err != nil {
		t.Fatal(err)
	}
	return n, st, a, peer.Fpr
}

// H3. A message's reply_to names another message by its msg_id, and a peer's send_message only caps
// its length: a reply to a message this host never held, or one retention has deleted since,
// travelled as it was, every importer refused the file, and `export` said it had written one and
// exited 0. hdtp-identity 0.3.3's writer nulls such a reply_to, for every host (the node does not
// null it itself: one implementation). The export also reads its file back as an importer would
// before it reports it (portable.CheckWritten, TestAFileThatDoesNotReadBackIsRefused).
func TestADanglingReplyTravelsAsNoReply(t *testing.T) {
	for _, c := range []struct {
		name   string
		dangle func(t *testing.T, st store.Store, a store.Account, peer string) string
	}{
		{"a peer's reply to a message never held", func(t *testing.T, st store.Store, a store.Account, peer string) string {
			if err := st.InsertMessage(context.Background(), store.Message{ID: "m1", AccountID: a.ID, ContactFpr: peer, MsgID: "p-1", ThreadID: "t1",
				Direction: "in", Sender: "human", Kind: "text", Body: "about that", ReplyTo: "never-here", Status: "delivered", CreatedAt: 1790000005}); err != nil {
				t.Fatal(err)
			}
			return "m1"
		}},
		{"a reply whose parent retention deleted", func(t *testing.T, st store.Store, a store.Account, peer string) string {
			ctx := context.Background()
			for _, m := range []store.Message{
				{ID: "m1", MsgID: "p-1", Body: "the question", CreatedAt: 1790000001},
				{ID: "m2", MsgID: "p-2", Body: "the answer", ReplyTo: "p-1", CreatedAt: 1790000009},
			} {
				m.AccountID, m.ContactFpr, m.ThreadID, m.Direction, m.Sender, m.Kind, m.Status = a.ID, peer, "t1", "in", "human", "text", "delivered"
				if err := st.InsertMessage(ctx, m); err != nil {
					t.Fatal(err)
				}
			}
			if n, err := st.DeleteMessagesBefore(ctx, a.ID, 1790000005); err != nil || n != 1 {
				t.Fatalf("retention: %d %v", n, err)
			}
			return "m2"
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			n, st, a, peer := exportedNode(t)
			reply := c.dangle(t, st, a, peer)
			st.Close()
			file := filepath.Join(t.TempDir(), "alice.zip")
			code, out, errb := run(t, "export", "-config", n.cfg, "-slug", "alice", "-out", file)
			if code != 0 {
				t.Fatalf("export: code=%d out=%q err=%q", code, out, errb)
			}
			zr, err := zip.OpenReader(file)
			if err != nil {
				t.Fatal(err)
			}
			defer zr.Close()
			got, err := hdtpidentity.ReadExportZip(&zr.Reader, a.RootFingerprint, time.Now(), portable.ImportCeiling)
			if err != nil {
				t.Fatalf("the file does not read: %v", err)
			}
			for _, m := range got.Messages {
				if m.ID == reply && m.ReplyTo != nil {
					t.Fatalf("the dangling reply_to travelled: %q", *m.ReplyTo)
				}
			}
		})
	}
}

// Coordinator (hdtp-identity 0.3.3, SPEC 9.2 #25). The writer leaves out a message a contact made
// that the file must never carry — here one whose body reads as a private key — and the export
// names it, by id and the writer's reason, in its output and its audit row.
func TestAMessageTheWriterLeftOutIsReported(t *testing.T) {
	n, st, a, peer := exportedNode(t)
	ctx := context.Background()
	body := "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----"
	if err := st.InsertMessage(ctx, store.Message{ID: "m-key", AccountID: a.ID, ContactFpr: peer, MsgID: "p-key", ThreadID: "t1",
		Direction: "in", Sender: "agent", Kind: "text", Body: body, Status: "delivered", CreatedAt: 1790000006}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	file := filepath.Join(t.TempDir(), "alice.zip")
	code, out, errb := run(t, "export", "-config", n.cfg, "-slug", "alice", "-out", file)
	if code != 0 || !strings.Contains(out, "left out: message m-key: its body holds what reads as a private key") || !strings.Contains(out, "0 message(s)") {
		t.Fatalf("export: code=%d out=%q err=%q", code, out, errb)
	}
	got := openStoreAt(t, n.dir)
	rows, _ := got.ListAuditEvents(ctx, "")
	named := false
	for _, r := range rows {
		named = named || (r.Action == "account_export" && strings.Contains(r.Resource, "left_out:m-key"))
	}
	if !named {
		t.Fatal("the export's audit row does not name the message it left out")
	}
}

// L13 and coordinator item 6. A first run with -yes shows the review before it writes (HDTP §9.2
// step 1: -yes is the agreement to what is on the screen above it, in the same run), and the
// import ends by minting the request for the next leaf itself (§9.2 step 4): `move` into a new
// slug, at this node's address for it, and says how to complete it.
func TestAnImportShowsItsReviewAndEndsWithARequestItMinted(t *testing.T) {
	n, st, _, peer := exportedNode(t)
	st.Close()
	file := filepath.Join(t.TempDir(), "alice.zip")
	if code, _, errb := run(t, "export", "-config", n.cfg, "-slug", "alice", "-out", file); code != 0 {
		t.Fatalf("export: %s", errb)
	}
	fresh := newIDNode(t, "fresh")
	body := `{"data_dir":"` + fresh.dir + `","internal_bind":"127.0.0.1:0","public_bind":"127.0.0.1:0","public_url":"https://fresh.example"}`
	if err := os.WriteFile(fresh.cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := run(t, "import", file, "-config", fresh.cfg, "-slug", "alice", "-yes")
	if code != 0 {
		t.Fatalf("import: code=%d out=%q err=%q", code, out, errb)
	}
	reviewAt, writtenAt := strings.Index(out, "write "+peer), strings.Index(out, "imported ")
	if reviewAt < 0 || writtenAt < 0 || reviewAt > writtenAt || !strings.Contains(out, `("Alice")`) {
		t.Fatalf("the review must come first, in the same run, the name quoted:\n%s", out)
	}
	endpoint := identity.EndpointFor("https://fresh.example", "alice")
	if !strings.Contains(out, "a request for a new leaf is waiting: move at "+endpoint) ||
		!strings.Contains(out, "open /identity/alice/wallet") ||
		!strings.Contains(out, "-----BEGIN CERTIFICATE REQUEST-----") {
		t.Fatalf("the import must end with the request it minted:\n%s", out)
	}
	got := openStoreAt(t, fresh.dir)
	a, err := got.GetAccountBySlug(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	pending := 0
	for _, l := range mustLeaves(t, got, a.ID) {
		if l.State == identity.LeafPending && l.Endpoint == endpoint {
			pending++
		}
	}
	if pending != 1 {
		t.Fatalf("%d pending requests at %s after the import", pending, endpoint)
	}
	rows, _ := got.ListAuditEvents(context.Background(), "")
	minted := 0
	for _, r := range rows {
		if r.Action == "account_csr" && r.Outcome == "ok" && strings.Contains(r.Resource, "purpose:move") {
			minted++
		}
	}
	if minted != 1 {
		t.Fatalf("the request is audited once as account_csr: %d", minted)
	}
}
