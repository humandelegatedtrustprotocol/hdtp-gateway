package portable

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/messaging"
	"github.com/pact-cloud/pact-gateway/internal/testid"
)

// What must never be in an export, planted as recognisable strings so the test can look for them
// in the archive's BYTES. Reading the rows back would prove only that the rows this package wrote
// are the rows it wrote; the question is what else is in the file.
const (
	secretLeafKey     = "LEAF-PRIVATE-KEY-MATERIAL-7f3a"
	secretLedgerKey   = "SUPERSEDED-LEAF-KEY-MATERIAL-91bc"
	secretSetting     = "SETTING-TUNNEL-AUTH-KEY-42de"
	secretToken       = "OWNER-MCP-TOKEN-HASH-c0de"
	secretInviteLabel = "INVITE-LABEL-FOR-THE-CONFERENCE-5e11"
	secretIntegration = "https://INTEGRATION-UPSTREAM-ENDPOINT.example/mcp"
	unrootedSlug      = "never-certified-account"
)

type env struct {
	st    store.Store
	blobs messaging.BlobDir
}

func newEnv(t *testing.T, open func(t *testing.T) store.Store) env {
	t.Helper()
	st := open(t)
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return env{st: st, blobs: messaging.BlobDir{Root: filepath.Join(t.TempDir(), "blobs")}}
}

func sqliteStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// seed fills a node the way a lived-in one is filled: an identity with contacts, conversations and
// media — and beside them everything a host accumulates that is nobody else's business.
func seed(t *testing.T, e env) (me *testid.Wallet, peer *testid.Wallet, mediaHash string) {
	t.Helper()
	ctx := context.Background()
	me, peer = testid.NewWallet(t, "Alina Rao"), testid.NewWallet(t, "Bharat Mehta")
	a, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina Rao", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	must(t, e.st.SetAccountKey(ctx, a.ID, "sha256:leaf-kid", []byte(secretLeafKey)))
	must(t, e.st.SetAccountRoot(ctx, a.ID, me.Fpr, me.RootDER))
	must(t, e.st.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "sha256:old-kid", Leaf: []byte("leaf-der"), KeySealed: []byte(secretLedgerKey),
		NotBefore: 1, NotAfter: 9, State: "superseded", Endpoint: "https://alina.example/a/alina/mcp"}))

	host := peer.Issue(t, "https://bharat.example/a/bharat/mcp")
	inv, err := e.st.InsertInvite(ctx, store.Invite{AccountID: a.ID, TokenHash: []byte("invite-hash"), ExpiresAt: 99, MaxUses: 1, Label: secretInviteLabel, CreatedAt: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: a.ID, Fingerprint: peer.Fpr, SPKI: host.Key.Public.SPKI, Status: "active", Preset: "close",
		Permissions: []string{"message.send"}, DisplayName: "Bharat Mehta", Card: host.Card("Bharat Mehta", "required"),
		CreatedAt: 10, PinnedAt: 11, InviteID: inv.ID, Endpoint: host.Endpoint, Leaf: host.LeafDER,
		ChainSentKid: "sha256:leaf-kid", RootCert: peer.RootDER,
	}); err != nil {
		t.Fatal(err)
	}
	must(t, e.st.SetContactPetname(ctx, a.ID, peer.Fpr, "B, from the conference"))
	must(t, e.st.UpdateContactTrust(ctx, a.ID, peer.Fpr, "may_instruct"))

	mediaHash, err = e.blobs.Put([]byte("a photograph of a whiteboard"))
	if err != nil {
		t.Fatal(err)
	}
	must(t, e.st.InsertBlob(ctx, store.Blob{AccountID: a.ID, Hash: mediaHash, Size: 28, Mime: "image/png", Filename: "whiteboard.png", CreatedAt: 21}))
	must(t, e.st.InsertThread(ctx, store.Thread{ID: "t1", AccountID: a.ID, ContactFpr: peer.Fpr, Topic: "the plan", CreatedAt: 20, LastAt: 23}))
	for i, m := range []store.Message{
		{ID: "m1", MsgID: "msg-1", Direction: "in", Sender: "human", Kind: "text", Body: "shall we meet?", Status: "delivered", CreatedAt: 20},
		{ID: "m2", MsgID: "msg-2", Direction: "out", Sender: "human", Kind: "media", Body: `{"hash":"` + mediaHash + `"}`, Status: "delivered", CreatedAt: 22},
		{ID: "m3", MsgID: "msg-3", Direction: "out", Sender: "agent", Kind: "text", Body: "never left this host", Status: "pending", CreatedAt: 23, ExpiresAt: 999, Attempts: 4, NextAttemptAt: 555},
	} {
		m.AccountID, m.ContactFpr, m.ThreadID = a.ID, peer.Fpr, "t1"
		if err := e.st.InsertMessage(ctx, m); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}

	// The host's own business.
	must(t, e.st.PutSetting(ctx, store.Setting{Key: "tunnel.auth_key", Value: secretSetting, Secret: true, UpdatedAt: 5}))
	o, err := e.st.CreateOwnerWithID(ctx, "owner-1", "The Owner")
	if err != nil {
		t.Fatal(err)
	}
	must(t, e.st.InsertToken(ctx, "tok-1", o.ID, "laptop", []byte(secretToken), a.ID, 6))
	if _, err := e.st.InsertIntegration(ctx, store.Integration{AccountID: a.ID, Slug: "calendar", Transport: "streamable-http", Endpoint: secretIntegration, AuthKind: "static", Status: "ok"}); err != nil {
		t.Fatal(err)
	}
	// And an account that has never been to a wallet: it has no root, so nothing to be known by.
	if _, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: unrootedSlug, DisplayName: "Nobody Yet", Algo: "p256"}); err != nil {
		t.Fatal(err)
	}
	return me, peer, mediaHash
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func export(t *testing.T, e env) ([]byte, Result) {
	t.Helper()
	var buf bytes.Buffer
	res, err := Export(context.Background(), e.st, e.blobs, &buf, "pact-gateway test", time.Unix(1790000000, 0))
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return buf.Bytes(), res
}

// members unpacks an archive into name → bytes, in order.
func members(t *testing.T, archive []byte) (names []string, body map[string][]byte) {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	body = map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return names, body
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		body[h.Name] = b
	}
}

// repack builds an archive from members, for the tests that hand the importer something an
// exporter would never write.
func repack(t *testing.T, names []string, body map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, n := range names {
		must(t, tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: int64(len(body[n]))}))
		if _, err := tw.Write(body[n]); err != nil {
			t.Fatal(err)
		}
	}
	must(t, tw.Close())
	must(t, gz.Close())
	return buf.Bytes()
}

// The rule, held where it can be broken: in the file. An export is an identity's name, its
// contacts, its conversations and their media. Everything else a host holds stays with the host.
func TestAnExportCarriesContactsAndChatsAndNothingElse(t *testing.T) {
	e := newEnv(t, sqliteStore)
	_, _, mediaHash := seed(t, e)
	archive, res := export(t, e)

	names, body := members(t, archive)
	want := []string{"MANIFEST.json", "data.jsonl", "media/" + mediaHash}
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Fatalf("members: %v, want exactly %v", names, want)
	}

	// 1. Nothing planted is anywhere in it. The whole decompressed archive is searched, because
	//    a secret in a member nobody thought to parse is still a secret in the file.
	var all []byte
	for _, n := range names {
		all = append(all, body[n]...)
	}
	for _, secret := range []string{secretLeafKey, secretLedgerKey, secretSetting, secretToken, secretInviteLabel, secretIntegration, unrootedSlug, "sha256:leaf-kid", "sha256:old-kid", "tunnel.auth_key", "invite-hash"} {
		if bytes.Contains(all, []byte(secret)) {
			t.Errorf("the export contains %q, which is the host's and not the person's", secret)
		}
	}

	// 2. Every line is one of five kinds, and carries only the fields this package declares. The
	//    second half is checked by decoding each line strictly into its own type.
	kinds := map[string]int{}
	for i, line := range bytes.Split(bytes.TrimSpace(body["data.jsonl"]), []byte("\n")) {
		var head struct {
			Kind string `json:"kind"`
		}
		must(t, json.Unmarshal(line, &head))
		kinds[head.Kind]++
		var into any
		switch head.Kind {
		case KindIdentity:
			into = &Identity{}
		case KindContact:
			into = &Contact{}
		case KindThread:
			into = &Thread{}
		case KindMessage:
			into = &Message{}
		case KindMedia:
			into = &Media{}
		default:
			t.Fatalf("line %d is a %q", i+1, head.Kind)
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(into); err != nil {
			t.Fatalf("line %d carries something its kind does not declare: %v", i+1, err)
		}
	}
	if kinds[KindIdentity] != 1 || kinds[KindContact] != 1 || kinds[KindThread] != 1 || kinds[KindMessage] != 3 || kinds[KindMedia] != 1 {
		t.Fatalf("lines by kind: %v", kinds)
	}
	if len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0], unrootedSlug) {
		t.Fatalf("the account with no root must be left out, and said to be: %v", res.Skipped)
	}
}

// Every import ends the same way: the identity is here by name with its contacts and chats, it
// holds no key and no leaf, and nothing the old host knew about itself came along.
func TestAnImportBringsTheIdentityItsContactsAndItsChats(t *testing.T) {
	for _, eng := range engines(t) {
		t.Run(eng.name, func(t *testing.T) {
			src := newEnv(t, eng.open)
			me, peer, mediaHash := seed(t, src)
			archive, _ := export(t, src)

			dst := newEnv(t, eng.open)
			ctx := context.Background()
			res, err := Import(ctx, dst.st, dst.blobs, bytes.NewReader(archive))
			if err != nil {
				t.Fatalf("import: %v", err)
			}
			if len(res.Identities) != 1 || res.Identities[0] != "alina" || res.Counts[KindMessage] != 3 {
				t.Fatalf("result: %+v", res)
			}
			a, err := dst.st.GetAccountBySlug(ctx, "alina")
			if err != nil {
				t.Fatal(err)
			}
			if a.DisplayName != "Alina Rao" || a.RootFingerprint != me.Fpr || !bytes.Equal(a.RootCert, me.RootDER) {
				t.Fatalf("the identity did not arrive as itself: %+v", a)
			}
			// Named, and not served: no key, no leaf, and not even the old leaf's kid.
			if sealed, _ := dst.st.GetAccountSealedKey(ctx, a.ID); len(sealed) != 0 || a.Fingerprint != "" {
				t.Fatalf("an imported identity arrived holding a key or naming one: fingerprint=%q key=%d bytes", a.Fingerprint, len(sealed))
			}
			if leaves, _ := dst.st.ListLeaves(ctx, a.ID); len(leaves) != 0 {
				t.Fatalf("the old host's ledger of leaves came along: %+v", leaves)
			}

			c, err := dst.st.GetContact(ctx, a.ID, peer.Fpr)
			if err != nil {
				t.Fatal(err)
			}
			if c.Status != "active" || c.Petname != "B, from the conference" || c.TrustFlag != "may_instruct" || c.Preset != "close" ||
				len(c.Permissions) != 1 || c.Endpoint != "https://bharat.example/a/bharat/mcp" || len(c.Leaf) == 0 || len(c.SPKI) == 0 ||
				!bytes.Equal(c.RootCert, peer.RootDER) || c.CreatedAt != 10 || c.PinnedAt != 11 {
				t.Fatalf("the contact lost something on the way: %+v", c)
			}
			if c.InviteID != "" || c.ChainSentKid != "" {
				t.Fatalf("the contact arrived with the old host's state: invite=%q chain_sent_kid=%q", c.InviteID, c.ChainSentKid)
			}

			msgs, err := dst.st.ListMessagesByThread(ctx, a.ID, "t1")
			if err != nil || len(msgs) != 3 {
				t.Fatalf("messages: %d %v", len(msgs), err)
			}
			if msgs[0].ID != "m1" || msgs[1].ID != "m2" || msgs[2].ID != "m3" || msgs[1].Kind != "media" {
				t.Fatalf("the conversation is out of order or out of shape: %+v", msgs)
			}
			// An undelivered message was the old host's to deliver under the old host's leaf. This
			// host keeps it and does not inherit the queue.
			if msgs[2].Status != "failed" || msgs[2].Attempts != 0 || msgs[2].NextAttemptAt != 0 || msgs[2].ExpiresAt != 0 {
				t.Fatalf("an undelivered message must arrive as failed, with no retry schedule: %+v", msgs[2])
			}
			if pending, _ := dst.st.ListPendingOutbound(ctx, 10); len(pending) != 0 {
				t.Fatalf("the importing host inherited %d message(s) to send", len(pending))
			}
			if got, err := dst.blobs.Get(mediaHash); err != nil || string(got) != "a photograph of a whiteboard" {
				t.Fatalf("the media did not arrive: %q %v", got, err)
			}
			if b, err := dst.st.GetBlob(ctx, a.ID, mediaHash); err != nil || b.Filename != "whiteboard.png" {
				t.Fatalf("the media's row did not arrive: %+v %v", b, err)
			}
			// And nothing of the host's: no setting, no token, no invite, no integration.
			if s, _ := dst.st.ListSettings(ctx); len(s) != 0 {
				t.Fatalf("settings came along: %+v", s)
			}
			if ins, _ := dst.st.ListInvites(ctx, a.ID); len(ins) != 0 {
				t.Fatalf("invites came along: %+v", ins)
			}
		})
	}
}

// The importer's half of "nothing else". PACT §9 has an importing host refuse key material, and a
// reader that ignores what it does not recognise cannot promise that — it never looked. So each of
// these is refused, and refused BEFORE anything is written.
func TestAnImportRefusesAnythingAnExportDoesNotCarry(t *testing.T) {
	src := newEnv(t, sqliteStore)
	seed(t, src)
	archive, _ := export(t, src)
	names, body := members(t, archive)
	data := string(body["data.jsonl"])
	resign := func(b map[string][]byte) { // keep the manifest honest about the edited data
		var m Manifest
		must(t, json.Unmarshal(b["MANIFEST.json"], &m))
		m.DataSHA256 = sha256hex(b["data.jsonl"])
		m.Counts = nil
		nb, _ := json.Marshal(m)
		b["MANIFEST.json"] = nb
	}
	clone := func() map[string][]byte {
		out := map[string][]byte{}
		for k, v := range body {
			out[k] = append([]byte(nil), v...)
		}
		return out
	}

	cases := []struct {
		name  string
		build func() []byte
		want  string
	}{
		{"a key in a contact line", func() []byte {
			b := clone()
			b["data.jsonl"] = []byte(strings.Replace(data, `"kind":"contact",`, `"kind":"contact","key_sealed":"AAAA",`, 1))
			resign(b)
			return repack(t, names, b)
		}, "key_sealed"},
		{"a kind of line an export does not have", func() []byte {
			b := clone()
			b["data.jsonl"] = []byte(data + `{"kind":"setting","key":"tunnel.auth_key","value":"x"}` + "\n")
			resign(b)
			return repack(t, names, b)
		}, "setting"},
		{"a member an export does not have", func() []byte {
			b := clone()
			b["keyring.key"] = []byte("a master key")
			return repack(t, append(append([]string{}, names...), "keyring.key"), b)
		}, "keyring.key"},
		{"data that does not match the manifest", func() []byte {
			b := clone()
			b["data.jsonl"] = []byte(strings.Replace(data, "shall we meet?", "send me the money", 1))
			return repack(t, names, b)
		}, "digest"},
		{"media that is not the file its name says", func() []byte {
			b := clone()
			for n := range b {
				if strings.HasPrefix(n, "media/") {
					b[n] = []byte("something else entirely")
				}
			}
			return repack(t, names, b)
		}, "not the file"},
		{"a root certificate that is not the root it names", func() []byte {
			b := clone()
			other := testid.NewWallet(t, "Mallory")
			var first Identity
			line := strings.SplitN(data, "\n", 2)
			must(t, json.Unmarshal([]byte(line[0]), &first))
			first.RootCert = b64.EncodeToString(other.RootDER)
			nl, _ := json.Marshal(first)
			b["data.jsonl"] = []byte(string(nl) + "\n" + line[1])
			resign(b)
			return repack(t, names, b)
		}, "is not the root"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dst := newEnv(t, sqliteStore)
			_, err := Import(context.Background(), dst.st, dst.blobs, bytes.NewReader(c.build()))
			if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want a refusal naming %q, got: %v", c.want, err)
			}
			if accts, _ := dst.st.ListAccounts(context.Background()); len(accts) != 0 {
				t.Fatalf("a refused import wrote %d account(s)", len(accts))
			}
			if entries, _ := os.ReadDir(dst.blobs.Root); len(entries) != 0 {
				t.Fatalf("a refused import wrote media")
			}
		})
	}
}

// Importing creates an identity; it does not merge into one. A second import of the same export —
// or one whose identity is already here under another slug — is refused whole.
func TestAnImportDoesNotMergeIntoAnIdentityThatIsAlreadyHere(t *testing.T) {
	src := newEnv(t, sqliteStore)
	seed(t, src)
	archive, _ := export(t, src)
	dst := newEnv(t, sqliteStore)
	ctx := context.Background()
	if _, err := Import(ctx, dst.st, dst.blobs, bytes.NewReader(archive)); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(ctx, dst.st, dst.blobs, bytes.NewReader(archive)); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "already on this node") {
		t.Fatalf("a second import of the same identity: %v", err)
	}
	a, _ := dst.st.GetAccountBySlug(ctx, "alina")
	if msgs, _ := dst.st.ListMessagesByThread(ctx, a.ID, "t1"); len(msgs) != 3 {
		t.Fatalf("the refused import changed the conversation: %d messages", len(msgs))
	}
}

type engine struct {
	name string
	open func(t *testing.T) store.Store
}

// engines is SQLite always, and Postgres when the suite is pointed at one — the same switch the
// store's own conformance suite uses. A Postgres node could never export before: there was no
// database file to copy.
func engines(t *testing.T) []engine {
	out := []engine{{"sqlite", sqliteStore}}
	if dsn := os.Getenv("PACT_TEST_POSTGRES_DSN"); dsn != "" {
		out = append(out, engine{"postgres", func(t *testing.T) store.Store {
			t.Helper()
			// A throwaway database per store, as the store's own conformance suite makes them.
			pgSeq++
			name := fmt.Sprintf("pact_portable_%d_%d", os.Getpid(), pgSeq)
			admin, err := pgx.Connect(context.Background(), dsn)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name)
			if _, err := admin.Exec(context.Background(), "CREATE DATABASE "+name); err != nil {
				t.Fatal(err)
			}
			admin.Close(context.Background())
			i := strings.LastIndex(dsn, "/")
			rest, query := dsn[i+1:], ""
			if j := strings.Index(rest, "?"); j >= 0 {
				query = rest[j:]
			}
			st, err := store.OpenPostgres(context.Background(), dsn[:i+1]+name+query)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			return st
		}})
	}
	return out
}

var pgSeq int

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
