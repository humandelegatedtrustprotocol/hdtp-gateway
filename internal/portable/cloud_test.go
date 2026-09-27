package portable

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/testid"
)

// The cloud's `npm run leave` writes this node's import file (pact-cloud/gateway/src/leave), and
// the two sides are in different repositories and different languages. Each used to hold a
// description of the other: the converter read "internal/cli/backup.go" out of a comment and
// fabricated a SQLite store to match it, goose bookkeeping and all, and re-pinned "29 versions
// through 29" every time this node added a migration. Two descriptions of one format drift.
//
// So this does not compare descriptions. It has the cloud's converter WRITE a file — from real
// certificates made here, because this importer checks that a root certificate is the root it
// travels under — and imports it. The importer is strict, so a field the converter adds without
// its being declared in this package fails here, in this repository's gate, on the day it is added.
//
// It needs the sibling repository and node, and says so loudly when it has neither: a clone of this
// repository alone skips this, and must not read that as the two formats agreeing.
func TestTheCloudsLeaveFileImports(t *testing.T) {
	gateway, err := filepath.Abs(filepath.Join("..", "..", "..", "pact-cloud", "gateway"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(gateway, "scripts", "leave.mjs")); err != nil {
		t.Skipf("!! NOT CHECKED: the cloud's converter is not on disk at ../pact-cloud/gateway, so nothing proved that the file it writes is one this node imports")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("!! NOT CHECKED: `node` is not installed, so the cloud's converter could not be run")
	}
	if _, err := os.Stat(filepath.Join(gateway, "node_modules", "esbuild")); err != nil {
		t.Skip("!! NOT CHECKED: ../pact-cloud/gateway has no node_modules (run `npm ci` there), so the cloud's converter could not be run")
	}

	me, peer := testid.NewWallet(t, "Alina"), testid.NewWallet(t, "Bharat")
	host := peer.Issue(t, "https://agent.bharat.example/a/bharat/mcp")
	dir := t.TempDir()
	fixture, _ := json.Marshal(map[string]string{
		"root": me.Fpr, "root_cert": b64.EncodeToString(me.RootDER),
		"contact_root": peer.Fpr, "contact_root_cert": b64.EncodeToString(peer.RootDER),
		"contact_leaf": b64.EncodeToString(host.LeafDER), "contact_spki": b64.EncodeToString(host.Key.Public.SPKI),
		"contact_endpoint": host.Endpoint,
	})
	fixturePath, out := filepath.Join(dir, "fixture.json"), filepath.Join(dir, "pact-export.tar.gz")
	if err := os.WriteFile(fixturePath, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, "--disable-warning=ExperimentalWarning", "scripts/leave.mjs", "--selftest", "--fixture", fixturePath, "--emit", out)
	cmd.Dir = gateway
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the cloud's converter failed its own self-test: %v\n%s", err, b)
	}
	file, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the converter wrote no file: %v", err)
	}

	dst := newEnv(t, sqliteStore)
	ctx := context.Background()
	res, err := Import(ctx, dst.st, dst.blobs, bytes.NewReader(file))
	if err != nil {
		t.Fatalf("this node refuses the file the cloud's converter writes: %v", err)
	}
	if len(res.Identities) != 1 || res.Identities[0] != "alina" || res.Counts[KindContact] != 1 || res.Counts[KindMessage] != 2 || res.Counts[KindMedia] != 1 {
		t.Fatalf("what arrived: %+v", res)
	}
	a, err := dst.st.GetAccountBySlug(ctx, "alina")
	if err != nil || a.RootFingerprint != me.Fpr || !bytes.Equal(a.RootCert, me.RootDER) {
		t.Fatalf("the identity did not arrive as itself: %+v %v", a, err)
	}
	if sealed, _ := dst.st.GetAccountSealedKey(ctx, a.ID); len(sealed) != 0 {
		t.Fatalf("an identity that left the cloud arrived holding %d bytes of key", len(sealed))
	}
	c, err := dst.st.GetContact(ctx, a.ID, peer.Fpr)
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint != host.Endpoint || !bytes.Equal(c.Leaf, host.LeafDER) || !bytes.Equal(c.RootCert, peer.RootDER) ||
		c.Petname != "B, from the conference" || c.TrustFlag != "may_instruct" ||
		len(c.Permissions) != 1 || c.Permissions[0] != "message.text" || len(c.TheirPermissions) != 1 || c.TheirPermissions[0] != "calendar.read" {
		t.Fatalf("the contact lost something between the two hosts: %+v", c)
	}
	msgs, err := dst.st.ListMessagesByThread(ctx, a.ID, "t1")
	if err != nil || len(msgs) != 2 || msgs[0].Body != "shall we meet?" {
		t.Fatalf("the conversation: %+v %v", msgs, err)
	}
	if msgs[1].Status != "failed" {
		t.Fatalf("a message the cloud never delivered must arrive as failed, not as this node's to send: %q", msgs[1].Status)
	}
	if blobs, _ := dst.st.ListBlobs(ctx, a.ID); len(blobs) != 1 || blobs[0].Filename != "note.txt" {
		t.Fatalf("the media: %+v", blobs)
	}
	if got, err := dst.blobs.Get(blobs(t, dst, a.ID)); err != nil || string(got) != "a media blob, content-addressed" {
		t.Fatalf("the media's bytes: %q %v", got, err)
	}
}

func blobs(t *testing.T, e env, accountID string) string {
	t.Helper()
	list, err := e.st.ListBlobs(context.Background(), accountID)
	if err != nil || len(list) == 0 {
		t.Fatalf("no media: %v", err)
	}
	return list[0].Hash
}
