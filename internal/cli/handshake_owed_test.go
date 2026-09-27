package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/testid"
)

// An import leaves its contacts owed this host's handshake until the identity's next leaf is
// installed (PACT §9.2). That state has a way out only if the owner can see it, so the two places
// an owner already looks — `account certificate` and `doctor` — both name it, with the command
// that ends it; and once nothing is owed, neither says anything. A blocked contact is never owed.
func TestOwedHandshakesAreNamedByAccountCertificateAndDoctor(t *testing.T) {
	ctx := context.Background()
	owner, friend, blocked := testid.NewWallet(t, "Work"), testid.NewWallet(t, "Friend"), testid.NewWallet(t, "Blocked")
	var accountID string
	r := runServe(t, func(t *testing.T, dir string) {
		st, err := store.OpenSQLite(filepath.Join(dir, "pact.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if err := st.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		// What an import into a new slug leaves: a keyless identity holding its root, and contacts.
		a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "work", DisplayName: "Work", Algo: "p256"})
		if err != nil {
			t.Fatal(err)
		}
		accountID = a.ID
		if err := st.SetAccountRoot(ctx, a.ID, owner.Fpr, nil); err != nil {
			t.Fatal(err)
		}
		for fpr, status := range map[string]string{friend.Fpr: "active", blocked.Fpr: "blocked"} {
			if err := st.ImportContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: fpr, Status: status, TrustFlag: "messages_only", Endpoint: "https://x.example/a/x/mcp", HandshakeDueAt: 1}); err != nil {
				t.Fatal(err)
			}
		}
	})
	cfg := filepath.Join(r.dir, "config.json")
	want := "1 imported contact(s) of work wait for a new leaf: run `account csr -slug work -purpose move`"

	code, out, errb := runQuiet("account", "certificate", "-config", cfg, "-slug", "work")
	if code != 0 || !strings.Contains(out, want) {
		t.Fatalf("account certificate must name the owed handshake: code=%d out=%q err=%q", code, out, errb)
	}
	_, out, _ = runQuiet("doctor", "-config", cfg)
	if !strings.Contains(out, "warn handshake    "+want) {
		t.Fatalf("doctor must name the owed handshake:\n%s", out)
	}

	// M5 (review 2026-09-28): a keyless imported slug holds its root and no leaf. Certified means a
	// current leaf, so neither command reports one, and neither prints the zero date a missing
	// leaf's notAfter is.
	for _, args := range [][]string{{"account", "certificate", "-config", cfg, "-slug", "work"}, {"doctor", "-config", cfg}} {
		_, out, _ := runQuiet(args...)
		if !strings.Contains(out, "work has no leaf yet") || strings.Contains(out, "0001-01-01") || strings.Contains(out, "1970-01-01") || strings.Contains(out, "valid until") {
			t.Fatalf("%s on a slug with no leaf:\n%s", args[0], out)
		}
	}

	// L5 (review 2026-09-28): announce on a slug with no leaf yet has nothing to walk and must not
	// say it resumed anything; the handshake goes out when the first leaf is installed.
	if code, out, errb := runQuiet("account", "announce", "-config", cfg, "-slug", "work"); code == 0 || strings.Contains(out, "resumed") || !strings.Contains(errb, "no leaf yet") {
		t.Fatalf("announce on a keyless slug: code=%d out=%q err=%q", code, out, errb)
	}

	// Told, so owed nothing: both fall silent.
	st := openStoreAt(t, r.dir)
	if err := st.ClearContactHandshake(ctx, accountID, friend.Fpr); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, out, _ := runQuiet("account", "certificate", "-config", cfg, "-slug", "work"); strings.Contains(out, "wait for a new leaf") {
		t.Fatalf("account certificate names a handshake nobody is owed: %q", out)
	}
	if _, out, _ := runQuiet("doctor", "-config", cfg); strings.Contains(out, "handshake") {
		t.Fatalf("doctor names a handshake nobody is owed:\n%s", out)
	}
}

// A served identity asks for a renewal; one with no leaf here yet asks for a move.
func TestTheOwedHandshakeLineAsksForTheRightLeaf(t *testing.T) {
	if got := handshakesOwedLine("work", 2, true); !strings.Contains(got, "2 imported contact(s)") || !strings.Contains(got, "-purpose renew") {
		t.Fatalf("a served identity: %q", got)
	}
	if got := handshakesOwedLine("work", float64(1), false); !strings.Contains(got, "-purpose move") {
		t.Fatalf("an identity with no leaf, over JSON: %q", got)
	}
	if got := handshakesOwedLine("work", 0, true); got != "" {
		t.Fatalf("nothing owed must say nothing: %q", got)
	}
}
