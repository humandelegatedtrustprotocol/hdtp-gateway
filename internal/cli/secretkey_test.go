package cli

import (
	"context"
	"strings"
	"testing"
)

// Credentials for a supervised stdio child are stored as
// `integration.<slug>.env.<NAME>` settings rows, and environment variable names
// are UPPERCASE by universal convention — CALDAV_PASSWORD, GITHUB_TOKEN, API_KEY.
// isSecretKey compared against lowercase markers with a case-SENSITIVE
// strings.Contains, so none of them matched and every one was written to the
// settings table in plaintext, while its own comment says it "errs toward
// secrecy".
//
// The row is the evidence, not the predicate: this asserts what actually landed
// in the store.
func TestUppercaseCredentialsAreSealedAtRest(t *testing.T) {
	dir := t.TempDir()
	st := openStoreAt(t, dir)
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	svc := &settingsService{store: st, kr: openKeyringAt(t, dir)}

	const secret = "hunter2-not-in-the-clear"
	for _, key := range []string{
		"integration.cal.env.CALDAV_PASSWORD",
		"integration.gh.env.GITHUB_TOKEN",
		"integration.x.env.API_KEY",
		"integration.y.env.CLIENT_SECRET",
	} {
		if err := svc.save(ctx, key, secret); err != nil {
			t.Fatalf("save %s: %v", key, err)
		}
	}
	rows, err := st.ListSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range rows {
		if !strings.HasPrefix(r.Key, "integration.") {
			continue
		}
		seen++
		if !r.Secret {
			t.Errorf("%s was stored UNSEALED: a credential sits in plaintext in the "+
				"settings table and in every backup of it", r.Key)
		}
		if strings.Contains(r.Value, secret) {
			t.Errorf("%s: the plaintext credential is readable in the stored value", r.Key)
		}
	}
	if seen != 4 {
		t.Fatalf("expected 4 stored rows, saw %d", seen)
	}

	// And it must still round-trip through the decrypting reader.
	vals, err := svc.values(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if vals["integration.cal.env.CALDAV_PASSWORD"] != secret {
		t.Errorf("a sealed credential did not read back: %q",
			vals["integration.cal.env.CALDAV_PASSWORD"])
	}
}
