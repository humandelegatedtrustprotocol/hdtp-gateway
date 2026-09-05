package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
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

// Fixing the predicate only protects the NEXT write. A credential already written
// in the clear stays exposed until something rewrites it, and an owner cannot be
// expected to notice that a value they typed once is sitting in plaintext in
// every backup. Startup repairs it.
func TestLegacyPlaintextCredentialsAreResealedAtStartup(t *testing.T) {
	dir := t.TempDir()
	st := openStoreAt(t, dir)
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var audited []string
	svc := &settingsService{store: st, kr: openKeyringAt(t, dir),
		audit: func(a, r, o string) { audited = append(audited, a+" "+r+" "+o) }}

	const secret = "left-in-the-clear"
	// exactly what the old predicate wrote: Secret=false, value in plaintext
	for _, k := range []string{"integration.cal.env.CALDAV_PASSWORD", "integration.gh.env.GITHUB_TOKEN"} {
		if err := st.PutSetting(ctx, store.Setting{Key: k, Value: secret, Secret: false}); err != nil {
			t.Fatal(err)
		}
	}
	// and a genuinely non-secret row, which must be left alone
	if err := st.PutSetting(ctx, store.Setting{
		Key: "integration.cal.calendar_url", Value: "http://radicale/owner/work/",
	}); err != nil {
		t.Fatal(err)
	}

	n, err := svc.resealLegacySecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("resealed %d rows, want 2", n)
	}
	rows, err := st.ListSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		switch r.Key {
		case "integration.cal.calendar_url":
			if r.Secret {
				t.Error("a non-secret row was sealed; the predicate has become too broad")
			}
		default:
			if !r.Secret || strings.Contains(r.Value, secret) {
				t.Errorf("%s is still in the clear after the repair", r.Key)
			}
		}
	}
	// the values must still read back, or the repair destroyed the configuration
	vals, err := svc.values(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if vals["integration.cal.env.CALDAV_PASSWORD"] != secret {
		t.Errorf("a resealed credential no longer reads back: %q", vals["integration.cal.env.CALDAV_PASSWORD"])
	}
	// and the KEY is audited, never the value
	joined := strings.Join(audited, "\n")
	if !strings.Contains(joined, "settings_reseal key:integration.cal.env.CALDAV_PASSWORD sealed") {
		t.Errorf("the repair was not audited: %v", audited)
	}
	if strings.Contains(joined, secret) {
		t.Error("the audit trail contains the credential")
	}
	// idempotent: a second pass finds nothing
	again, err := svc.resealLegacySecrets(ctx)
	if err != nil || again != 0 {
		t.Errorf("second pass resealed %d rows (err %v); it must be idempotent", again, err)
	}
}
