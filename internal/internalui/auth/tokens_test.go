package auth

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

func tokenEnv(t *testing.T) (*TokenService, string) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	o, err := st.CreateOwnerWithID(ctx, "", "Sumit")
	if err != nil {
		t.Fatal(err)
	}
	return &TokenService{Store: st}, o.ID
}

func TestTokenLifecycle(t *testing.T) {
	svc, owner := tokenEnv(t)
	ctx := context.Background()

	plain, id, err := svc.Create(ctx, owner, "claude-code", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plain, "pact_") {
		t.Fatalf("token shape: %q", plain)
	}
	ident, err := svc.Validate(ctx, plain)
	if err != nil || ident.OwnerID != owner || ident.AccountID != "" {
		t.Fatalf("validate: %v %+v", err, ident)
	}
	// revocation is effective on the immediately following request
	if err := svc.Revoke(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Validate(ctx, plain); err == nil {
		t.Fatal("revoked token still validates")
	}
	// double revoke refused
	if err := svc.Revoke(ctx, id); err == nil {
		t.Fatal("double revocation accepted")
	}
}

func TestTokenScopingAndUnknowns(t *testing.T) {
	svc, owner := tokenEnv(t)
	ctx := context.Background()
	plain, _, err := svc.Create(ctx, owner, "work-only", "acct-42")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := svc.Validate(ctx, plain)
	if err != nil || ident.AccountID != "acct-42" {
		t.Fatalf("scope lost: %v %+v", err, ident)
	}
	if _, err := svc.Validate(ctx, "pact_"+strings.Repeat("0", 48)); err == nil {
		t.Fatal("unknown token validates")
	}
	if _, err := svc.Validate(ctx, "bearer-something-else"); err == nil {
		t.Fatal("non-pact token validates")
	}
	if _, _, err := svc.Create(ctx, owner, "", ""); err == nil {
		t.Fatal("unlabeled token accepted")
	}
}

func TestTokenListNeverLeaksSecrets(t *testing.T) {
	svc, owner := tokenEnv(t)
	ctx := context.Background()
	plain, _, _ := svc.Create(ctx, owner, "leaky?", "")
	list, err := svc.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %d", err, len(list))
	}
	blob, _ := json.Marshal(list)
	if strings.Contains(string(blob), plain) || strings.Contains(string(blob), plain[5:]) {
		t.Fatal("list output contains the secret")
	}
	if list[0].Label != "leaky?" || list[0].Revoked {
		t.Fatalf("metadata wrong: %+v", list[0])
	}
}
