package integrationtest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// An owner's scope — which accounts an owner may manage — is decided in one place for every owner
// door: policy.OwnerScope, reading the owner's memberships through internal/internalui/auth's
// Memberships, then policy.AllowOwnerManage. The portal (account_resolve.go) and the owner MCP
// (ownermcp/server.go) each looped the memberships themselves, while policy's README called itself
// the single owner-manage call site. So outside the store, the memberships are read only by that
// adapter and by identity's adoption of orphan accounts, which decides nothing about access; and the
// adapter is called only by OwnerScope, so no door reads its list and decides on its own.
func TestAnOwnersScopeIsReadInOnePlace(t *testing.T) {
	root := repoRoot(t)
	want := []string{"internal/identity/membership.go", "internal/internalui/auth/scope.go"}
	wantLister := []string{"internal/core/policy/policy.go"}
	var got, lister []string
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "internal/core/store/") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), ".ListMembershipsByOwner(") {
			got = append(got, rel)
		}
		if strings.Contains(string(src), ".OwnerMemberships(") {
			lister = append(lister, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("the owner's memberships are read by %v; want only %v (an owner door decides scope through policy.OwnerScope)", got, want)
	}
	slices.Sort(lister)
	if !slices.Equal(lister, wantLister) {
		t.Fatalf("policy.MembershipLister.OwnerMemberships is called by %v; want only %v (an owner door decides scope through policy.OwnerScope)", lister, wantLister)
	}
}
