// Package conformance is the single test suite every Store engine must pass
// (SPEC §11.1): the engines cannot drift apart because they are judged by the
// same tests. Engine packages call Run with a fresh-store factory.
package conformance

import (
	"context"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// Migratable is what the suite needs beyond store.Store: down-migration for the
// up/down/up cleanliness check.
type Migratable interface {
	store.Store
	MigrateDown(ctx context.Context) error
}

// Factory returns a NEW, empty, unmigrated store. The suite migrates it and the
// factory's cleanup must drop whatever it created.
type Factory func(t *testing.T) Migratable

// Run judges one engine by the whole suite, area by area, in one fixed order.
func Run(t *testing.T, newStore Factory) {
	migrations(t, newStore)
	ownersAndAccounts(t, newStore)
	contacts(t, newStore)
	ownerUnderAChosenID(t, newStore)
	petnames(t, newStore)
	importAndMove(t, newStore)
	pact20State(t, newStore)
	retention(t, newStore)
	settings(t, newStore)
	credentials(t, newStore)
	messages(t, newStore)
	memberships(t, newStore)
	integrations(t, newStore)
	auditPages(t, newStore)
}

func migrated(t *testing.T, newStore Factory) Migratable {
	t.Helper()
	s := newStore(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}
