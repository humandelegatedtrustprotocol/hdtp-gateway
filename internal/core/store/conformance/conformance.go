// Package conformance is the single test suite every Store engine must pass
// (SPEC §11.1): the engines cannot drift apart because they are judged by the
// same tests. Engine packages call Run with a fresh-store factory.
package conformance

import (
	"context"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// Migratable is what the suite needs beyond store.Store: down-migration for the
// up/down/up cleanliness check.
type Migratable interface {
	store.Store
	// MigrateDown rolls the schema back to version 0.
	MigrateDown(ctx context.Context) error
}

// Factory returns a NEW, empty, unmigrated store. The suite migrates it. Clean-up is the factory's:
// the SQLite caller's file is under t.TempDir(), and the Postgres caller closes the store in
// t.Cleanup but leaves its database hdtp_conf_N, which the next run's factory call drops
// (DROP DATABASE IF EXISTS) before it creates the database again.
type Factory func(t *testing.T) Migratable

// Run judges one engine by the whole suite, area by area, in one fixed order.
func Run(t *testing.T, newStore Factory) {
	migrations(t, newStore)
	ownersAndAccounts(t, newStore)
	contacts(t, newStore)
	ownerUnderAChosenID(t, newStore)
	petnames(t, newStore)
	importAndMove(t, newStore)
	identityState(t, newStore)
	retention(t, newStore)
	conversationDeletion(t, newStore)
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
