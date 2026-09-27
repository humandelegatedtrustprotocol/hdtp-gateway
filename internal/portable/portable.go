// Package portable is what a person takes with them when they leave a host, and what a host takes
// in when they arrive (PACT §9.2, SPEC §3.10): one identity's CONTACTS, its CHATS and the FILES in
// them, in one unencrypted zip that any host can read, and nothing else.
//
// "Nothing else" is the whole design, so it is worth saying what is not here and why.
//
//   - No key of any kind. A leaf is the person's root entrusting ONE host for one address until
//     one date, and a copy of its key would let whoever held the file speak as that host.
//   - No settings, no integration credentials, no sessions, tokens or passkeys, no invites, no
//     audit chain, no ledger of leaves. Those belong to the HOST that made them.
//   - Not the root's certificate either: the file names its owner by the root's fingerprint, and
//     the certificate arrives with the first chain the wallet issues the importing host.
//
// It is written THROUGH the Store interface rather than by copying a database, so the file holds
// what this package asks the store for: there is no column to forget to blank and no table to
// forget to drop, and a node on Postgres exports exactly as one on SQLite does.
//
// The format and every rule about what a file may say are pact-identity's, shared with the cloud
// and the `pact` CLI: this package reads and writes the zip through pactidentity.ReadExportZip and
// WriteExportZip, and merges through export_merge. What is here is the node's side of it — its
// store's rows mapped to the format's and back, and its files.
package portable

import (
	"errors"
	"fmt"
)

// ErrRefused marks a file this host will not take, or an export it will not write, and says why.
// Nothing has been written when an import is refused.
var ErrRefused = errors.New("refused")

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, a...))
}

// ImportCeiling is the whole-file limit this host sets on what an import decompresses (PACT
// §9.2): far above any history a person accumulates, far below a disk.
const ImportCeiling = 16 << 30

// Result says what an export wrote or an import took in.
type Result struct {
	Contacts, Threads, Messages, Media int
	// AlreadyHere counts, on an import, the threads, messages and files this identity already
	// held; they are left as they are.
	AlreadyHere int
	// LeftOut names what an export did not carry, and why.
	LeftOut []string
}
