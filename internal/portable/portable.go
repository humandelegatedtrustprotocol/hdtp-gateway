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
// §9.2). It bounds the DISK an import can fill: the media files, which are most of any export's
// bytes, are hashed as they stream and written one at a time, never held together.
const ImportCeiling = 16 << 30

// ImportMessagesCeiling bounds what an import holds in MEMORY. messages.jsonl is the one member read
// into memory whole: every message becomes a row in the plan the person reviews, and Apply writes
// them in one transaction. Measured on 2026-09-28 (TestAnImportsMemoryFollowsItsMessages, 1 KB
// bodies, 10,000 and 40,000 messages): reading allocates 11.4-11.5 bytes per byte of
// messages.jsonl in all, and the plan holds 1.1-1.3 bytes per byte once the collector has run. At
// 128 MiB the read allocates at most about 1.5 GiB over its course and holds about 170 MB; a
// larger messages.jsonl is refused by its declared size, which archive/zip holds the member to,
// before a byte of it is read. (The contacts and threads members are bounded by the format, at
// 4 MiB and 16 MiB.)
const ImportMessagesCeiling = 128 << 20

// Result says what an export wrote or an import took in.
type Result struct {
	Contacts, Threads, Messages, Media int
	// PinsFilled counts, on an import, the contacts held here with no leaf whose pin the file
	// filled; Contacts counts the contacts it added.
	PinsFilled int
	// AlreadyHere counts, on an import, the threads, messages and files this identity already
	// held; they are left as they are.
	AlreadyHere int
	// LeftOut names what an export did not carry, and why.
	LeftOut []string
}
