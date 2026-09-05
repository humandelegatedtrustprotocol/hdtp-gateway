// Package migrations embeds the per-engine schema migrations (SPEC §11.1) so the
// binary migrates itself — `pact-gateway migrate` and first-run setup need no
// external goose binary.
package migrations

import "embed"

//go:embed sqlite/*.sql
var SQLite embed.FS

//go:embed postgres/*.sql
var Postgres embed.FS
