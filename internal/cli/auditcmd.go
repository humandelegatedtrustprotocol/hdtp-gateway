package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/audit"
)

func auditCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: pact-gateway audit <verify|export|archive|repair> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	var cfgPath string
	var throughSeq int64
	fs := commonFlags("audit "+sub, &cfgPath, stderr)
	fs.Int64Var(&throughSeq, "through", 0, "archive: archive events up to and including this seq")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "audit:", err)
		return 1
	}
	// Offline command (SPEC §12.1): refuse while the node holds the lock.
	lock, err := core.AcquireLock(cfg.DataDir)
	if err != nil {
		fmt.Fprintln(stderr, "audit:", err)
		return 1
	}
	defer lock.Release()
	st, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "audit:", err)
		return 1
	}
	defer st.Close()
	rows, err := st.ListAuditEvents(context.Background(), "")
	if err != nil {
		fmt.Fprintln(stderr, "audit:", err)
		return 1
	}
	events := make([]audit.Event, 0, len(rows))
	for _, r := range rows {
		events = append(events, audit.Event{
			Seq: r.Seq, TS: r.TS, AccountID: r.AccountID, ActorKind: r.ActorKind,
			ActorID: r.ActorID, Action: r.Action, Resource: r.Resource, Outcome: r.Outcome,
			RequestID: r.RequestID, Details: r.Details, PrevHash: r.PrevHash, Hash: r.Hash,
		})
	}
	as := auditStore{st: st}
	switch sub {
	case "verify":
		// Anchored: the retained rows must extend genesis, or the terminal hash
		// of whatever was archived. Verifying a chain against its own first row
		// cannot see a head that was removed (SPEC §11.6).
		if idx, err := audit.VerifyChain(context.Background(), as); err != nil {
			// An unfinished archive run is not tampering, and saying "BROKEN"
			// would send an owner hunting an intruder who is not there.
			if errors.Is(err, audit.ErrArchiveInterrupted) {
				fmt.Fprintf(stderr, "audit: %v\n", err)
				return 1
			}
			fmt.Fprintf(stderr, "audit: chain BROKEN at row %d: %v\n", idx, err)
			return 1
		}
		anchor, _ := st.AuditAnchor(context.Background())
		if anchor.TerminalHash != "" {
			// The archive is PART of the chain, so a missing archive is a
			// missing chain — not a reason to report success. Verifying only
			// what happens to still be on disk would reintroduce exactly the
			// "deleted history is invisible" hole §11.6 exists to close.
			archives := archiveFiles(cfg.DataDir)
			if len(archives) == 0 {
				fmt.Fprintf(stderr, "audit: chain BROKEN: the anchor names an archive through seq %d "+
					"but no archive files are present in %s\n", anchor.ArchivedThroughSeq, archiveDir(cfg.DataDir))
				return 1
			}
			if _, err := os.Stat(anchor.ArchivePath); err != nil && anchor.ArchivePath != "" {
				fmt.Fprintf(stderr, "audit: chain BROKEN: the archive the anchor names (%s) is gone\n",
					anchor.ArchivePath)
				return 1
			}
			if idx, err := audit.VerifyWithArchives(context.Background(), as, archives); err != nil {
				fmt.Fprintf(stderr, "audit: chain BROKEN at row %d: %v\n", idx, err)
				return 1
			}
			fmt.Fprintf(stdout, "audit chain verified across %d archive file(s) + %d live events, intact\n",
				len(archives), len(events))
			return 0
		}
		fmt.Fprintf(stdout, "audit chain verified: %d events, intact\n", len(events))
		return 0
	case "repair":
		// Finish an archive run that died between recording the anchor and
		// removing the rows it covers. Safe because the archive file was
		// written, read back and verified before the anchor was ever written.
		n, err := audit.Repair(context.Background(), as)
		if err != nil {
			fmt.Fprintln(stderr, "audit:", err)
			return 1
		}
		if n == 0 {
			fmt.Fprintln(stdout, "audit: nothing to repair")
			return 0
		}
		fmt.Fprintf(stdout, "audit: repaired an interrupted archive; removed %d row(s)\n", n)
		return 0
	case "archive":
		res, err := audit.Archive(context.Background(), as, archiveDir(cfg.DataDir), throughSeq, nil)
		if err != nil {
			fmt.Fprintln(stderr, "audit:", err)
			return 1
		}
		if res.Archived == 0 {
			fmt.Fprintln(stdout, "audit: nothing to archive")
			return 0
		}
		fmt.Fprintf(stdout, "archived %d events through seq %d to %s\n", res.Archived, res.Through, res.Path)
		return 0
	case "export":
		if err := audit.ExportJSONL(stdout, events); err != nil {
			fmt.Fprintln(stderr, "audit:", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintln(stderr, "usage: pact-gateway audit <verify|export|archive|repair> [flags]")
		return 2
	}
}

// archiveDir is where audit archives live: beside the store, so a backup that
// copies the data directory copies the chain's history with it.
func archiveDir(dataDir string) string { return filepath.Join(dataDir, "audit") }

// archiveFiles lists the archive segments in seq order — the filenames are
// zero-padded, so lexical order is chain order.
func archiveFiles(dataDir string) []string {
	matches, err := filepath.Glob(filepath.Join(archiveDir(dataDir), "audit-*.jsonl"))
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	return matches
}
