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
	"github.com/pact-cloud/pact-gateway/internal/core/auditstore"
)

const auditUsage = "usage: pact-gateway audit <verify|export|archive|repair|erase-archive> [flags]"

func auditCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, auditUsage)
		return 2
	}
	sub, rest := args[0], args[1:]
	var cfgPath string
	var throughSeq int64
	var eraseFile string
	fs := commonFlags("audit "+sub, &cfgPath, stderr)
	fs.Int64Var(&throughSeq, "through", 0, "archive: archive events up to and including this seq")
	fs.StringVar(&eraseFile, "file", "", "erase-archive: the identity archive under <data_dir>/audit-archive to erase")
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
	as := auditstore.Adapter{St: st}
	// The identity archives (SPEC §3.11, §11.6): rows from the middle of the chain, which every
	// check below puts back in their places.
	idDir := identityArchiveDir(cfg.DataDir)
	idFiles, err := audit.ArchiveFiles(idDir)
	if err != nil {
		fmt.Fprintln(stderr, "audit:", err)
		return 1
	}
	archived, err := audit.ReadArchives(idDir)
	if err != nil {
		fmt.Fprintf(stderr, "audit: chain BROKEN: %v\n", err)
		return 1
	}
	switch sub {
	case "verify":
		// Anchored: the retained rows must extend genesis, or the terminal hash
		// of whatever was archived. Verifying a chain against its own first row
		// cannot see a head that was removed (SPEC §11.6).
		if idx, err := audit.VerifyChain(context.Background(), as, archived); err != nil {
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
			if idx, err := audit.VerifyWithArchives(context.Background(), as, archives, archived); err != nil {
				fmt.Fprintf(stderr, "audit: chain BROKEN at row %d: %v\n", idx, err)
				return 1
			}
			fmt.Fprintf(stdout, "audit chain verified across %d archive file(s) + %d live events%s, intact\n",
				len(archives), len(events), identitySummary(idFiles, archived, events))
			return 0
		}
		fmt.Fprintf(stdout, "audit chain verified: %d events%s, intact\n", len(events), identitySummary(idFiles, archived, events))
		return 0
	case "repair":
		// Finish an archive run that died between recording the anchor and
		// removing the rows it covers. Safe because the archive file was
		// written, read back and verified before the anchor was ever written.
		n, err := audit.Repair(context.Background(), as, archived)
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
		res, err := audit.Archive(context.Background(), as, archiveDir(cfg.DataDir), throughSeq, archived, nil)
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
	case "erase-archive":
		// When law requires an identity's archived rows to go (SPEC §11.6): their content goes,
		// the account id with it, and what the chain needs of them — seq, prev_hash, hash — stays,
		// so `verify` still walks one chain and reports the rows as erased.
		return eraseArchive(st, idDir, eraseFile, events, stdout, stderr)
	case "export":
		if err := audit.ExportJSONL(stdout, events); err != nil {
			fmt.Fprintln(stderr, "audit:", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintln(stderr, auditUsage)
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

// identityArchiveDir is where the trail of an identity that left goes once its period is over
// (SPEC §3.11): beside the store, like the head archives, so a backup of the data directory
// carries it.
func identityArchiveDir(dataDir string) string { return filepath.Join(dataDir, "audit-archive") }

// identitySummary is what verify says of the identity archives: how many files and rows, how many
// of those rows were erased, and how many are still in the table as well (a run the node's next
// sweep finishes).
func identitySummary(files []string, archived, live []audit.Event) string {
	if len(files) == 0 {
		return ""
	}
	erased := 0
	for _, e := range archived {
		if e.Erased {
			erased++
		}
	}
	_, both, _ := audit.Merge(live, archived)
	out := fmt.Sprintf(" + %d identity archive file(s) holding %d row(s)", len(files), len(archived))
	if erased > 0 {
		out += fmt.Sprintf(", %d of them erased", erased)
	}
	if both > 0 {
		out += fmt.Sprintf(" (%d of them still in the table too: an archive run has not finished, and the node's next sweep finishes it)", both)
	}
	return out
}

// eraseArchive is `audit erase-archive -file NAME`: one identity archive's rows are reduced to
// seq, prev_hash and hash, and one audit row says so.
func eraseArchive(st audit.Sink, dir, name string, live []audit.Event, stdout, stderr io.Writer) int {
	if name == "" {
		fmt.Fprintln(stderr, "audit: erase-archive needs -file, the name of a file in", dir)
		return 2
	}
	path := filepath.Join(dir, filepath.Base(name))
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(stderr, "audit: %s is not an identity archive in %s\n", name, dir)
		return 1
	}
	// A file whose rows are still in the table belongs to a run that has not finished: erasing it
	// would leave the table's rows beside skeletons that differ from them.
	held, err := audit.ReadArchives(dir)
	if err != nil {
		fmt.Fprintln(stderr, "audit:", err)
		return 1
	}
	if _, both, _ := audit.Merge(live, held); both > 0 {
		fmt.Fprintln(stderr, "audit: an archive run has not finished (its rows are still in the table); start the node once so its sweep finishes it, then erase")
		return 1
	}
	out, n, err := audit.Erase(path)
	if err != nil {
		fmt.Fprintln(stderr, "audit:", err)
		return 1
	}
	w := &audit.Writer{Sink: st}
	if err := w.Append(context.Background(), "", "cli", "", audit.EraseAction,
		fmt.Sprintf("file:%s rows:%d", filepath.Base(out), n), "ok", "", ""); err != nil {
		fmt.Fprintf(stderr, "audit: the archive was erased and the audit row was not written: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "erased %d row(s): %s now holds their seq and hashes only\n", n, out)
	return 0
}
