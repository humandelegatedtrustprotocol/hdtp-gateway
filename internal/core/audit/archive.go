package audit

// Archiving and re-anchoring the chain (SPEC §11.6).
//
// Pruning an append-only log is the one operation that can quietly destroy what
// the log is for. The chain detects edits and reordering because each row binds
// the previous row's hash — but a chain with its oldest rows removed is still
// internally consistent, so deletion alone is invisible. That is why archiving
// is not "export then delete":
//
//  1. the archived rows are written to a JSONL file and read back and verified
//     before anything is removed — an archive that cannot be verified means the
//     rows stay in the database;
//  2. the terminal hash of the archived segment is recorded durably, so what
//     remains is checked against it rather than against its own first row.
//
// Verification then spans the archive files plus the live table as one chain,
// and a head that was removed without archiving shows up as exactly what it is.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Store is the slice of the store this package needs.
type Store interface {
	ListAuditEvents(ctx context.Context, actorFilter string) ([]Row, error)
	AuditAnchor(ctx context.Context) (Anchor, error)
	SetAuditAnchor(ctx context.Context, a Anchor) error
	DeleteAuditEventsThrough(ctx context.Context, seq int64) (int64, error)
}

// Row is one stored audit row, in the store's shape.
type Row struct {
	Seq       int64
	TS        int64
	AccountID string
	ActorKind string
	ActorID   string
	Action    string
	Resource  string
	Outcome   string
	RequestID string
	Details   string
	PrevHash  string
	Hash      string
}

// Anchor is what the retained chain must extend.
type Anchor struct {
	ArchivedThroughSeq int64
	TerminalHash       string
	ArchivePath        string
	UpdatedAt          int64
}

func (r Row) event() Event { return Event(r) }

// Events converts stored rows.
func Events(rows []Row) []Event {
	out := make([]Event, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.event())
	}
	return out
}

// VerifyChain checks the live rows against the durable anchor: genesis when
// nothing has been archived, the archived segment's terminal hash afterwards.
// This is what `audit verify` calls, and the reason a removed head is visible.
func VerifyChain(ctx context.Context, st Store) (int, error) {
	anchor, err := st.AuditAnchor(ctx)
	if err != nil {
		return 0, err
	}
	rows, err := st.ListAuditEvents(ctx, "")
	if err != nil {
		return 0, err
	}
	expect := GenesisHash
	if anchor.TerminalHash != "" {
		expect = anchor.TerminalHash
	}
	// A crash between "record the anchor" and "delete the archived rows" leaves
	// rows the anchor already claims. Those rows do not link to the archived
	// terminal hash, so measuring them against it would report an honest chain
	// as broken — the worst answer a tamper-evidence tool can give. Name the
	// state instead; Repair finishes what the archive started.
	if pending := rowsAtOrBefore(rows, anchor.ArchivedThroughSeq); pending > 0 {
		return pending, fmt.Errorf("%w: %d row(s) through seq %d are recorded as archived "+
			"but still present — an archive run did not finish. Run `audit repair`.",
			ErrArchiveInterrupted, pending, anchor.ArchivedThroughSeq)
	}
	// An empty live table is NOT "intact". The anchor is a plain row: anyone who
	// can write it can claim everything was archived, and an empty chain would
	// then verify against a hash nothing has to match. Archiving refuses to take
	// the last row precisely so this state cannot arise honestly.
	if len(rows) == 0 {
		if anchor.TerminalHash == "" {
			return -1, nil // a node that has simply never written an audit row
		}
		return 0, fmt.Errorf("audit: the live chain is empty while the anchor claims "+
			"history through seq %d — every row was removed, which archiving never does",
			anchor.ArchivedThroughSeq)
	}
	return VerifyFrom(expect, Events(rows))
}

// VerifyWithArchives walks the archive files and then the live rows as ONE
// chain, which is what SPEC §11.6 promises. Files are read in the order given;
// each must continue where the previous ended.
func VerifyWithArchives(ctx context.Context, st Store, archives []string) (int, error) {
	prev := GenesisHash
	seen := 0
	for _, path := range archives {
		f, err := os.Open(path)
		if err != nil {
			return seen, fmt.Errorf("audit: opening archive %s: %w", path, err)
		}
		events, err := ImportJSONL(f)
		f.Close()
		if err != nil {
			return seen, fmt.Errorf("audit: reading archive %s: %w", path, err)
		}
		if bad, err := VerifyFrom(prev, events); err != nil {
			return seen + bad, fmt.Errorf("audit: archive %s: %w", path, err)
		}
		if len(events) > 0 {
			prev = events[len(events)-1].Hash
		}
		seen += len(events)
	}
	rows, err := st.ListAuditEvents(ctx, "")
	if err != nil {
		return seen, err
	}
	if bad, err := VerifyFrom(prev, Events(rows)); err != nil {
		return seen + bad, err
	}
	return -1, nil
}

// ArchiveResult reports what an archive run moved.
type ArchiveResult struct {
	Archived int
	Path     string
	Through  int64
	Terminal string
}

// Archive writes every row at or before `throughSeq` to a JSONL file in `dir`,
// verifies the file it just wrote, records the new anchor, and only then removes
// those rows. The order is the safety property: a failure at any step leaves the
// database holding rows that are still verifiable.
func Archive(ctx context.Context, st Store, dir string, throughSeq int64, now func() time.Time) (ArchiveResult, error) {
	if now == nil {
		now = time.Now
	}
	anchor, err := st.AuditAnchor(ctx)
	if err != nil {
		return ArchiveResult{}, err
	}
	// Finish any run that died mid-commit before starting a new one; otherwise
	// the verify below would refuse on a state that is merely unfinished.
	if _, err := Repair(ctx, st); err != nil {
		return ArchiveResult{}, err
	}
	if anchor, err = st.AuditAnchor(ctx); err != nil {
		return ArchiveResult{}, err
	}
	// Refuse to run on a chain that does not verify — archiving a broken chain
	// would bake the break into an archive nobody can re-check.
	if bad, err := VerifyChain(ctx, st); err != nil {
		return ArchiveResult{}, fmt.Errorf("audit: refusing to archive a chain that does not verify (row %d): %w", bad, err)
	}
	rows, err := st.ListAuditEvents(ctx, "")
	if err != nil {
		return ArchiveResult{}, err
	}
	var segment []Event
	for _, r := range rows {
		if r.Seq <= throughSeq {
			segment = append(segment, r.event())
		}
	}
	if len(segment) == 0 {
		return ArchiveResult{Through: anchor.ArchivedThroughSeq, Terminal: anchor.TerminalHash}, nil
	}
	// Never archive everything: the retained chain is what carries the anchor
	// forward, and an empty table cannot be told from a deleted one.
	if len(segment) == len(rows) {
		return ArchiveResult{}, fmt.Errorf("audit: refusing to archive the entire chain — " +
			"keep at least one row so the anchor has something to anchor")
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ArchiveResult{}, err
	}
	last := segment[len(segment)-1]
	path := filepath.Join(dir, fmt.Sprintf("audit-%020d-%020d.jsonl", segment[0].Seq, last.Seq))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ArchiveResult{}, fmt.Errorf("audit: creating archive: %w", err)
	}
	if err := ExportJSONL(f, segment); err != nil {
		f.Close()
		return ArchiveResult{}, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return ArchiveResult{}, err
	}
	if err := f.Close(); err != nil {
		return ArchiveResult{}, err
	}

	// Read back what was written and verify it BEFORE deleting anything.
	if err := verifyArchiveFile(path, expectedAnchor(anchor), last.Hash); err != nil {
		return ArchiveResult{}, err
	}

	if err := st.SetAuditAnchor(ctx, Anchor{
		ArchivedThroughSeq: last.Seq, TerminalHash: last.Hash,
		ArchivePath: path, UpdatedAt: now().Unix(),
	}); err != nil {
		return ArchiveResult{}, err
	}
	if _, err := st.DeleteAuditEventsThrough(ctx, last.Seq); err != nil {
		return ArchiveResult{}, err
	}
	return ArchiveResult{Archived: len(segment), Path: path, Through: last.Seq, Terminal: last.Hash}, nil
}

// ErrArchiveInterrupted marks the one inconsistency archiving can leave behind:
// the anchor was recorded and the rows it covers were not removed. It is a
// distinct error because it is NOT tampering, and the remedy is mechanical.
var ErrArchiveInterrupted = errors.New("audit: an archive run did not finish")

// rowsAtOrBefore counts live rows the anchor already claims to have archived.
func rowsAtOrBefore(rows []Row, seq int64) int {
	if seq <= 0 {
		return 0
	}
	n := 0
	for _, r := range rows {
		if r.Seq <= seq {
			n++
		}
	}
	return n
}

// Repair finishes an interrupted archive run, and reports how many rows it
// removed. It is safe precisely because of the order Archive uses: the archive
// file is written AND read back AND verified before the anchor is recorded, so
// an anchor that exists is proof the rows it covers were preserved.
//
// It re-checks that proof rather than trusting it. If the archive file is
// missing or no longer ends where the anchor says, the live rows are the only
// copy left and Repair refuses — losing history is worse than staying broken.
func Repair(ctx context.Context, st Store) (int64, error) {
	anchor, err := st.AuditAnchor(ctx)
	if err != nil {
		return 0, err
	}
	if anchor.TerminalHash == "" || anchor.ArchivedThroughSeq <= 0 {
		return 0, nil // nothing was ever archived
	}
	rows, err := st.ListAuditEvents(ctx, "")
	if err != nil {
		return 0, err
	}
	if rowsAtOrBefore(rows, anchor.ArchivedThroughSeq) == 0 {
		return 0, nil // already consistent
	}
	if anchor.ArchivePath == "" {
		return 0, fmt.Errorf("%w: the anchor names no archive file, so the rows in the "+
			"table are the only copy", ErrArchiveInterrupted)
	}
	if err := verifyArchiveFile(anchor.ArchivePath, GenesisHash, anchor.TerminalHash); err != nil {
		// The segment may be a continuation rather than rooted at genesis; a
		// terminal-hash match is what actually proves these rows are held.
		if terr := archiveEndsAt(anchor.ArchivePath, anchor.TerminalHash, anchor.ArchivedThroughSeq); terr != nil {
			return 0, fmt.Errorf("%w: refusing to delete rows whose archive cannot be "+
				"confirmed (%v)", ErrArchiveInterrupted, terr)
		}
	}
	return st.DeleteAuditEventsThrough(ctx, anchor.ArchivedThroughSeq)
}

// archiveEndsAt confirms a file is an internally consistent chain that ends at
// the expected hash, and that it reaches at least the anchored sequence.
//
// This is the fallback for a segment that is a CONTINUATION rather than rooted
// at genesis, so it cannot anchor at GenesisHash. It previously compared only
// the last line's `hash` field to the terminal hash — a value supplied by the
// file being checked. Nothing was recomputed, so an archive with any number of
// rewritten rows passed as long as its final line still carried the right
// string, and Repair then deleted those rows from the table: the authentic copy
// destroyed on the word of the forgery.
//
// Verify re-derives every hash from each row's own content and requires each to
// extend the one before, anchored at the segment's own first prev_hash. That
// cannot prove where the segment begins — only the genesis-rooted path can — but
// it does prove these rows are the rows that hash to this terminal, which is
// exactly the claim deletion rests on.
func archiveEndsAt(path, terminal string, through int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	events, err := ImportJSONL(f)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("archive %s holds no rows", path)
	}
	if bad, err := Verify(events); err != nil {
		return fmt.Errorf("archive %s does not verify at row %d: %w", path, bad, err)
	}
	last := events[len(events)-1]
	if last.Hash != terminal {
		return fmt.Errorf("archive %s does not end at the anchored hash", path)
	}
	// The rows about to be deleted run through `through`; an archive that stops
	// short of it does not hold all of them.
	if last.Seq < through {
		return fmt.Errorf("archive %s ends at seq %d, short of the anchored %d",
			path, last.Seq, through)
	}
	return nil
}

func expectedAnchor(a Anchor) string {
	if a.TerminalHash == "" {
		return GenesisHash
	}
	return a.TerminalHash
}

// verifyArchiveFile re-reads an archive and checks it links where it should and
// ends where the caller believes it ends.
func verifyArchiveFile(path, anchor, terminal string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	events, err := ImportJSONL(io.Reader(f))
	if err != nil {
		return fmt.Errorf("audit: archive %s is unreadable: %w", path, err)
	}
	if bad, err := VerifyFrom(anchor, events); err != nil {
		return fmt.Errorf("audit: archive %s does not verify at row %d: %w", path, bad, err)
	}
	if len(events) == 0 || events[len(events)-1].Hash != terminal {
		return fmt.Errorf("audit: archive %s does not end where expected", path)
	}
	return nil
}
