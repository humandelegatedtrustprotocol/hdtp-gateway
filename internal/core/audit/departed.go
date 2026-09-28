package audit

// The audit trail of an identity that left (SPEC §3.11, §11.6).
//
// A leave erases every record of the identity at once, and the trail is the one
// place it cannot: its rows are a hash chain, append-only by trigger. So they stay
// in the live table for a period (the node's audit_archive_after), and then this
// file's job moves every row that names the identity by its account id — in the
// row's account column or in its resource — to a file of the identity's
// own, <data_dir>/audit-archive/<account-id>-<from>-<to>.jsonl, mode 0600.
//
// The rows come from the MIDDLE of the chain, and every row still carries the
// prev_hash it was sealed with. Verification therefore puts the archived rows back
// in their places by seq (Merge) and walks one chain: a file that is missing, cut
// short or edited leaves a row that does not link or does not hash, and is broken.
//
// The move is ordered so that a crash at any point loses no row and duplicates none:
//
//  1. the file is written under a temporary name, synced, renamed into place, and
//     read back: every row must be the live row, field for field, and hash to its
//     own hash;
//  2. one `audit_archive` row is appended to the chain, naming the segment and its
//     hashes and not the identity. It is the chain's newest row, so the rows about
//     to go are never the tail (the writer's next seq is read from the tail);
//  3. one transaction lists the rows by seq and hash where the prune guard admits
//     them, deletes them, and empties the list (Store.ArchiveRows).
//
// A run that died after 1 finds its file and reuses it; after 2, it finds its
// `audit_archive` row by the segment's first seq, and neither writes a second one
// nor moves a row it did not name. Until 3 commits, every row is still live, and a
// row in both the table and a file is the same row: Merge counts it, and `audit
// verify` reports the run unfinished rather than broken.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ArchiveAction is the audit action of the row an identity's archive writes.
const ArchiveAction = "audit_archive"

// EraseAction is the audit action of the row `audit erase-archive` writes.
const EraseAction = "audit_archive_erase"

// DepartedStore is the slice of the store the identity archive needs.
type DepartedStore interface {
	Store
	// ListDueLeaves is the account_leave rows whose erase went through, at or
	// before `before`, oldest first.
	ListDueLeaves(ctx context.Context, before int64, limit int) ([]Row, error)
	// ArchiveRows removes exactly these rows (by seq and hash) in one transaction.
	ArchiveRows(ctx context.Context, rows []Row) (int64, error)
	// AccountExists reports whether the account is still on this node.
	AccountExists(ctx context.Context, accountID string) (bool, error)
}

// Departed moves the trail of the identities that left at least After ago.
type Departed struct {
	Store DepartedStore
	// Dir is <data_dir>/audit-archive.
	Dir string
	// After is how long the rows stay in the live trail after the leave.
	After time.Duration
	Now   func() time.Time
	// Append writes one row to the chain through the node's ONE writer, and says
	// whether it was written: a second writer would fork the chain.
	Append func(action, resource, outcome string) error
}

// Segment is what one identity's archive moved.
type Segment struct {
	AccountID string
	From, To  int64
	Rows      int
	// Before is the prev_hash of the segment's first row; After the hash of its last.
	Before, After string
	Path          string
}

// dueBatch bounds one sweep's read of the leave rows. The sweep runs hourly and
// the rest wait for the next one.
const dueBatch = 100

// Run archives the trail of every identity whose leave is due, and reports what
// it moved. It stops at the first identity it cannot archive: the rows stay
// where they are, and the next sweep tries again.
func (d *Departed) Run(ctx context.Context) ([]Segment, error) {
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	due, err := d.Store.ListDueLeaves(ctx, now().Add(-d.After).Unix(), dueBatch)
	if err != nil || len(due) == 0 {
		return nil, err
	}
	var out []Segment
	seen := map[string]bool{}
	for _, l := range due {
		if l.AccountID == "" || seen[l.AccountID] {
			continue
		}
		seen[l.AccountID] = true
		// A leave that went through erased the account; one that is here again is not
		// an identity that left, and its trail is its own.
		if here, err := d.Store.AccountExists(ctx, l.AccountID); err != nil || here {
			if err != nil {
				return out, err
			}
			continue
		}
		seg, err := d.archive(ctx, l.AccountID)
		if err != nil {
			return out, fmt.Errorf("audit: archiving the trail of %s: %w", l.AccountID, err)
		}
		if seg.Rows > 0 {
			out = append(out, seg)
		}
	}
	return out, nil
}

// Names reports whether a row names the account: its account column, or the id in
// its resource. The node fills the column from the resource's `account:` prefix
// today (auditsink); a row written before it did has the id in its resource and an
// empty column. An account id is 32 random hex digits. The node writes no details
// (every row's is `{}`), so there is nothing there to name anybody.
func Names(e Event, accountID string) bool {
	return e.AccountID == accountID || strings.Contains(e.Resource, accountID)
}

func (d *Departed) archive(ctx context.Context, accountID string) (Segment, error) {
	if err := os.MkdirAll(d.Dir, 0o700); err != nil {
		return Segment{}, err
	}
	archived, err := ReadArchives(d.Dir)
	if err != nil {
		return Segment{}, err
	}
	// Never move rows out of a chain that does not verify: the break would go with them.
	if bad, err := VerifyChain(ctx, d.Store, archived); err != nil {
		return Segment{}, fmt.Errorf("the chain does not verify (row %d): %w", bad, err)
	}
	rows, err := d.Store.ListAuditEvents(ctx, "")
	if err != nil {
		return Segment{}, err
	}
	live := Events(rows)
	var named []Event
	for _, e := range live {
		if Names(e, accountID) {
			named = append(named, e)
		}
	}
	if len(named) == 0 {
		return Segment{AccountID: accountID}, nil
	}
	from := named[0].Seq
	// A run that died after appending its row: that row fixes the segment's end.
	to, recorded := int64(0), false
	for _, e := range live {
		if f, t, ok := segmentOf(e); ok && f == from {
			to, recorded = t, true
		}
	}
	if !recorded {
		to = named[len(named)-1].Seq
	}
	var seg []Event
	for _, e := range named {
		if e.Seq <= to {
			seg = append(seg, e)
		}
	}
	path := filepath.Join(d.Dir, fmt.Sprintf("%s-%020d-%020d.jsonl", accountID, from, to))
	if err := d.clearStale(accountID, path, live); err != nil {
		return Segment{}, err
	}
	if err := writeSegment(d.Dir, path, seg); err != nil {
		return Segment{}, err
	}
	out := Segment{AccountID: accountID, From: from, To: to, Rows: len(seg),
		Before: seg[0].PrevHash, After: seg[len(seg)-1].Hash, Path: path}
	if !recorded {
		resource := fmt.Sprintf("segment:%d-%d rows:%d before:%s after:%s", from, to, len(seg), out.Before, out.After)
		if err := d.Append(ArchiveAction, resource, "ok"); err != nil {
			return Segment{}, fmt.Errorf("recording the archive: %w", err)
		}
	}
	toGo := make([]Row, 0, len(seg))
	for _, e := range seg {
		toGo = append(toGo, Row{Seq: e.Seq, Hash: e.Hash})
	}
	n, err := d.Store.ArchiveRows(ctx, toGo)
	if err != nil {
		return Segment{}, fmt.Errorf("removing the archived rows: %w", err)
	}
	if n != int64(len(seg)) {
		return Segment{}, fmt.Errorf("removed %d of the %d archived rows", n, len(seg))
	}
	return out, nil
}

// segmentOf reads the segment an `audit_archive` row names.
func segmentOf(e Event) (from, to int64, ok bool) {
	if e.Action != ArchiveAction || !strings.HasPrefix(e.Resource, "segment:") {
		return 0, 0, false
	}
	span, _, _ := strings.Cut(strings.TrimPrefix(e.Resource, "segment:"), " ")
	f, t, found := strings.Cut(span, "-")
	if !found {
		return 0, 0, false
	}
	from, err1 := strconv.ParseInt(f, 10, 64)
	to, err2 := strconv.ParseInt(t, 10, 64)
	return from, to, err1 == nil && err2 == nil
}

// clearStale removes what an earlier run of this identity left behind: a
// temporary file, and a finished file whose rows are all still live rows (its run
// died before the delete, and the segment has since been drawn again). A file that
// holds a row the table does not is an archive, and is never touched.
func (d *Departed) clearStale(accountID, keep string, live []Event) error {
	entries, err := os.ReadDir(d.Dir)
	if err != nil {
		return err
	}
	bySeq := map[int64]Event{}
	for _, e := range live {
		bySeq[e.Seq] = e
	}
	for _, ent := range entries {
		name := ent.Name()
		full := filepath.Join(d.Dir, name)
		if strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".tmp") {
			if err := os.Remove(full); err != nil {
				return err
			}
			continue
		}
		if full == keep || !strings.HasPrefix(name, accountID+"-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		events, err := readFile(full)
		if err != nil {
			return err
		}
		stale := true
		for _, e := range events {
			if l, ok := bySeq[e.Seq]; !ok || l != e {
				stale = false
				break
			}
		}
		if stale {
			if err := os.Remove(full); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeSegment writes the rows to path, or finds them there already, and reads
// them back: every row the file holds must be the row given, field for field, and
// hash to its own hash.
func writeSegment(dir, path string, seg []Event) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := writeFileSynced(dir, path, seg); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	back, err := readFile(path)
	if err != nil {
		return err
	}
	if len(back) != len(seg) {
		return fmt.Errorf("%s holds %d rows, want %d", path, len(back), len(seg))
	}
	for i := range seg {
		if back[i] != seg[i] {
			return fmt.Errorf("%s: row %d is not the row in the table", path, back[i].Seq)
		}
		if h, err := HashEvent(back[i]); err != nil || h != back[i].Hash {
			return fmt.Errorf("%s: row %d does not hash to its hash", path, back[i].Seq)
		}
	}
	return nil
}

func randomName() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func readFile(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	events, err := ImportJSONL(f)
	if err != nil {
		return nil, fmt.Errorf("audit: archive %s: %w", path, err)
	}
	return events, nil
}

// ArchiveFiles lists the identity archives in dir, a temporary file of an
// unfinished write excepted.
func ArchiveFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ent := range entries {
		if n := ent.Name(); !ent.IsDir() && !strings.HasPrefix(n, ".") && strings.HasSuffix(n, ".jsonl") {
			out = append(out, filepath.Join(dir, n))
		}
	}
	sort.Strings(out)
	return out, nil
}

// ReadArchives reads every row the identity archives in dir hold.
func ReadArchives(dir string) ([]Event, error) {
	files, err := ArchiveFiles(dir)
	if err != nil {
		return nil, err
	}
	var out []Event
	for _, f := range files {
		events, err := readFile(f)
		if err != nil {
			return nil, err
		}
		out = append(out, events...)
	}
	return out, nil
}

// Merge puts rows from anywhere — the live table, head archives, identity
// archives — into one chain in seq order. A seq held twice must be the same row
// (field for field): that is a row an archive has written and not yet removed,
// and `both` counts them. A seq held twice with different content is a break.
func Merge(primary, archived []Event) (merged []Event, both int, err error) {
	all := make([]Event, 0, len(primary)+len(archived))
	all = append(all, primary...)
	all = append(all, archived...)
	sort.SliceStable(all, func(i, j int) bool { return all[i].Seq < all[j].Seq })
	for _, e := range all {
		if n := len(merged); n > 0 && merged[n-1].Seq == e.Seq {
			if merged[n-1] != e {
				return nil, 0, fmt.Errorf("audit: seq %d is held twice with different content — "+
					"an archive or the table was altered", e.Seq)
			}
			both++
			continue
		}
		merged = append(merged, e)
	}
	return merged, both, nil
}

// Erase replaces an identity archive's rows with what the chain needs of them —
// seq, prev_hash and hash — when law requires the rows themselves to go (SPEC
// §11.6). The rows' content, the account id among it, is gone; the chain still
// links through them, and verification reports them as erased. The erased file is
// named by its seqs alone. It returns the new file's path and how many rows it
// erased.
func Erase(path string) (string, int, error) {
	events, err := readFile(path)
	if err != nil {
		return "", 0, err
	}
	if len(events) == 0 {
		return "", 0, fmt.Errorf("audit: %s holds no rows", path)
	}
	skel := make([]Event, 0, len(events))
	for _, e := range events {
		skel = append(skel, Event{Seq: e.Seq, PrevHash: e.PrevHash, Hash: e.Hash, Erased: true})
	}
	dir := filepath.Dir(path)
	out := filepath.Join(dir, fmt.Sprintf("erased-%020d-%020d.jsonl", events[0].Seq, events[len(events)-1].Seq))
	if out != path {
		if _, err := os.Stat(out); err == nil {
			return "", 0, fmt.Errorf("audit: %s already exists", out)
		}
	}
	if err := writeFileSynced(dir, out, skel); err != nil {
		return "", 0, err
	}
	if out != path {
		if err := os.Remove(path); err != nil {
			return "", 0, err
		}
		if err := syncDir(dir); err != nil {
			return "", 0, err
		}
	}
	return out, len(events), nil
}

// writeFileSynced replaces path with the rows, through a synced temporary file.
func writeFileSynced(dir, path string, rows []Event) error {
	var buf bytes.Buffer
	if err := ExportJSONL(&buf, rows); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+randomName()+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}
