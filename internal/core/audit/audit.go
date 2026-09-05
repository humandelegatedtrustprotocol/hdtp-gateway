// Package audit implements the append-only audit hash chain of SPEC §11.4–§11.6:
// every event binds SHA-256(prev_hash ‖ canonical row); the genesis prev_hash is 32
// zero bytes; hashes are stored lowercase-hex; verification re-walks the chain and
// reports the first break; JSONL archives re-anchor and verify as one chain with the
// live table.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ChainVersion is the chain-format version (SPEC §11.4): it names the enumerated
// field list hashed below. Changing the fields bumps this and re-anchors the chain.
const ChainVersion = 1

// GenesisHash is the stored (lowercase-hex) form of the 32 zero bytes that seed
// the chain.
var GenesisHash = strings.Repeat("0", 64)

// Event is one audit row (SPEC §11.2 audit_events). PrevHash/Hash are lowercase hex.
type Event struct {
	Seq       int64  `json:"seq"`
	TS        int64  `json:"ts"`
	AccountID string `json:"account_id"`
	ActorKind string `json:"actor_kind"`
	ActorID   string `json:"actor_id"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	Outcome   string `json:"outcome"`
	RequestID string `json:"request_id"`
	Details   string `json:"details"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

// canonicalRow serializes the hashed field list as canonical JSON: UTF-8, keys
// lexicographically sorted, no insignificant whitespace, no HTML escaping — the
// same canonicalization as the envelope's protected header (SPEC §4.1). Field
// order below IS the sorted key order; struct declaration order carries it.
func canonicalRow(e Event) ([]byte, error) {
	row := struct {
		AccountID string `json:"account_id"`
		Action    string `json:"action"`
		ActorID   string `json:"actor_id"`
		ActorKind string `json:"actor_kind"`
		Details   string `json:"details"`
		Outcome   string `json:"outcome"`
		RequestID string `json:"request_id"`
		Resource  string `json:"resource"`
		Seq       int64  `json:"seq"`
		TS        int64  `json:"ts"`
		V         int    `json:"v"`
	}{
		AccountID: e.AccountID, Action: e.Action, ActorID: e.ActorID,
		ActorKind: e.ActorKind, Details: e.Details, Outcome: e.Outcome,
		RequestID: e.RequestID, Resource: e.Resource, Seq: e.Seq, TS: e.TS,
		V: ChainVersion,
	}
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(row); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	// Encoder appends a newline; the canonical form has none.
	return []byte(strings.TrimSuffix(b.String(), "\n")), nil
}

// HashEvent computes the event's chain hash: SHA-256 over the raw 32 bytes of
// PrevHash followed by the canonical row.
func HashEvent(e Event) (string, error) {
	prev, err := hex.DecodeString(e.PrevHash)
	if err != nil || len(prev) != 32 {
		return "", fmt.Errorf("audit: prev_hash %q is not 32 hex bytes", e.PrevHash)
	}
	row, err := canonicalRow(e)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(row)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Next fills PrevHash and Hash for an event that follows prevHash (GenesisHash for
// the first event). This is the single sealing path for new rows.
func Next(prevHash string, e Event) (Event, error) {
	e.PrevHash = prevHash
	h, err := HashEvent(e)
	if err != nil {
		return Event{}, err
	}
	e.Hash = h
	return e, nil
}

// Verify re-walks a chain segment in order. The first event's PrevHash anchors the
// segment (GenesisHash for a full chain; an archived segment's terminal hash after
// re-anchoring — SPEC §11.6). It returns the index of the first broken row.
// Verify checks a chain against whatever its first row claims to follow. It
// cannot detect a truncated head — the shortened chain is self-consistent — so
// it is only correct for a segment whose anchor the caller already trusts.
// Prefer VerifyFrom, which takes that anchor explicitly.
func Verify(events []Event) (int, error) {
	if len(events) == 0 {
		return -1, nil
	}
	return VerifyFrom(events[0].PrevHash, events)
}

// VerifyFrom checks that the events extend `anchor` — GenesisHash for a chain
// that has never been archived, or the terminal hash of the archived segment
// once it has (SPEC §11.6). Anchoring is what makes deletion visible: without
// it, removing the oldest rows leaves a chain that still verifies.
func VerifyFrom(anchor string, events []Event) (int, error) {
	prev := anchor
	for i, e := range events {
		if e.PrevHash != prev {
			return i, fmt.Errorf("audit: row %d (seq %d) prev_hash %q does not extend %q — "+
				"the chain is broken, reordered, or its head was removed", i, e.Seq, e.PrevHash, prev)
		}
		want, err := HashEvent(e)
		if err != nil {
			return i, err
		}
		if e.Hash != want {
			return i, fmt.Errorf("audit: row %d hash mismatch", i)
		}
		prev = e.Hash
	}
	return -1, nil
}

// ExportJSONL writes events one JSON object per line (SPEC §11.6 archives).
func ExportJSONL(w io.Writer, events []Event) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return fmt.Errorf("audit: %w", err)
		}
	}
	return nil
}

// ImportJSONL reads an archive produced by ExportJSONL.
func ImportJSONL(r io.Reader) ([]Event, error) {
	var out []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("audit: line %d: %w", len(out)+1, err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	return out, nil
}
