package portable

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/messaging"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// Export writes one identity — its contacts, its conversations and the files in them — to w as an
// export (PACT §9.2). An identity the wallet has never certified has no root, so it has no owner a
// file could name, and is refused. tool names the writer in the manifest; now dates it.
func Export(ctx context.Context, st store.Store, blobs messaging.BlobDir, w io.Writer, slug, tool string, now time.Time) (Result, error) {
	var res Result
	a, err := st.GetAccountBySlug(ctx, slug)
	if err != nil {
		return res, refuse("no identity called %q is on this node", slug)
	}
	if !a.HasRoot() {
		return res, refuse("%s has never been issued a certificate, so it has no root for an export to name as its owner", slug)
	}
	in := pactidentity.ExportInput{Owner: a.RootFingerprint, OwnerName: a.DisplayName, Tool: tool, ExportedAt: now,
		Contacts: []pactidentity.ContactRow{}, Threads: []pactidentity.ThreadRow{}, Messages: []pactidentity.MessageRow{}, Media: []pactidentity.ExportMedia{}}

	held, err := st.ListContacts(ctx, a.ID)
	if err != nil {
		return res, fmt.Errorf("export: %w", err)
	}
	carried, requested := map[string]bool{}, map[string]bool{}
	for _, c := range held {
		if aRequest(c) {
			requested[c.Fingerprint] = true
			res.LeftOut = append(res.LeftOut, "a request from "+c.Fingerprint+" that was never accepted")
			continue
		}
		carried[c.Fingerprint] = true
		in.Contacts = append(in.Contacts, contactRow(c))
	}

	threads, err := st.ListThreadsByAccount(ctx, a.ID)
	if err != nil {
		return res, fmt.Errorf("export: %w", err)
	}
	sort.SliceStable(threads, func(i, j int) bool { return threads[i].CreatedAt < threads[j].CreatedAt })
	sizes := map[string]int64{}
	for _, t := range threads {
		msgs, err := st.ListMessagesByThread(ctx, a.ID, t.ID)
		if err != nil {
			return res, fmt.Errorf("export: %w", err)
		}
		if !carried[t.ContactFpr] {
			// Why, truly: the stranger's request was never accepted, or the contact was removed and
			// its conversation outlived it (a removal deletes the contact's row, not its thread).
			why := "whose request was never accepted"
			if !requested[t.ContactFpr] {
				why = "a contact removed from this identity"
			}
			res.LeftOut = append(res.LeftOut, fmt.Sprintf("a conversation of %d message(s) with %s, %s", len(msgs), t.ContactFpr, why))
			continue
		}
		in.Threads = append(in.Threads, pactidentity.ThreadRow{ID: t.ID, Contact: t.ContactFpr, Topic: t.Topic, CreatedAt: rfc3339(t.CreatedAt), LastAt: rfc3339(t.LastAt)})
		for _, m := range msgs {
			row, hash, err := messageRow(m)
			if err != nil {
				return res, err
			}
			if hash != "" {
				if _, seen := sizes[hash]; !seen {
					// The size is the file's, read from the file: a file this node says it holds
					// and does not is refused by name, not left out.
					data, gerr := blobs.Get(hash)
					if gerr != nil {
						return res, refuse("message %s names file %s, which this node no longer holds", m.ID, hash)
					}
					sizes[hash] = int64(len(data))
					in.Media = append(in.Media, pactidentity.ExportMedia{Hash: hash, Size: int64(len(data))})
				}
			}
			if hash != "" {
				row.Attachments[0].Size = sizes[hash]
			}
			in.Messages = append(in.Messages, row)
		}
	}
	sort.Slice(in.Media, func(i, j int) bool { return in.Media[i].Hash < in.Media[j].Hash })
	// The writer leaves out what the file must never carry and a contact could put there — a
	// message whose body or file reads as a private key, with its file — and lists each one; it
	// nulls a reply_to whose message the file does not carry (SPEC §9.2, pact-identity 0.3.3). Every
	// message left out is named to the person, with the writer's reason (SPEC §9.2 #25).
	leftOut, err := pactidentity.WriteExportZip(w, in, func(hash string) (io.ReadCloser, error) {
		data, err := blobs.Get(hash)
		if err != nil {
			return nil, refuse("file %s went from this node while it was being exported", hash)
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	if err != nil {
		return res, refuse("%v", err)
	}
	gone := map[string]bool{}
	for _, l := range leftOut {
		gone[l.ID] = true
		res.LeftOutMessages = append(res.LeftOutMessages, l.ID)
		res.LeftOut = append(res.LeftOut, fmt.Sprintf("message %s: %s", l.ID, l.Reason))
	}
	files := map[string]bool{}
	for _, m := range in.Messages {
		if gone[m.ID] {
			continue
		}
		res.Messages++
		for _, a := range m.Attachments {
			files[a.File] = true
		}
	}
	res.Contacts, res.Threads, res.Media = len(in.Contacts), len(in.Threads), len(files)
	return res, nil
}

// contactRow is a held contact as contacts.csv carries it. What the format leaves out (PACT §9.2):
// the preset (permissions carries the set), the trust flag (the node's integrations', not PACT's),
// the card (the next exchange refreshes it) and the SPKI (it is the leaf's).
func contactRow(c store.Contact) pactidentity.ContactRow {
	return pactidentity.ContactRow{
		Root: c.Fingerprint, Endpoint: c.Endpoint, Name: c.Petname, DisplayName: c.DisplayName,
		Status: c.Status, WasActive: c.EverActive || c.Status == "active",
		Permissions: orEmpty(c.Permissions), TheirPermissions: orEmpty(c.TheirPermissions),
		Leaf: b64OrNil(c.Leaf), RootCert: b64OrNil(c.RootCert), Added: rfc3339(c.CreatedAt),
	}
}

// messageRow is a stored message as messages.jsonl carries it, and the file it names, if any.
//
// A media message keeps its file's description as JSON in the body (messaging.MediaMeta); the
// export lifts it into `attachments` and the body is empty, as the format has it for a message
// that carries a file. A link the node never fetched has no file to carry, so the link travels as
// the body.
func messageRow(m store.Message) (pactidentity.MessageRow, string, error) {
	row := pactidentity.MessageRow{
		ID: m.ID, Thread: m.ThreadID, Contact: m.ContactFpr, MsgID: m.MsgID, Direction: m.Direction,
		Sender: m.Sender, Time: rfc3339(m.CreatedAt), Body: m.Body, Status: exportStatus(m.Status),
		Attachments: []pactidentity.Attachment{},
	}
	if m.ReplyTo != "" {
		r := m.ReplyTo
		row.ReplyTo = &r
	}
	if m.Kind != "media" {
		return row, "", nil
	}
	var meta messaging.MediaMeta
	if err := json.Unmarshal([]byte(m.Body), &meta); err != nil {
		return row, "", refuse("message %s is a media message whose description does not read", m.ID)
	}
	if meta.Hash == "" {
		row.Body = meta.URL
		return row, "", nil
	}
	row.Body = ""
	row.Attachments = []pactidentity.Attachment{{File: meta.Hash, Filename: meta.Filename, MIME: meta.Mime, Size: meta.Size}}
	return row, meta.Hash, nil
}

// exportStatus maps the node's delivery states onto the format's (PACT §9.2). An outbound message
// still pending is queued, and an importer does not send it. An inbound message still waiting for
// its human (queued_for_human, which nothing writes any more; rows from before remain) is queued
// too, as the cloud's exporter writes it: one mapping for both hosts (building rule 1).
func exportStatus(s string) string {
	switch s {
	case "pending", "queued_for_human":
		return "queued"
	case "failed":
		return "failed"
	default: // delivered
		return "delivered"
	}
}

func rfc3339(unix int64) string { return time.Unix(unix, 0).UTC().Format(time.RFC3339) }

func b64OrNil(b []byte) *string {
	if len(b) == 0 {
		return nil
	}
	s := pactidentity.B64url(b)
	return &s
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
