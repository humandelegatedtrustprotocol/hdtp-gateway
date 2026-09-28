package portable

import (
	"archive/zip"
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"time"

	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// CheckWritten reads a file this node has just written back as an importer would: pactidentity's
// ReadExportZip, under the identity's own root. A file every importer refuses is not an export, and
// the writer must not report one: `export` removes it and says why (SPEC §3.10).
func CheckWritten(zr *zip.Reader, owner string, now time.Time) error {
	if _, err := pactidentity.ReadExportZip(zr, owner, now, ImportCeiling); err != nil {
		return refuse("the file written does not read back as an export, so it was not kept: %v", err)
	}
	return nil
}

// PACT Cloud's import ceilings (pact-cloud gateway/src/router/limits.ts, IMPORT_CEILING and
// IMPORT_LIMITS): what its one upload route takes back in. They are the cloud's, not the format's —
// another host may take more — so an export over them is written and warned about, never refused
// (SPEC 2.2.1: a host's own import ceilings never refuse an export).
const (
	cloudContacts         = 5_000
	cloudContactsCSVBytes = 2 * 1024 * 1024
	cloudThreads          = 5_000
	cloudThreadsCSVBytes  = 1024 * 1024
	cloudMessageLines     = 40_000
	cloudIDCharacters     = 2_400_000
	cloudZipBytes         = 64 * 1024 * 1024
)

// CloudCeilings names each of PACT Cloud's import ceilings a written export is over, with the
// number and the limit; none when it is under all of them.
func CloudCeilings(zr *zip.Reader, zipBytes uint64) []string {
	var out []string
	over := func(what string, n, limit uint64) {
		if n > limit {
			out = append(out, fmt.Sprintf("%d %s, over PACT Cloud's %d", n, what, limit))
		}
	}
	for _, f := range zr.File {
		switch f.Name {
		case "contacts.csv":
			over("bytes of contacts.csv", f.UncompressedSize64, cloudContactsCSVBytes)
			over("contacts", csvRows(f), cloudContacts)
		case "threads.csv":
			over("bytes of threads.csv", f.UncompressedSize64, cloudThreadsCSVBytes)
			over("threads", csvRows(f), cloudThreads)
		case "messages.jsonl":
			lines, ids := messageLines(f)
			over("message lines", lines, cloudMessageLines)
			over("characters of message ids (id, msg_id, reply_to)", ids, cloudIDCharacters)
		}
	}
	over("bytes of zip", zipBytes, cloudZipBytes)
	return out
}

// csvRows counts a CSV member's records after its header.
func csvRows(f *zip.File) uint64 {
	rc, err := f.Open()
	if err != nil {
		return 0
	}
	defer rc.Close()
	r := csv.NewReader(rc)
	r.FieldsPerRecord = -1
	var n uint64
	for {
		if _, err := r.Read(); err == io.EOF {
			break
		} else if err != nil {
			break
		}
		n++
	}
	if n > 0 {
		n-- // the header
	}
	return n
}

// messageLines counts messages.jsonl's lines and the characters of the ids they carry.
func messageLines(f *zip.File) (lines, ids uint64) {
	rc, err := f.Open()
	if err != nil {
		return 0, 0
	}
	defer rc.Close()
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 64*1024), pactidentity.ExportLineMax+1)
	for sc.Scan() {
		lines++
		var m struct {
			ID      string  `json:"id"`
			MsgID   string  `json:"msg_id"`
			ReplyTo *string `json:"reply_to"`
		}
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			ids += runes(m.ID) + runes(m.MsgID)
			if m.ReplyTo != nil {
				ids += runes(*m.ReplyTo)
			}
		}
	}
	return lines, ids
}

// runes counts a string's characters, as the cloud's limit counts them.
func runes(s string) (n uint64) {
	for range s {
		n++
	}
	return n
}
