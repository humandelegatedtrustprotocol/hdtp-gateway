package portable

import (
	"archive/zip"
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"

	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// CheckWritten reads a file this node has just written back as an importer would: hdtpidentity's
// ReadExportZip, under the identity's own root. A file every importer refuses is not an export, and
// the writer must not report one: `export` removes it and says why (SPEC §3.10).
func CheckWritten(zr *zip.Reader, owner string, now time.Time) error {
	if _, err := hdtpidentity.ReadExportZip(zr, owner, now, ImportCeiling); err != nil {
		return refuse("the file written does not read back as an export, so it was not kept: %v", err)
	}
	return nil
}

// BatonDeck's import ceilings (batondeck gateway/src/router/limits.ts: IMPORT_CEILING,
// IMPORT_LIMITS and DIRECTORY_LIMITS): what its one upload route takes back in. They are the
// cloud's, not the format's — another host may take more — so an export over them is written and
// warned about, never refused (HDTP §9.2, Ceilings: a host's own import ceilings never refuse an export).
// Each value is written as the cloud writes it, a literal, so batondeck's check-node-claims can
// hold the two lists to each other.
const (
	cloudZipBytes         = 95 * 1024 * 1024
	cloudContacts         = 5_000
	cloudContactsCSVBytes = 4 * 1024 * 1024
	cloudThreads          = 20_000
	cloudThreadsCSVBytes  = 4 * 1024 * 1024
	cloudMessageLines     = 150_000
	cloudIDCharacters     = 10_000_000
	cloudMediaBytes       = 95 * 1024 * 1024
	cloudMediaFiles       = 5_000
	// The cloud's central directory bounds, derived there from cloudMediaFiles: the files and the
	// five members that are not a file, each record at most 148 bytes (TestTheCloudsDirectoryBounds
	// holds the derivation). An export this node writes has at most those five other members and
	// records of at most 125 bytes (46, a name of at most 70, a 9-byte timestamp), so it is over
	// either bound only when it is over cloudMediaFiles, which is warned about: neither is warned
	// about again.
	cloudZipEntries     = 5_005
	cloudDirectoryBytes = 740_740
)

// mediaFile is the name of an export's media file: media/ and the sha256 of its bytes in hex, as
// the cloud matches it when it counts files.
var mediaFile = regexp.MustCompile(`^media/[0-9a-f]{64}$`)

// CloudCeilings names each of BatonDeck's import ceilings a written export is over, with the
// number and the limit; none when it is under all of them. The files' bytes are the sizes their
// directory entries state, as the cloud reads them; CheckWritten has already held each file to the
// format's own bound, so none is left out of the sum as the cloud leaves out an oversized one.
func CloudCeilings(zr *zip.Reader, zipBytes uint64) []string {
	var out []string
	over := func(what string, n, limit uint64) {
		if n > limit {
			out = append(out, fmt.Sprintf("%d %s, over BatonDeck's %d", n, what, limit))
		}
	}
	var files, fileBytes uint64
	for _, f := range zr.File {
		switch {
		case f.Name == "contacts.csv":
			over("bytes of contacts.csv", f.UncompressedSize64, cloudContactsCSVBytes)
			over("contacts", csvRows(f), cloudContacts)
		case f.Name == "threads.csv":
			over("bytes of threads.csv", f.UncompressedSize64, cloudThreadsCSVBytes)
			over("threads", csvRows(f), cloudThreads)
		case f.Name == "messages.jsonl":
			lines, ids := messageLines(f)
			over("message lines", lines, cloudMessageLines)
			over("characters of message ids (id, msg_id, reply_to)", ids, cloudIDCharacters)
		case mediaFile.MatchString(f.Name):
			files++
			fileBytes += f.UncompressedSize64
		}
	}
	over("files", files, cloudMediaFiles)
	over("bytes of files", fileBytes, cloudMediaBytes)
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
	sc.Buffer(make([]byte, 0, 64*1024), hdtpidentity.ExportLineMax+1)
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
