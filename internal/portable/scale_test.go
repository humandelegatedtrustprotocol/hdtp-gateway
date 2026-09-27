package portable

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/testid"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// scaleExport is an export of one identity with `threads` threads spread over 100 contacts and
// one message in each, written by the library's own writer.
func scaleExport(t *testing.T, threads int) ([]byte, string) {
	t.Helper()
	owner := testid.NewWallet(t, "Scale")
	at := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	in := pactidentity.ExportInput{Owner: owner.Fpr, OwnerName: "Scale", Tool: "scale test", ExportedAt: at,
		Threads: []pactidentity.ThreadRow{}, Messages: []pactidentity.MessageRow{}, Media: []pactidentity.ExportMedia{}}
	var roots []string
	for i := 0; i < 100; i++ {
		root := testid.NewWallet(t, fmt.Sprintf("Contact %d", i)).Fpr
		roots = append(roots, root)
		in.Contacts = append(in.Contacts, pactidentity.ContactRow{Root: root, Endpoint: fmt.Sprintf("https://c%d.example/a/c/mcp", i),
			Status: "active", WasActive: true, Permissions: []string{"message.text"}, TheirPermissions: []string{}, Added: at.Format(time.RFC3339)})
	}
	stamp := at.Format(time.RFC3339)
	for i := 0; i < threads; i++ {
		id := "t" + strconv.Itoa(i)
		root := roots[i%len(roots)]
		in.Threads = append(in.Threads, pactidentity.ThreadRow{ID: id, Contact: root, Topic: "topic " + id, CreatedAt: stamp, LastAt: stamp})
		in.Messages = append(in.Messages, pactidentity.MessageRow{ID: "m" + id, Thread: id, Contact: root, MsgID: "msg-" + id, Direction: "in",
			Sender: "human", Time: stamp, Body: "hello " + id, Status: "delivered", Attachments: []pactidentity.Attachment{}})
	}
	var buf bytes.Buffer
	if _, err := pactidentity.WriteExportZip(&buf, in, nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), owner.Fpr
}

// importTook reads one generated export (the whole check, and the merge) and then applies it into
// a fresh SQLite store, and says how long each took.
func importTook(t *testing.T, threads int) (read, apply time.Duration) {
	t.Helper()
	file, _ := scaleExport(t, threads)
	e := newEnv(t, sqliteStore)
	started := time.Now()
	p, err := Read(context.Background(), e.st, zipReader(t, file), "scale", time.Now())
	read = time.Since(started)
	if err != nil {
		t.Fatalf("reading %d threads: %v", threads, err)
	}
	started = time.Now()
	res, err := p.Apply(context.Background(), e.st, e.blobs, time.Now())
	apply = time.Since(started)
	if err != nil {
		t.Fatalf("applying %d threads: %v", threads, err)
	}
	if res.Threads != threads || res.Messages != threads {
		t.Fatalf("imported %+v, want %d threads and messages", res, threads)
	}
	return read, apply
}

// An import's cost grows with the file, not with its square. It is timed in two parts: reading
// and checking the whole file (pact-identity's ReadExportZip, then export_merge), and writing it
// into the store. v0.3.0 read threads.csv in time quadratic in its rows: measured here on SQLite at
// 10,000 and 40,000 threads, reading took 10.8x and 17.7x as long for 4x the threads, while
// writing took 2.9x and 4.7x; an end-to-end ratio, diluted by the writes, measured anywhere from
// 5.3x to 9.9x on the same code and could not tell the two apart. With v0.3.1, on the same Mac:
// 12.5k -> 50k threads read in 0.16 s -> 0.66 s (4.1x) and wrote in 0.48 s -> 1.96 s (4.1x);
// 10k -> 40k read 3.9x and wrote 3.9x and 4.1x, over two runs.
//
// PACT_EXPORT_SCALE=<threads> imports a quarter of that and then all of it, logs both parts, and
// fails when either takes more than six times as long for four times the threads. `make scale` runs
// it at 40,000 and the pre-push hook runs `make scale`; it stays out of `make check`, whose parallel
// race-enabled packages make a wall-clock ratio say more about the machine than the code.
func TestAnImportGrowsLinearlyWithItsThreads(t *testing.T) {
	n, err := strconv.Atoi(os.Getenv("PACT_EXPORT_SCALE"))
	if err != nil || n < 400 {
		t.Skip("!! NOT MEASURED: set PACT_EXPORT_SCALE=<threads> (e.g. 50000) to time an import at that size")
	}
	qRead, qApply := importTook(t, n/4)
	read, apply := importTook(t, n)
	t.Logf("%d threads: read %v, write %v; %d threads: read %v, write %v; one message each, 100 contacts, SQLite",
		n/4, qRead, qApply, n, read, apply)
	for _, m := range []struct {
		what         string
		quarter, all time.Duration
	}{{"reading and checking", qRead, read}, {"writing", qApply, apply}} {
		ratio := float64(m.all) / float64(m.quarter)
		t.Logf("%s: %.1fx for 4x the threads", m.what, ratio)
		if ratio > 6 {
			t.Errorf("%s four times the threads took %.1f times as long: it is not linear", m.what, ratio)
		}
	}
}
