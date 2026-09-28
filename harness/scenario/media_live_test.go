package scenario

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/harness/fabric"
	"github.com/pact-cloud/pact-gateway/harness/images"
	"github.com/pact-cloud/pact-gateway/harness/registry"
)

// S3 — messaging and media, and the guard on the one request a contact can make the node send.
//
// A contact's `send_media` carries its bytes inline or names a URL. Inline bytes are stored under
// their hash and served to the owner as a download. A URL is recorded and NEVER fetched on
// arrival (SPEC §7.5): the owner fetches it deliberately, and the fetch is refused an address in
// the §7.5 ranges and refused a redirect, because a contact who controls the URL would otherwise
// steer the node into its owner's home network.
//
// The hosts a URL can name sit on a ROUTABLE network (198.18.0.0/15, fabric.NetOpts.Routable), so
// the guard judges them as it would a host on the internet: on a default Docker network every
// address is RFC 1918 and every fetch would be refused at the first hop, which proves nothing
// about redirects. The node is also on `home`, an ordinary private network, where a canary
// listens: nothing in this scenario may ever reach it. Every stub logs each request line, so
// "not fetched" is a count of zero on a listener that is shown to count.
func TestMessagingAndMediaUnderTheFetchGuard(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S3", Name: "messaging and media: inline and url media, and an owner's fetch refused a private address and a redirect", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome},
		Timeout: 12 * time.Minute,
	})
	pub, err := w.Fab.Network(ctx, "pub", fabric.NetOpts{Routable: true})
	if err != nil {
		t.Fatal(err)
	}
	home, err := w.Fab.Network(ctx, "home", fabric.NetOpts{})
	if err != nil {
		t.Fatal(err)
	}
	alice, err := w.Node(ctx, NodeOpts{
		Slug: "alice", Net: pub, PublishPublic: true,
		Env: map[string]string{"PACT_SEAL": "optional"},
	})
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	if err := w.Fab.Connect(ctx, alice.Node, home); err != nil {
		t.Fatal(err)
	}
	bob, target, err := w.Contact(ctx, alice)
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	fileBody := "PACT-S3-FILE " + w.Fab.Prefix()
	files, filesIP := stubHTTP(ctx, t, w, "files", pub, okResponse(fileBody))
	canary, canaryIP := stubHTTP(ctx, t, w, "canary", home, okResponse("PACT-S3-CANARY"))
	redirector, redirIP := stubHTTP(ctx, t, w, "redirector", pub,
		"HTTP/1.1 302 Found\r\nLocation: http://"+canaryIP+"/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	for _, a := range []struct{ name, ip string }{{"files", filesIP}, {"redirector", redirIP}} {
		if ip := net.ParseIP(a.ip); ip == nil || ip.IsPrivate() || ip.IsLoopback() {
			t.Fatalf("%s is at %s, which the guard would refuse at the first hop: the network is not routable", a.name, a.ip)
		}
	}
	if ip := net.ParseIP(canaryIP); ip == nil || !ip.IsPrivate() {
		t.Fatalf("the canary is at %s, which is not a private address", canaryIP)
	}

	fetch := func(t *testing.T, url string) (hash, refusal string) {
		t.Helper()
		r, err := alice.Portal.Post(ctx, "/media/fetch", alice.AccountID, map[string]string{"url": url})
		if err != nil {
			t.Fatalf("POST /media/fetch: %v", err)
		}
		var out struct{ Hash, Error string }
		if err := json.Unmarshal([]byte(r.Body), &out); err != nil {
			t.Fatalf("POST /media/fetch answered %d, not JSON: %s", r.Code, shorten(r.Body, 200))
		}
		return out.Hash, out.Error
	}
	download := func(t *testing.T, hash, want string) {
		t.Helper()
		r, err := alice.Portal.Read(ctx, "/media/"+hash+"?account="+alice.AccountID)
		if err != nil {
			t.Fatal(err)
		}
		if r.Code != 200 || r.Body != want {
			t.Fatalf("GET /media/%s answered %d with %q, want 200 with the %d bytes that were sent", hash[:12], r.Code, shorten(r.Body, 80), len(want))
		}
		// A contact's file never chooses how the portal's own origin treats it.
		if ct, cd := r.Header.Get("Content-Type"), r.Header.Get("Content-Disposition"); ct != "application/octet-stream" || !strings.HasPrefix(cd, "attachment") {
			t.Errorf("the download is served as %q, %q; want application/octet-stream as an attachment", ct, cd)
		}
	}
	// Every message a contact sends without a thread_id opens a thread of its own, so what the
	// owner holds from bob is every thread, read.
	threads := func(t *testing.T) string {
		t.Helper()
		raw, err := alice.Owner.Call(ctx, "get_inbox", map[string]any{"account_id": alice.AccountID})
		if err != nil {
			t.Fatalf("get_inbox: %v", err)
		}
		var list []struct {
			ThreadID   string `json:"thread_id"`
			ContactFpr string `json:"contact_fpr"`
		}
		if err := json.Unmarshal([]byte(raw), &list); err != nil || len(list) == 0 {
			t.Fatalf("want bob's threads, got %s (%v)", shorten(raw, 200), err)
		}
		var all strings.Builder
		for _, th := range list {
			if th.ContactFpr != bob.Fingerprint() {
				t.Fatalf("a thread from %s, who is not bob", th.ContactFpr)
			}
			body, err := alice.Owner.Call(ctx, "read_thread", map[string]any{"account_id": alice.AccountID, "thread_id": th.ThreadID})
			if err != nil {
				t.Fatalf("read_thread: %v", err)
			}
			all.WriteString(body)
		}
		return all.String()
	}

	t.Run("a message and inline media reach the owner, and the media downloads as sent", func(t *testing.T) {
		if _, err := bob.Call(ctx, target, "send_message", map[string]any{
			"text": "media follows " + PlaintextCanary, "sender": "agent", "msg_id": "s3-text",
		}, "s3-text"); err != nil {
			t.Fatalf("send_message: %v", err)
		}
		inline := "PACT-S3-INLINE " + w.Fab.Prefix() + " \x00\x01\x02 bytes, not text"
		if _, err := bob.Call(ctx, target, "send_media", map[string]any{
			"filename": "note.bin", "mime": "text/html", "sender": "agent", "msg_id": "s3-inline",
			"data": base64.StdEncoding.EncodeToString([]byte(inline)),
		}, "s3-inline"); err != nil {
			t.Fatalf("send_media inline: %v", err)
		}
		sum := sha256.Sum256([]byte(inline))
		hash := hex.EncodeToString(sum[:])
		body := threads(t)
		if !strings.Contains(body, PlaintextCanary) || !strings.Contains(body, hash) {
			t.Fatalf("the thread lacks the message or the media's hash %s: %s", hash[:12], shorten(body, 400))
		}
		// Sent as text/html: served as an octet-stream attachment all the same.
		download(t, hash, inline)
	})

	t.Run("url media is recorded and not fetched, until the owner fetches it", func(t *testing.T) {
		url := "http://" + filesIP + "/sent-by-bob"
		if _, err := bob.Call(ctx, target, "send_media", map[string]any{
			"filename": "remote.bin", "mime": "application/octet-stream", "sender": "agent", "msg_id": "s3-url", "url": url,
		}, "s3-url"); err != nil {
			t.Fatalf("send_media url: %v", err)
		}
		if body := threads(t); !strings.Contains(body, url) {
			t.Fatalf("the thread does not carry the url: %s", shorten(body, 400))
		}
		// An absence cannot be polled for, only given time: a margin in which a fetch on arrival
		// would have happened.
		time.Sleep(5 * time.Second)
		if n := hits(ctx, t, w, files, "/sent-by-bob"); n != 0 {
			t.Fatalf("the node fetched a contact's url on arrival (%d request(s)); SPEC §7.5 says never", n)
		}
		// The control: the owner's fetch of the same url gets through, and the listener counts it.
		hash, refusal := fetch(t, url)
		if refusal != "" {
			t.Fatalf("the owner's fetch of a routable url was refused: %s", refusal)
		}
		if n := hits(ctx, t, w, files, "/sent-by-bob"); n != 1 {
			t.Fatalf("the owner's fetch reached the host %d time(s), want 1", n)
		}
		if sum := sha256.Sum256([]byte(fileBody)); hash != hex.EncodeToString(sum[:]) {
			t.Fatalf("the fetch stored %s, not the hash of what the host served", hash)
		}
		download(t, hash, fileBody)
	})

	t.Run("a fetch of a private address is refused before it is sent, and audited", func(t *testing.T) {
		before := countAudit(ctx, t, alice, "media_fetch_refused")
		_, refusal := fetch(t, "http://"+canaryIP+"/direct")
		if !strings.Contains(refusal, "private address") {
			t.Errorf("a fetch of %s answered %q, want a refusal naming the private address", canaryIP, refusal)
		}
		if n := hits(ctx, t, w, canary, "/direct"); n != 0 {
			t.Errorf("the canary on the home network was reached %d time(s)", n)
		}
		if after := countAudit(ctx, t, alice, "media_fetch_refused"); after != before+1 {
			t.Errorf("media_fetch_refused rows went %d -> %d, want one more", before, after)
		}
	})

	// The same guard reached two other ways: a NAME that resolves to the private address (the
	// canary's container name, which the node's resolver answers on the home network — the
	// rebinding shape, a name that looks like anybody's), and the address written as an
	// IPv4-mapped IPv6 literal. Each is refused before anything is sent, and audited.
	for _, c := range []struct{ how, url, path string }{
		{"a name that resolves to it", "http://" + canary.Name + "/named", "/named"},
		{"its IPv4-mapped IPv6 form", "http://[::ffff:" + canaryIP + "]/mapped", "/mapped"},
	} {
		t.Run("the private address by "+c.how+" is refused too", func(t *testing.T) {
			before := countAudit(ctx, t, alice, "media_fetch_refused")
			_, refusal := fetch(t, c.url)
			if !strings.Contains(refusal, "private address") {
				t.Errorf("a fetch of %s answered %q, want a refusal naming the private address", c.url, refusal)
			}
			if n := hits(ctx, t, w, canary, c.path); n != 0 {
				t.Errorf("the canary was reached %d time(s) through %s", n, c.url)
			}
			if after := countAudit(ctx, t, alice, "media_fetch_refused"); after != before+1 {
				t.Errorf("media_fetch_refused rows went %d -> %d, want one more", before, after)
			}
		})
	}

	t.Run("a redirect is refused, and its target is never reached", func(t *testing.T) {
		_, refusal := fetch(t, "http://"+redirIP+"/hop")
		n := hits(ctx, t, w, redirector, "/hop")
		if n == 0 {
			t.Fatalf("UNREACHED: the redirector never saw the fetch (%q), so this says nothing about redirects", refusal)
		}
		if n != 1 || !strings.Contains(refusal, "redirects refused") {
			t.Errorf("the redirector was asked %d time(s) and the fetch answered %q; want 1 and a refused redirect", n, refusal)
		}
		if n := hits(ctx, t, w, canary, "/stolen"); n != 0 {
			t.Errorf("the redirect's private target was reached %d time(s)", n)
		}
	})
}

// okResponse is a 200 carrying body.
func okResponse(body string) string {
	return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

// stubHTTP starts a host that answers every request with response and logs each request line to
// its log as `REQ <line>`, and returns it and its address on net. busybox nc runs the handler per
// connection; the handler reads the headers out before answering, so a client is not reset.
func stubHTTP(ctx context.Context, t *testing.T, w *World, name string, n *fabric.Network, response string) (*fabric.Container, string) {
	t.Helper()
	const handler = "#!/bin/sh\n" +
		"read -r line\n" +
		"echo \"REQ $line\" >&2\n" +
		"while read -r h; do case \"$h\" in \"$(printf '\\r')\"|'') break;; esac; done\n" +
		"cat /response\n"
	c, err := w.Fab.Container(ctx, fabric.Spec{
		Name: name, Image: images.Alpine, Network: n,
		Env: map[string]string{
			"HANDLER":  base64.StdEncoding.EncodeToString([]byte(handler)),
			"RESPONSE": base64.StdEncoding.EncodeToString([]byte(response)),
		},
		Cmd: []string{"sh", "-c", `echo "$HANDLER" | base64 -d > /h.sh && chmod +x /h.sh && ` +
			`echo "$RESPONSE" | base64 -d > /response && exec nc -lk -p 80 -e /h.sh`},
	})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	// Listening, read from the kernel's own table rather than by connecting, which would log.
	deadline := time.Now().Add(30 * time.Second)
	for {
		// busybox nc listens dual-stack, so the socket is in tcp6.
		out, _ := w.Fab.Exec(ctx, c, "cat", "/proc/net/tcp", "/proc/net/tcp6")
		if listening.Match(out) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never listened on :80", name)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
	ip, err := w.Fab.IPOn(ctx, c, n)
	if err != nil {
		t.Fatal(err)
	}
	return c, ip
}

// listening matches a socket on port 80 (0x0050) in state LISTEN (0A), in either table.
var listening = regexp.MustCompile(`:0050 0+:0000 0A`)

// hits counts the GETs of path a stub has logged.
func hits(ctx context.Context, t *testing.T, w *World, c *fabric.Container, path string) int {
	t.Helper()
	out, err := w.Fab.Raw(ctx, "docker", "logs", c.Name)
	if err != nil {
		t.Fatalf("docker logs %s: %v", c.Name, err)
	}
	return strings.Count(string(out), "REQ GET "+path+" ")
}
