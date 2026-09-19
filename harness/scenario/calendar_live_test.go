package scenario

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/fabric"
)

// S4 — a contact books a real appointment in a real calendar.
//
// Everything about the calendar provider was tested against a fake upstream: a
// Caller func returning literals. What none of it touched was whether the chain
// an owner actually assembles works — a supervised stdio child, a third-party MCP
// server nobody here wrote, a CalDAV server, a recipe, an exposure, a permission
// — and whether a booking made through the PACT surface becomes an event another
// CalDAV client would see.
//
// It does now, but only after three product gaps this scenario found:
//
//	E15                 a recipe could not bind a tool returning plain text, and
//	                    create-event answers with the event uid and nothing else
//	$cfg.<name>         the mapping DSL had no way to carry a per-install value,
//	                    and every caldav-mcp tool needs a collection URL
//	stdio environment   StdioConfigFor had no production caller, so every child
//	                    ran with an empty environment and could not be configured
//
// The upstream is dominik1001/caldav-mcp, pinned, installed into the image at
// build time (`make harness-image-caldav`) rather than fetched by npx mid-test.
// The calendar is Radicale. Neither is a stand-in written here.
func TestContactBooksIntoRealCalDAV(t *testing.T) {
	requireLive(t)
	if _, err := dockerRun(context.Background(), "docker", "image", "inspect", caldavImage); err != nil {
		t.Skipf("%s not built — run `make harness-image-caldav`", caldavImage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	p, err := SetupPaired(ctx, "pactcal", Ports{Owner: "18092", Public: "18093"}, caldavImage)
	if p != nil {
		t.Cleanup(func() { p.Teardown(os.Getenv("PACT_HARNESS_ARTIFACTS")) })
	}
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	f, net := p.Fab, p.Net

	// --- a real CalDAV server, and a real collection on it ---
	cfgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfgDir, "config"), []byte(
		"[server]\nhosts = 0.0.0.0:5232\n[auth]\ntype = none\n"+
			"[storage]\nfilesystem_folder = /data/collections\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rad, err := f.Container(ctx, fabric.Spec{
		Name: "radicale", Image: radicaleImage, Network: net,
		Volumes: []string{filepath.Join(cfgDir, "config") + ":/config/config:ro"},
	})
	if err != nil {
		t.Fatalf("starting radicale: %v", err)
	}
	const collection = "/owner/work/"
	if err := waitCalDAV(ctx, f, net.Name, rad.Name, collection, 90*time.Second); err != nil {
		out, _ := f.Raw(ctx, "docker", "logs", rad.Name)
		t.Fatalf("radicale never accepted a calendar: %v\n%s", err, shorten(string(out), 400))
	}

	// --- the integration, exactly as an owner configures one ---
	//
	// The child's environment and the recipe's per-install parameter share the
	// settings namespace and are deliberately separated inside it: `env.` reaches
	// the child's environment, everything else reaches the recipe as `$cfg.<name>`.
	// A credential that became a recipe parameter would be built into an upstream
	// tool argument and logged as one.
	for k, v := range map[string]string{
		"integration.cal.env.CALDAV_BASE_URL": "http://" + rad.Name + ":5232",
		"integration.cal.env.CALDAV_USERNAME": "owner",
		"integration.cal.env.CALDAV_PASSWORD": "harness-pw",
		"integration.cal.calendar_url":        collection,
	} {
		if err := p.Portal.PostForm(ctx, "/settings/adapter", "",
			map[string]string{"key": k, "value": v}); err != nil {
			t.Fatalf("storing %s: %v", k, err)
		}
	}
	if err := p.Portal.PostForm(ctx, "/integrations/create", p.AccountID,
		map[string]string{
			"slug": "cal", "transport": "stdio-supervised",
			"command": "caldav-mcp", "auth_kind": "none",
		}); err != nil {
		t.Fatalf("creating the integration: %v", err)
	}
	id, err := integrationID(ctx, p, "cal")
	if err != nil {
		t.Fatal(err)
	}

	// Connecting spawns the child. If the environment did not reach it, this is
	// where it dies — caldav-mcp has no other input.
	if err := p.Portal.PostForm(ctx, "/integrations/"+id+"/connect", p.AccountID, nil); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := waitIntegration(ctx, p, "cal", "ok", 3*time.Minute); err != nil {
		out, _ := f.Raw(ctx, "docker", "logs", p.Node.Name)
		t.Fatalf("the supervised child never became healthy: %v\n%s", err, shorten(string(out), 800))
	}

	// --- expose two tools, MAPPED onto the shipped caldav recipe ---
	//
	// `ack` is mandatory: create-event is write-capable, and SPEC §6.9 requires a
	// recorded acknowledgment before a write tool reaches a contact.
	if err := p.Portal.PostForm(ctx, "/integrations/"+id+"/exposure", p.AccountID,
		map[string]string{
			// A mapped entry must NAME the PACT capability it implements; the
			// upstream tool name is not itself a capability.
			"expose_list-events": "on", "mode_list-events": "mapped",
			"recipe_list-events": "caldav", "name_list-events": "check_availability",
			"expose_create-event": "on", "mode_create-event": "mapped",
			"recipe_create-event": "caldav", "name_create-event": "book_slot",
			"ack": "on",
		}); err != nil {
		t.Fatalf("publishing the exposure: %v", err)
	}
	if _, err := p.Owner.Call(ctx, "set_permissions", map[string]any{
		"account_id": p.AccountID, "contact_fpr": p.Contact.Fingerprint(),
		"permissions": []string{"calendar.availability", "calendar.book"},
	}); err != nil {
		t.Fatalf("granting the calendar permissions: %v", err)
	}

	// --- what the contact sees ---
	//
	// Listed first: the switchboard filters tools/list per caller (SPEC §5.4), so
	// this is also the proof that the exposure and the permission both landed.
	tools, err := p.Contact.ListTools(ctx, p.Target)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	t.Logf("the contact is offered: %v", tools)
	for _, want := range []string{"check_availability", "book_slot"} {
		if !containsStr(tools, want) {
			t.Fatalf("%s is not offered to the contact; the exposure or the permission "+
				"did not take: %v", want, tools)
		}
	}

	start, end := nextWorkdayWindow()
	availRaw, err := p.Contact.Call(ctx, p.Target, "check_availability", map[string]any{
		"window": map[string]any{
			"from": start.Format(time.RFC3339),
			"to":   end.Format(time.RFC3339),
			"tz":   "UTC",
		},
		"duration_min": 30,
	}, "avail-1")
	if err != nil {
		t.Fatalf("check_availability: %v", err)
	}
	var avail struct {
		Slots []struct{ Start, End string } `json:"slots"`
	}
	if err := json.Unmarshal([]byte(availRaw), &avail); err != nil {
		t.Fatalf("availability is not the documented shape: %v (%s)", err, shorten(availRaw, 300))
	}
	if len(avail.Slots) == 0 {
		t.Fatalf("an empty calendar offered no slots at all: %s", shorten(availRaw, 400))
	}
	// SPEC §6.7 and PACT §6.2: at most five, and never the raw free/busy. The
	// upstream returns whole events — summary, description, location — so a leak
	// here would publish the calendar's contents to a contact.
	if len(avail.Slots) > 5 {
		t.Errorf("availability returned %d slots; the cap is 5", len(avail.Slots))
	}
	for _, banned := range []string{"summary", "uid", "description", "location", "busy"} {
		if strings.Contains(strings.ToLower(availRaw), banned) {
			t.Errorf("availability leaked upstream event data (%q): %s", banned, shorten(availRaw, 400))
		}
	}

	chosen := avail.Slots[0]
	bookRaw, err := p.Contact.Call(ctx, p.Target, "book_slot", map[string]any{
		"msg_id":  "book-1",
		"slot":    map[string]any{"start": chosen.Start, "end": chosen.End, "tz": "UTC"},
		"subject": "Tea with Bob",
	}, "book-1")
	if err != nil {
		t.Fatalf("book_slot: %v", err)
	}
	var ack struct {
		BookingID string `json:"booking_id"`
		ICS       string `json:"ics"`
	}
	if err := json.Unmarshal([]byte(bookRaw), &ack); err != nil {
		t.Fatalf("booking ack is not the documented shape: %v (%s)", err, shorten(bookRaw, 300))
	}
	// The upstream answers with a bare uid, not JSON. Before E15 this was an
	// error; an empty booking id here means that fix regressed.
	if ack.BookingID == "" {
		t.Error("no booking id: caldav-mcp answers create-event with a plain-text uid, " +
			"which a recipe could not bind at all before E15")
	}
	if !strings.Contains(ack.ICS, "BEGIN:VCALENDAR") {
		t.Errorf("the ack carried no ICS the contact could add to their own calendar: %s",
			shorten(ack.ICS, 200))
	}

	// --- and the event is REALLY there, seen by a plain CalDAV client ---
	body := caldavReport(ctx, f, net.Name, rad.Name, collection)
	if !strings.Contains(body, "Tea with Bob") {
		t.Fatalf("the booking never reached the calendar; another CalDAV client sees "+
			"nothing:\n%s", shorten(body, 700))
	}
	t.Logf("S4: %d policy-filtered slots offered, booked %s, and the event is in Radicale",
		len(avail.Slots), ack.BookingID)
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// nextWorkdayWindow is the next Monday–Friday 09:00–17:00 UTC after tomorrow.
// The default policy admits only workday business hours, so a window chosen
// without regard to the day would legitimately return nothing.
func nextWorkdayWindow() (time.Time, time.Time) {
	d := time.Now().UTC().AddDate(0, 0, 1)
	for d.Weekday() == time.Saturday || d.Weekday() == time.Sunday {
		d = d.AddDate(0, 0, 1)
	}
	start := time.Date(d.Year(), d.Month(), d.Day(), 9, 0, 0, 0, time.UTC)
	return start, start.Add(8 * time.Hour)
}

// integrationID finds an integration by slug through the owner MCP.
func integrationID(ctx context.Context, p *Paired, slug string) (string, error) {
	raw, err := p.Owner.Call(ctx, "list_integrations", map[string]any{"account_id": p.AccountID})
	if err != nil {
		return "", fmt.Errorf("list_integrations: %w", err)
	}
	var out []struct{ ID, Slug, Status string }
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return "", fmt.Errorf("list_integrations shape: %w (%s)", err, shorten(raw, 300))
	}
	for _, in := range out {
		if in.Slug == slug {
			return in.ID, nil
		}
	}
	return "", fmt.Errorf("no integration %q in %s", slug, shorten(raw, 300))
}

// waitIntegration polls until an integration reaches a status.
func waitIntegration(ctx context.Context, p *Paired, slug, want string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var last string
	for {
		raw, _ := p.Owner.Call(ctx, "list_integrations", map[string]any{"account_id": p.AccountID})
		var out []struct{ ID, Slug, Status string }
		_ = json.Unmarshal([]byte(raw), &out)
		for _, in := range out {
			if in.Slug == slug {
				last = in.Status
				if in.Status == want {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("status is %q, want %q", last, want)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// waitCalDAV creates the collection and waits until the server serves it.
func waitCalDAV(ctx context.Context, f *fabric.Fabric, network, host, collection string,
	budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var last string
	for {
		out, _ := f.Raw(ctx, "docker", "run", "--rm", "--network", network, curlImage,
			"-sS", "-m", "10", "-u", "owner:harness-pw", "-X", "MKCALENDAR",
			"-o", "/dev/null", "-w", "%{http_code}", "http://"+host+":5232"+collection)
		last = strings.TrimSpace(string(out))
		// 201 created it; 405 means it is already there from a previous attempt.
		if last == "201" || last == "405" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("MKCALENDAR answered %q", last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// caldavReport asks the CalDAV server for the collection's events, as any other
// client would. This is the assertion that the booking is real rather than
// something the node merely told us about.
func caldavReport(ctx context.Context, f *fabric.Fabric, network, host, collection string) string {
	const report = `<?xml version="1.0" encoding="utf-8" ?>` +
		`<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">` +
		`<D:prop><C:calendar-data/></D:prop>` +
		`<C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"/></C:comp-filter></C:filter>` +
		`</C:calendar-query>`
	out, _ := f.Raw(ctx, "docker", "run", "--rm", "--network", network, curlImage,
		"-sS", "-m", "20", "-u", "owner:harness-pw", "-X", "REPORT",
		"-H", "Depth: 1", "-H", "Content-Type: application/xml",
		"--data", report, "http://"+host+":5232"+collection)
	return string(out)
}
