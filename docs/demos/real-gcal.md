# Demo: a contact books a real Google Calendar slot

The P3 exit demo end to end: an owner connects a Google Calendar MCP server to
their node, exposes `check_availability` + `book_slot` in **mapped** mode through a
shipped recipe, and a contact's agent books a slot — receiving a `booking_id` and an
ICS, never raw free/busy (SPEC §6.7, PACT §6.2/§12).

The automated version of this path runs in `make check` against an in-test fake
(`internal/integrationtest/calendar_test.go`). This document is the manual run
against a **real** calendar.

**Verification status:** commands below were drafted 2026-08-24 and are verified
against the in-test fake only. The real-Google run needs the owner's Google OAuth
Desktop-app credentials and has **not yet been executed** — record the run date here
when it is: `Last manual run: —`.

## Prerequisites

- A running node: `docker compose up` (or `pact-gateway serve`), portal on
  `http://127.0.0.1:8080`, one account created (`pact-gateway account create --slug me --name "Your Name"` — both flags are required).
- One of the three verified servers. This walkthrough uses
  **nspady/google-calendar-mcp** (`@cocal/google-calendar-mcp`), which runs as a
  supervised stdio child and therefore needs the **`-full`** image (ships `node`/`npx`)
  or a host-mounted Node.
- Google Cloud project with the Calendar API enabled and an OAuth **Desktop app**
  client; download its credentials JSON. Use the **narrowest scope that works**:
  free/busy + events for booking. Prefer a dedicated calendar/account (SPEC §6.9).

## 1. Add the integration

Portal → *Integrations* → **Add**:

| Field | Value |
|---|---|
| slug | `gcal` |
| transport | `stdio-supervised` |
| command | `npx -y @cocal/google-calendar-mcp` |
| auth | `static` (the child receives the credentials path via its env allow-list) |

Environment allow-list for the child (portal → Integrations → the integration): only
`GOOGLE_OAUTH_CREDENTIALS=/data/gcal-credentials.json` and `PATH`. Nothing else from the
node's environment reaches the child (SPEC §6.2). Resource caps stay at the defaults
(512 MiB, Linux-enforced).

Click **Connect**. The child starts under the supervisor; on its first run it opens the
Google consent flow in a browser (the server's own OAuth, on the owner's machine). Status
moves to `ok` and catalog **v1** is taken automatically.

## 2. Expose the two capabilities

Portal → the integration → **Exposure**:

- `get-freebusy` → mode **mapped**, recipe `nspady`, exposed name `check_availability`
- `create-event` → mode **mapped**, recipe `nspady`, exposed name `book_slot`

`create-event` is flagged write-capable; tick the acknowledgment (it is audited with the
tool names) and **Publish**. Do **not** expose `list-events`, `update-event` or
`delete-event` — the use-case does not need them.

## 3. Grant a contact the PACT core permissions

Mapped capabilities are authorized by PACT §8 core permissions, not by
`integration.gcal` (SPEC §6.6). Portal → *Contacts* → the contact → switchboard:
enable `calendar.availability` and `calendar.book`.

## 4. The contact's agent books

From the contact's node (or any MCP client presenting that contact's client cert):

```
tools/call check_availability {"window_start":"2026-08-25T00:00:00Z","window_end":"2026-08-26T00:00:00Z","duration_minutes":30}
→ {"slots":[{"start":"2026-08-25T09:00:00Z","end":"2026-08-25T09:30:00Z"}, … ≤5 …]}

tools/call book_slot {"msg_id":"b-1","start":"2026-08-25T09:00:00Z","end":"2026-08-25T09:30:00Z","subject":"Tea"}
→ {"booking_id":"bk_…","ics":"BEGIN:VCALENDAR…"}
```

Replaying `book_slot` with the same `msg_id` returns the identical acknowledgment
without creating a second event (§11.2 idempotency). The event appears in the owner's
Google Calendar; the ICS the contact received is synthesized by the node from the
confirmed slot, not taken from Google.

## 5. Verify and audit

- Portal → *Audit*: `exposure_ack`, `exposure_publish`, `catalog_snapshot`,
  `integration_connect`, and the booking's `tools/call` rows.
- `pact-gateway audit verify` — chain intact.
- Change the tool description upstream (or update the npm package) and hit **Refresh
  catalog**: the changed entry turns **STALE**, is withheld from the contact's
  `tools/list`, and offers one-click **Reconfirm** (SPEC §6.5).

## Other verified servers

| Server | Notes |
|---|---|
| Google official (`calendarmcp.googleapis.com/mcp/v1`, preview) | recipe `google-official`; `suggest_time` already returns candidates. ⚠️ `create_event` write scope **unverified** — confirm before enabling booking (the recipe carries the caveat). |
| workspace-mcp (`taylorwilsdon/google_workspace_mcp`) | recipe `workspace-mcp`; `manage_event` with `action=create`/`delete` constants. |
