// Webhooks: where this identity's events are posted, signed, once each. BatonDeck's portal page
// (portal/src/views/webhooks.tsx) moved onto the node's portal: its components, its session and its
// forms (docs/release/webhooks-2026-10-18.md, W3). The portal is the one door that registers an
// endpoint; the owner MCP and the CLI have none.
import { useCallback, useEffect, useState } from "react";
import { failureOf, getJSON, postForm } from "../api";
import { Breakable, UrlText } from "../glance";
import { Badge, Button, EmptyState, Failed, Field, HelpTip, List, ListRow, Menu, MenuItem, Notice, PageHeader, Readout, Section, Table, type Note } from "../ui";
import { whenTitle } from "../words";

type WebhookEndpoint = {
  id: string;
  url: string;
  events: string[];
  status: string;
  consecutive_failures: number;
  rotating_until: number | null;
  created_at: number;
  updated_at: number;
};

type Delivery = {
  id: string;
  event_type: string;
  status: string;
  http_status: number | null;
  latency_ms: number;
  response_excerpt: string | null;
  created_at: number;
};

/** A URL's host, or the URL as written when it is not one. */
function hostOf(url: string): string {
  try { return new URL(url).host; } catch { return url; }
}

/** What a refused post says: the node's sentence, or its status and code when it sent none. */
function refusalOf(r: { status: number; body: string }): string {
  try {
    const j = JSON.parse(r.body) as { error?: string; detail?: string };
    if (j.detail) return j.detail;
    if (j.error) return `The node answered ${r.status} (${j.error}).`;
  } catch { /* not the node's JSON: a refusal before the page, said by its status */ }
  return `The node answered ${r.status}.`;
}

/** A time the node stores in unix milliseconds, said with its day and clock. */
function at(ms: number): string {
  return new Date(ms).toLocaleString([], { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
}

export function Webhooks() {
  const [endpoints, setEndpoints] = useState<WebhookEndpoint[] | null>(null);
  const [events, setEvents] = useState<string[]>([]);
  const [err, setErr] = useState("");
  const [note, setNote] = useState<Note | null>(null);
  const [opening, setOpening] = useState(false);
  const [url, setUrl] = useState("");
  const [filter, setFilter] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  /** The signing secret, shown once. Cleared by the person, never by a reload. */
  const [secret, setSecret] = useState<{ value: string; url: string; rotated: boolean } | null>(null);
  /** Which endpoint's delivery log is open, and what is in it. */
  const [openLog, setOpenLog] = useState<string | null>(null);
  const [deliveries, setDeliveries] = useState<Delivery[] | null>(null);
  /** A refused log read is shown as the refusal, never as "Nothing delivered yet". */
  const [deliveriesErr, setDeliveriesErr] = useState("");

  const load = useCallback(() => {
    getJSON<{ endpoints: WebhookEndpoint[]; events: string[] }>("/api/webhooks")
      .then((d) => { setEndpoints(d.endpoints ?? []); setEvents(d.events ?? []); setErr(""); })
      .catch((e) => setErr(failureOf(e)));
  }, []);
  useEffect(() => { load(); }, [load]);

  const readLog = useCallback((id: string | null) => {
    setDeliveries(null);
    setDeliveriesErr("");
    if (!id) return;
    getJSON<{ deliveries: Delivery[] }>(`/api/webhooks/${encodeURIComponent(id)}/deliveries`)
      .then((d) => setDeliveries(d.deliveries ?? []))
      .catch((e) => setDeliveriesErr(failureOf(e)));
  }, []);
  useEffect(() => { readLog(openLog); }, [openLog, readLog]);

  /** One post; what it answered on success, null (and the refusal said) when it was refused. */
  const post = async <T,>(path: string, fields: Record<string, string>, fail: string): Promise<T | null> => {
    const r = await postForm(path, fields);
    if (!r.ok) {
      setNote({ kind: "err", text: `${fail} ${refusalOf(r)}` });
      return null;
    }
    try { return JSON.parse(r.body) as T; } catch { return null; }
  };

  const act = async (what: string, fail: string, path: string, fields: Record<string, string> = {}) => {
    setNote(null);
    if (await post(path, fields, fail) !== null) setNote({ kind: "ok", text: what });
    load();
  };

  const create = async () => {
    setBusy(true);
    setNote(null);
    // The secret comes back once, and this decides where the identity's events go from now on.
    const made = await post<{ endpoint: WebhookEndpoint; secret: string }>("/webhooks/create",
      { url: url.trim(), events: filter.join(",") }, "Could not register that endpoint.");
    if (made) {
      setSecret({ value: made.secret, url: made.endpoint.url, rotated: false });
      setOpening(false);
      setUrl("");
      setFilter([]);
      load();
    }
    setBusy(false);
  };

  const rotate = async (e: WebhookEndpoint) => {
    setNote(null);
    const r = await post<{ secret: string }>(`/webhooks/${encodeURIComponent(e.id)}/rotate`, {}, "Could not issue a new secret.");
    if (r) setSecret({ value: r.secret, url: e.url, rotated: true });
    load();
  };

  const header = <PageHeader title="Webhooks" />;
  if (endpoints === null) return <main>{header}{err ? <Failed what="the webhooks" error={err} retry={load} /> : <EmptyState loading />}</main>;

  return (
    <main>
      {header}
      {note && <Notice kind={note.kind}>{note.text}</Notice>}
      {secret && (
        <Notice kind="warn" title={secret.rotated ? "New signing secret — copy it now" : "Signing secret — copy it now"}>
          <p>
            This is the only time it is readable, for <code>{secret.url}</code>. Verify
            the <code>X-HDTP-Signature</code> header with it:
            {" "}<code>{"t=…,v1=HMAC-SHA256(secret, `${t}.${body}`)"}</code>, and reject
            anything whose <code>t</code> is more than five minutes old.
          </p>
          {secret.rotated && <p>The previous secret keeps working for 24 hours, so nothing breaks while you deploy this one.</p>}
          <Readout value={secret.value} copy block />
          <p><Button variant="secondary" onClick={() => setSecret(null)}>I have saved it</Button></p>
        </Notice>
      )}
      <Section title="Endpoints"
        description={<>This node posts this identity's events, signed, to your URL — ids and metadata only.<HelpTip label="About webhooks">
          Every delivery carries ids and metadata — never a message, media or a card — and is signed so you can
          prove it came from this node. An endpoint is sent what happens from the second it was added; an event from earlier in that same second can reach it too.
        </HelpTip></>}
        footer={!opening && !secret && <Button variant="secondary" onClick={() => setOpening(true)}>Add an endpoint</Button>}>
        {opening && (
          <div className="fields">
            <Field label="Where to post" help="An http or https URL."
              tip="Only you can add one, so a receiver on this host, in the same compose project or on your network is fine: plain http, a local name and an address are all taken.">
              <input type="url" value={url} autoFocus placeholder="https://hooks.example.com/hdtp"
                onChange={(e) => setUrl(e.target.value)} />
            </Field>
            <fieldset className="scope-picker">
              <legend>Which events {filter.length === 0 && <span className="muted">— none ticked means all of them</span>}</legend>
              {events.map((ev) => (
                <Field key={ev} check label={<code>{ev}</code>}>
                  <input type="checkbox" checked={filter.includes(ev)}
                    onChange={(e) => setFilter((cur) => e.target.checked ? [...cur, ev] : cur.filter((x) => x !== ev))} />
                </Field>
              ))}
            </fieldset>
            <p>
              <Button busy={busy} disabled={busy || url.trim() === ""} onClick={create}>Add endpoint</Button>{" "}
              <Button variant="quiet" onClick={() => { setOpening(false); setNote(null); }}>Cancel</Button>
            </p>
          </div>
        )}

        <List aria-label="Webhook endpoints" empty={<EmptyState title="No endpoints yet">Add one and this node will post this identity's events to it.</EmptyState>}>
          {endpoints.map((e) => (
            <ListRow key={e.id}
              title={<UrlText url={e.url} />}
              meta={<>
                <Badge status={e.status} />
                {e.rotating_until && <><Badge tone="warn">rotating</Badge> <span className="muted" title={whenTitle(e.rotating_until)}>old secret accepted until {at(e.rotating_until)}</span></>}
                {e.consecutive_failures > 0 && <span className="muted">{e.consecutive_failures} failed in a row</span>}
              </>}
              description={e.events.length === 0 ? "Every event" : e.events.join(", ")}
              trailing={<>
                <Menu label={`Manage the endpoint at ${hostOf(e.url)}`} className="btn secondary" trigger="Manage">
                  <MenuItem onClick={() => void navigator.clipboard?.writeText(e.url).then(() => setNote({ kind: "ok", text: "The endpoint's URL is on the clipboard." }))}>Copy URL</MenuItem>
                  <MenuItem onClick={() => setOpenLog(openLog === e.id ? null : e.id)}>
                    {openLog === e.id ? "Hide deliveries" : "Deliveries"}
                  </MenuItem>
                  <MenuItem onClick={() => void rotate(e)}>Rotate secret</MenuItem>
                  <MenuItem onClick={() => void act(e.status === "paused" ? "Resumed." : "Paused.",
                    e.status === "paused" ? "Could not resume it." : "Could not pause it.",
                    `/webhooks/${encodeURIComponent(e.id)}/status`, { status: e.status === "paused" ? "active" : "paused" })}>
                    {e.status === "paused" ? "Resume" : "Pause"}
                  </MenuItem>
                </Menu>
                <Button variant="quiet" aria-label={`Remove the endpoint at ${hostOf(e.url)}`}
                  confirm={`Remove the endpoint at ${hostOf(e.url)}? Nothing more is posted to it from now on, and its delivery log can no longer be read here.`}
                  onClick={() => { if (openLog === e.id) setOpenLog(null); void act("Endpoint removed.", "Could not remove it.", `/webhooks/${encodeURIComponent(e.id)}/remove`); }}>Remove</Button>
              </>}>
              {openLog === e.id && (
                deliveriesErr ? <Failed what="the deliveries" error={deliveriesErr} retry={() => readLog(e.id)} /> :
                deliveries === null ? <EmptyState loading /> : (
                  <Table head={["when", "event", "result", { label: "took", num: true }]}
                    empty={<EmptyState title="Nothing delivered yet" />}>
                    {deliveries.map((d) => (
                      <tr key={d.id}>
                        <td className="muted" title={whenTitle(d.created_at)}>{at(d.created_at)}</td>
                        <td className="wrap"><code><Breakable text={d.event_type} /></code></td>
                        <td>
                          <Badge status={d.status} />
                          {d.http_status !== null && <span className="muted"> HTTP {d.http_status}</span>}
                          {d.response_excerpt && <span className="cell-note clamp" title={d.response_excerpt}>{d.response_excerpt}</span>}
                        </td>
                        <td className="muted num">{d.latency_ms} ms</td>
                      </tr>
                    ))}
                  </Table>
                )
              )}
            </ListRow>
          ))}
        </List>
        <p className="help">
          A delivery is attempted exactly once.
          <HelpTip label="About delivery">
            If your endpoint takes longer than 10 seconds, is down, redirects, or answers anything outside 2xx, that
            event is not sent again: no second attempt, no backoff, and no dead-letter replay. Nothing is sent to a
            paused endpoint, and what happened while it was paused is not sent later. Twenty failures in a row pause
            the endpoint — the node stops posting to a URL that has stopped answering, and you resume it here when it
            is fixed.
          </HelpTip>
          {" "}Treat a webhook as a hint and the inbox (<code>get_inbox</code>, <code>wait_for_updates</code>) as the record.
        </p>
      </Section>
    </main>
  );
}
