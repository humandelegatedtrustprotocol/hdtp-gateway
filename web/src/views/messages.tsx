// The inbox: conversations on the left, one conversation in the middle, the
// contact on the right — every thread with that person merged in time order,
// because a conversation is with a person, not with a thread id (HDTP §7).
// The right-hand panel is the contact's permission switchboard and their slice
// of the audit trail, so "what may this contact do" is answered next to what
// they are doing.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { accountName, currentAccount, failureOf, getJSON, postForm, subscribe } from "../api";
import { Link, navigate } from "../router";
import { Avatar, Badge, Button, CountChip, EmptyState, Failed, Icon, Notice, PLUMBING_TOOLS, PageHeader, Toolbar, permLabel, tallyCount, toolAction, toolLabel, trustWord, type IconName, type Tally } from "../ui";
import { SchemaForm, missingRequired } from "../schema_form";
import { IdText } from "../glance";
import { actionWord, ago, fileSize, mediaKind, undeliveredReason, when, whenTitle } from "../words";
import type { Schema, Values } from "../schema_form";

/** `unread` is counted by the node at runtime from the conversation's read marker, and capped: `{ count: 50, capped: true }` reads "50+". */
type Person = {
  fingerprint: string; label: string; status: string; preview: string;
  selected: boolean; unread: Tally; presence: string;
  /** When they were last seen to be reachable (unix seconds): what the presence dot is evidence of. */
  last_seen?: number;
};
type Media = { filename: string; mime: string; size?: number; hash?: string; url?: string };
/** `ts` is when it was written and `until` when a message still being tried stops being tried (unix seconds). */
type Msg = { mine: boolean; body: string; who: string; ts: number; until?: number; state?: string; media?: Media };
/**
 * One page of conversations, most recently active first (the node's ConversationsPage); `more` when there
 * are others past it, which a search reaches. `through` is the newest message of the selected conversation
 * this answer shows: what showing it marks read through (POST /messages/read).
 */
type Data = { contacts: Person[] | null; messages: Msg[] | null; new_msg_id: string; unread: Tally; more: boolean; through: number };

type PermRow = { name: string; on: boolean };
type Contact = {
  fingerprint: string; display_name: string; petname: string; status: string;
  preset: string; trust: string; permissions: PermRow[]; their_permissions: string[] | null; presets: string[];
};
type ContactTool = { name: string; description?: string; input_schema?: Schema };
// The protocol's own plumbing is callable but not something a person invokes by hand.
const PANEL_KEY = "hdtp.inbox.panel";
/** The narrowest window the contact panel stands beside the conversation in; style.css makes it a drawer below (held equal by test/style_test.mjs). */
const PANEL_BESIDE = 1360;
const FOCUS_KEY = "hdtp.inbox.focus";

type AuditRow = { Seq: number; TS: number; ActorKind: string; ActorID: string; Action: string; Resource: string; Outcome: string };

type Pane = "list" | "thread" | "panel";

export function Messages() {
  const [sel, setSel] = useState(() => new URLSearchParams(location.search).get("contact") ?? "");
  const [d, setD] = useState<Data | null>(null);
  const [text, setText] = useState("");
  const [sendErr, setSendErr] = useState("");
  // The message being sent right now, shown before the node answers.
  const [pending, setPending] = useState<Msg | null>(null);
  const [q, setQ] = useState("");
  const [pane, setPane] = useState<Pane>(sel ? "thread" : "list");
  // The contact panel is the owner's to keep or dismiss; the choice persists — from PANEL_BESIDE up,
  // where it stands beside the conversation. Narrower (above a phone) it is a drawer over the
  // conversation (style.css), so the page opens without it whatever was saved, and opening or closing
  // it there is for now, not kept: as a third column there it left the conversation 252px at 1100.
  const [panelOpen, setPanelOpen] = useState<boolean>(() => {
    if (window.innerWidth < PANEL_BESIDE) return false;
    try { const v = localStorage.getItem(PANEL_KEY); if (v !== null) return v === "1"; } catch { /* no storage */ }
    return true;
  });
  const togglePanel = () => setPanelOpen((v) => {
    if (window.innerWidth >= PANEL_BESIDE) { try { localStorage.setItem(PANEL_KEY, v ? "0" : "1"); } catch { /* ignore */ } }
    return !v;
  });
  // Focus: the thread alone, full width. Both side columns step aside until asked back.
  const [focus, setFocus] = useState<boolean>(() => { try { return localStorage.getItem(FOCUS_KEY) === "1"; } catch { return false; } });
  const toggleFocus = () => setFocus((v) => { try { localStorage.setItem(FOCUS_KEY, v ? "0" : "1"); } catch { /* ignore */ } return !v; });
  const [uploading, setUploading] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const [tools, setTools] = useState<ContactTool[]>([]);
  const [allTools, setAllTools] = useState<ContactTool[]>([]);
  const [toolsState, setToolsState] = useState<"loading" | "ready" | "failed">("loading");
  const [toolsTry, setToolsTry] = useState(0);
  const [menuOpen, setMenuOpen] = useState(false);
  const [accept, setAccept] = useState<string>("");
  const [toolsOpen, setToolsOpen] = useState(false);
  const [active, setActive] = useState<ContactTool | null>(null);
  const [args, setArgs] = useState<Values>({});
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<string>("");
  const logRef = useRef<HTMLDivElement>(null);
  const taRef = useRef<HTMLTextAreaElement>(null);

  // A first read that failed is said as one: the Inbox drew a blank content area, with no list, no
  // heading and no error, for as long as the node refused.
  const [err, setErr] = useState("");
  // The search is the node's too: the list is one page, and a conversation past it is found by asking.
  const [search, setSearch] = useState("");
  useEffect(() => { const t = setTimeout(() => setSearch(q.trim()), 250); return () => clearTimeout(t); }, [q]);
  const load = useCallback(() => {
    const params: Record<string, string> = {};
    if (sel) params.contact = sel;
    if (search) params.q = search;
    return getJSON<Data>("/api/conversations", params).then((x) => { setD(x); setErr(""); }).catch((e) => setErr(failureOf(e)));
  }, [sel, search]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => subscribe(load), [load]); // SSE: deliveries and inbound messages refresh the view
  // Whether the page is seen. Coming back to it reads the conversation on screen (the effect below runs
  // again on the change) and looks again for what moved while it was hidden.
  const [visible, setVisible] = useState(() => document.visibilityState === "visible");
  useEffect(() => {
    const onVis = () => { const v = document.visibilityState === "visible"; setVisible(v); if (v) load(); };
    document.addEventListener("visibilitychange", onVis);
    return () => document.removeEventListener("visibilitychange", onVis);
  }, [load]);
  // Showing a conversation reads it, through the newest message shown and no further: one that lands after
  // stays unread. Only while the page is seen, and only when the row says there is something to read, so a
  // read that changes nothing is never sent. The sidebar hears of it at once (Counts, "hdtp:counts").
  const selUnread = tallyCount((d?.contacts ?? []).find((p) => p.fingerprint === sel)?.unread ?? 0);
  const through = d?.through ?? 0;
  useEffect(() => {
    if (!sel || selUnread === 0 || through === 0 || !visible) return;
    postForm("/messages/read", { contact: sel, through: String(through) }).then((r) => {
      if (!r.ok) return;
      dispatchEvent(new Event("hdtp:counts"));
      load();
    }).catch(() => { /* the count stays until the next look */ });
  }, [sel, selUnread, through, visible, load]);
  // A conversation whose contact was removed (the node's "removed" row, named by what its threads kept):
  // a record to read, with nobody to write to, no tools to ask for and no contact to show.
  const selRemoved = (d?.contacts ?? []).find((p) => p.fingerprint === sel)?.status === "removed";
  // What this contact lets us call on their server — asked once per conversation.
  useEffect(() => {
    setPending(null); setTools([]); setAllTools([]); setToolsState("loading"); setMenuOpen(false); setToolsOpen(false); setActive(null); setArgs({}); setResult("");
    if (!sel || selRemoved) return;
    let alive = true;
    getJSON<{ tools: ContactTool[] }>(`/api/contacts/${encodeURIComponent(sel)}/tools`)
      .then((r) => { if (alive) { setAllTools(r.tools ?? []); setTools((r.tools ?? []).filter((t) => !PLUMBING_TOOLS.has(t.name))); setToolsState("ready"); } })
      .catch(() => { if (alive) { setAllTools([]); setTools([]); setToolsState("failed"); } });
    return () => { alive = false; };
  }, [sel, toolsTry, selRemoved]);
  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [d?.messages?.length, sel]);
  useEffect(() => {
    if (!menuOpen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setMenuOpen(false); };
    const onClick = (e: MouseEvent) => { if (!(e.target as Element).closest?.(".plus-wrap")) setMenuOpen(false); };
    addEventListener("keydown", onKey); addEventListener("mousedown", onClick);
    return () => { removeEventListener("keydown", onKey); removeEventListener("mousedown", onClick); };
  }, [menuOpen]);

  const people = useMemo(() => {
    const all = d?.contacts ?? [];
    const needle = q.trim().toLowerCase();
    return needle ? all.filter((p) => p.label.toLowerCase().includes(needle)) : all;
  }, [d, q]);
  const current = (d?.contacts ?? []).find((p) => p.fingerprint === sel) ?? null;

  const pick = (fpr: string) => {
    setSel(fpr);
    setPane("thread");
    history.replaceState(null, "", "/messages?contact=" + encodeURIComponent(fpr));
  };

  const send = async () => {
    const body = text.trim();
    if (!body || !sel || !d?.new_msg_id) return;
    setText("");
    if (taRef.current) taRef.current.style.height = "";
    // The node records the message and then attempts delivery inline, which
    // takes as long as reaching their node takes. Show the bubble with a clock
    // straight away, as a messenger does, rather than leaving the thread empty
    // until the round trip finishes and the message appears already delivered.
    setPending({ mine: true, body, who: "human", ts: Math.floor(Date.now() / 1000), state: "sending" });
    const r = await postForm("/messages/send", { contact: sel, text: body, msg_id: d.new_msg_id });
    const err = r.url.searchParams?.get("err") ?? "";
    setSendErr(r.ok ? err ?? "" : "send failed");
    setPending(null);
    load(); // also fetches a fresh msg_id
  };

  const upload = async (file: File) => {
    if (!sel || !d?.new_msg_id) return;
    if (file.size > 5 * 1024 * 1024) { setSendErr("That file is over 5 MiB, the protocol's limit for inline media."); return; }
    setUploading(true); setSendErr("");
    const fd = new FormData();
    fd.append("file", file, file.name);
    fd.append("contact", sel); fd.append("msg_id", d.new_msg_id);
    fd.append("csrf", csrfCookie());
    const url = "/messages/send_media" + (currentAccount() ? "?account=" + encodeURIComponent(currentAccount()) : "");
    try {
      const r = await fetch(url, { method: "POST", headers: { "X-HDTP-Csrf": csrfCookie() }, body: fd });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) setSendErr(j.error || "the file was not sent");
    } catch { setSendErr("could not reach this node"); }
    setUploading(false);
    if (fileRef.current) fileRef.current.value = "";
    load();
  };

  const run = async () => {
    if (!active || !sel) return;
    setRunning(true); setResult("");
    const body = new URLSearchParams();
    body.set("csrf", csrfCookie()); if (currentAccount()) body.set("account", currentAccount());
    body.set("tool", active.name); body.set("args", JSON.stringify(args));
    try {
      const r = await fetch(`/contacts/${encodeURIComponent(sel)}/call`, {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "X-HDTP-Csrf": csrfCookie() }, body: body.toString(),
      });
      const j = await r.json().catch(() => null);
      if (!r.ok || !j) setResult("✖ " + (j?.error || `the call failed (${r.status})`));
      else setResult(renderResult(j.result));
    } catch { setResult("✖ could not reach this node"); }
    setRunning(false);
  };

  if (!d) return <main className="wide">{err ? <><PageHeader title="Inbox" /><Failed what="your conversations" error={err} retry={load} /></> : <EmptyState loading />}</main>;

  const missing = active ? missingRequired(active.input_schema ?? {}, args) : [];
  const cls = "inbox" + (panelOpen ? "" : " panel-off") + (focus ? " focus" : "");
  return (
    <main className="wide">
      <div className={cls} data-pane={pane}>
        <aside className="convs" aria-label="Conversations">
          <div className="hd">
            <h1>Inbox</h1>
            <Toolbar><Button variant="secondary" to="/invites" title="Invite someone">+ Invite</Button></Toolbar>
          </div>
          <div className="search">
            <input type="text" placeholder="Search contacts" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search contacts" />
          </div>
          <div className="conv-list">
            {people.map((p) => (
              <button key={p.fingerprint} className={"conv" + (p.fingerprint === sel ? " sel" : "")} onClick={() => pick(p.fingerprint)}>
                <Avatar name={p.label} />
                <span className="who">
                  <b><span>{p.label}</span>{p.presence && <span className={"dot " + p.presence} title={presenceWords(p)} aria-label={presenceWords(p)} />}</b>
                  <span className="preview">{p.preview || (p.status === "active" ? "No messages yet" : p.status)}</span>
                </span>
                <span className="end">
                  {tallyCount(p.unread) > 0 && <CountChip n={p.unread} noun="unread" tone="ok" />}
                </span>
              </button>
            ))}
            {d.more && <p className="muted">Showing the most recent conversations. Search to find anyone else.</p>}
            {people.length === 0 && ((d.contacts ?? []).length === 0 && !search ? (
              <EmptyState title="No contacts yet" action={<Button to="/invites">Create an invite</Button>}>Invite someone, or accept an invite you were given.</EmptyState>
            ) : (
              <EmptyState>Nobody matches “{q}”.</EmptyState>
            ))}
          </div>
        </aside>

        <section className="thread" aria-label="Conversation">
          {current ? (
            <>
              <div className="thread-h">
                <Toolbar className="back"><Button variant="quiet" icon="back" aria-label="Back to conversations" onClick={() => setPane("list")} /></Toolbar>
                <Avatar name={current.label} />
                <div className="who">
                  <div className="name" title={current.label}>{current.label}</div>
                  <div className="meta">
                    {current.presence && <><span className={"dot " + current.presence} />{presenceWords(current)}</>}
                    {!current.presence && <span>{current.status}</span>}
                  </div>
                </div>
                <div className="end">
                  {!selRemoved && <Badge tone="ok" title={`Their key is pinned: a message that does not verify against it is refused.\n${current.fingerprint}`}><Icon name="shield" size={12} /> pinned</Badge>}
                  {!selRemoved && <Toolbar className="details">
                    <Button variant="quiet" icon="panel" aria-pressed={panelOpen && !focus} title={panelOpen && !focus ? "Hide contact panel" : "Show contact panel"} aria-label="Contact panel"
                      onClick={() => { if (window.innerWidth <= 900) setPane(pane === "panel" ? "thread" : "panel"); else { if (focus) toggleFocus(); if (!panelOpen || focus) { if (!panelOpen) togglePanel(); } else togglePanel(); } }} />
                  </Toolbar>}
                  <Toolbar className="expand">
                    <Button variant="quiet" icon={focus ? "collapse" : "expand"} aria-pressed={focus} title={focus ? "Exit full width" : "Full width"} aria-label={focus ? "Exit full width" : "Full width"} onClick={toggleFocus} />
                  </Toolbar>
                </div>
              </div>
              <div className="log" ref={logRef}>
                <div className="log-in">
                  {(d.messages ?? []).length === 0 && (
                    <EmptyState title="Say hello">Messages you type here are labelled <code>human</code>; your agent's are labelled <code>agent</code>.</EmptyState>
                  )}
                  {[...(d.messages ?? []),
                    // The node records the message before it attempts delivery, so
                    // its own copy can arrive on the event stream while this one is
                    // still on screen; show ours only until then.
                    ...(pending && !(d.messages ?? []).some((m) => m.mine && m.body === pending.body) ? [pending] : []),
                  ].map((m, i) => (
                    <div key={i} className={"msg" + (m.mine ? " mine" : "")}>
                      {m.mine ? <Avatar me name={accountName()} size="sm" /> : <Avatar name={current.label} size="sm" />}
                      <div className="body">
                        <div className="meta">
                          {/* One contact per thread, and the avatar and the side say whose each message is: a
                              long name over every message wrapped to four lines on a phone. Said to a reader. */}
                          <span className="sr-only">{m.mine ? "You" : current.label}</span>
                          <span className={"tag " + (m.who === "agent" ? "agent" : "human")}>{m.who || "human"}</span>
                          <time dateTime={new Date(m.ts * 1000).toISOString()} title={whenTitle(m.ts * 1000)}>{when(m.ts * 1000, Date.now(), true)}</time>
                          {m.mine && <DeliveryMark state={m.state} />}
                        </div>
                        <div className="bubble">
                          {m.body}
                          {m.media && <MediaBubble m={m.media} onFetched={load} />}
                        </div>
                        {m.mine && <Undelivered m={m} />}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              {sendErr && <Notice kind="err">{sendErr}</Notice>}
              {selRemoved && <div className="foot-note">No longer a contact. The conversation stays as a record of what was said; nothing more can be sent to them from here.</div>}
              {!selRemoved && toolsOpen && (
                <div className="tooldock" aria-label="Contact tools">
                  <div className="tooldock-h">
                    <strong title={active?.name}>{active ? <>{toolLabel(active.name)} <code>{active.name}</code></> : "Tools this contact lets you call"}</strong>
                    <Toolbar>
                      {active && <Button variant="quiet" icon="back" aria-label="All tools" title="All tools" onClick={() => { setActive(null); setArgs({}); setResult(""); }} />}
                      <Button variant="quiet" icon="close" aria-label="Close tools" onClick={() => setToolsOpen(false)} />
                    </Toolbar>
                  </div>
                  {!active ? (
                    <div className="toollist">
                      {tools.map((t) => (
                        <button key={t.name} className="toolitem" onClick={() => { setActive(t); setArgs({}); setResult(""); }}>
                          <b title={t.name}>{toolLabel(t.name)}</b>{t.description && <span>{t.description}</span>}
                        </button>
                      ))}
                    </div>
                  ) : (
                    <>
                      {active.description && <p className="help">{active.description}</p>}
                      <SchemaForm schema={active.input_schema ?? {}} values={args} onChange={setArgs} />
                      <Toolbar>
                        <Button busy={running} disabled={missing.length > 0} onClick={run} title={`Call ${active.name}`}>{toolAction(active.name)}</Button>
                        {missing.length > 0 && <span className="muted">required: {missing.join(", ")}</span>}
                      </Toolbar>
                      {result && <pre className="toolresult">{result}</pre>}
                    </>
                  )}
                </div>
              )}
              {!selRemoved && <><div className="composer">
                <input ref={fileRef} type="file" hidden accept={accept || undefined} onChange={(e) => { const f = e.target.files?.[0]; if (f) upload(f); }} />
                <div className="plus-wrap">
                  <button className={"btn quiet icon plus" + (menuOpen ? " on" : "")} title="Add" aria-label="Add" aria-expanded={menuOpen} aria-haspopup="menu" aria-busy={uploading} disabled={uploading} onClick={() => setMenuOpen((v) => !v)}>
                    <Icon name="plus" size={20} />
                  </button>
                  {menuOpen && (
                    <div className="plusmenu" role="menu" aria-label="Add to the conversation">
                      {(() => {
                        const canMedia = allTools.some((t) => t.name === "send_media");
                        const pick = (acc: string) => { setAccept(acc); setMenuOpen(false); setTimeout(() => fileRef.current?.click(), 0); };
                        const open = (t: ContactTool) => { setMenuOpen(false); setActive(t); setArgs({}); setResult(""); setToolsOpen(true); };
                        const tiles: { key: string; label: string; icon: IconName; on: () => void; title?: string }[] = [];
                        if (canMedia) {
                          tiles.push({ key: "file", label: "File", icon: "file", on: () => pick("") });
                          tiles.push({ key: "photo", label: "Photo", icon: "image", on: () => pick("image/*") });
                        }
                        for (const t of tools) tiles.push({ key: t.name, label: toolLabel(t.name), icon: toolIcon(t.name), on: () => open(t), title: t.name });
                        if (tiles.length === 0) {
                          if (toolsState === "loading") return <p className="muted plus-empty">Asking {current.label}'s node what you may do there…</p>;
                          if (toolsState === "failed") {
                            return (
                              <p className="muted plus-empty">
                                Could not reach {current.label}'s node to list tools.{" "}
                                <Button variant="link" onClick={() => setToolsTry((n) => n + 1)}>Try again</Button>
                              </p>
                            );
                          }
                          return <p className="muted plus-empty">{current.label} has not enabled files or tools for you yet.</p>;
                        }
                        return tiles.map((t) => (
                          <button key={t.key} className="tile" role="menuitem" onClick={t.on} title={t.title}>
                            <span className="circ"><Icon name={t.icon} size={22} /></span>
                            <span className="lbl">{t.label}</span>
                          </button>
                        ));
                      })()}
                    </div>
                  )}
                </div>
                <textarea ref={taRef} rows={1} placeholder={`Message ${current.label}…`} value={text}
                  aria-label="Message"
                  onChange={(e) => { setText(e.target.value); e.target.style.height = ""; e.target.style.height = Math.min(160, e.target.scrollHeight) + "px"; }}
                  onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }} />
                <Button onClick={send} disabled={!text.trim()}>Send</Button>
              </div>
              <div className="foot-note"><span className="tag human">human</span> Sent as you. Enter sends, Shift+Enter for a new line.</div></>}
            </>
          ) : (
            <EmptyState title="Pick a conversation">Choose a contact on the left to read and write.</EmptyState>
          )}
        </section>

        {current && !selRemoved && <ContactPanel fpr={current.fingerprint} label={current.label} onBack={() => { if (window.innerWidth <= 900) setPane("thread"); else togglePanel(); }} />}
      </div>
    </main>
  );
}

// A tool result is MCP content: text parts are shown as text, anything else as JSON.
function renderResult(r: unknown): string {
  if (r && typeof r === "object" && Array.isArray((r as { content?: unknown[] }).content)) {
    const parts = (r as { content: { type?: string; text?: string }[] }).content;
    const texts = parts.filter((p) => p.type === "text" && typeof p.text === "string").map((p) => p.text as string);
    if (texts.length === parts.length && texts.length > 0) {
      return texts.map((t) => { try { return JSON.stringify(JSON.parse(t), null, 2); } catch { return t; } }).join("\n");
    }
  }
  return JSON.stringify(r, null, 2);
}

// A tool's tile: a plain label and an icon that says what it does. Unknown
// tools get their name spaced out and a spark, never hidden.
function toolIcon(name: string): "calendar" | "calendarCheck" | "calendarX" | "activity" | "plug" | "spark" {
  if (name === "check_availability") return "calendar";
  if (name === "book_slot") return "calendarCheck";
  if (name === "cancel_booking") return "calendarX";
  if (name === "get_status") return "activity";
  if (name.startsWith("integration.")) return "plug";
  return "spark";
}

// The right-hand panel: who this is, what they may do here (live switches),
// what they let you do there, and their recent entries in the audit trail.
function ContactPanel({ fpr, label, onBack }: { fpr: string; label: string; onBack: () => void }) {
  const [c, setC] = useState<Contact | null>(null);
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const base = `/contacts/${encodeURIComponent(fpr)}`;

  const load = useCallback(() => {
    getJSON<Contact>(`/api/contacts/${encodeURIComponent(fpr)}`).then(setC).catch(() => setC(null));
    // A contact's own calls are recorded as system actions carrying their
    // fingerprint in the resource, and the owner's decisions about them carry it
    // too — so the trail for "this contact" is anything that names them, not
    // only rows where they are the actor.
    getJSON<{ rows: AuditRow[] | null }>("/api/audit", { limit: "200" })
      // /api/audit answers newest first. This took the LAST eight of an
      // ascending list; against a descending one that is the eight OLDEST —
      // the seam a shared API's ordering change leaves behind in its second
      // consumer.
      .then((a) => setAudit((a.rows ?? []).filter((r) => r.ActorID === fpr || String(r.Resource).includes(fpr)).slice(0, 8)))
      .catch(() => {});
  }, [fpr]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => subscribe(load), [load]);

  // Permissions are a multi-select; postForm sets one value per key, so the
  // form is built by hand — same shape the contact page has always posted.
  const toggle = async (name: string, on: boolean) => {
    if (!c) return;
    setBusy(name);
    const body = new URLSearchParams();
    body.set("csrf", csrfCookie());
    if (currentAccount()) body.set("account", currentAccount());
    for (const p of c.permissions) if (p.name === name ? on : p.on) body.append("perm", p.name);
    const r = await fetch(`${base}/permissions`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "X-HDTP-Csrf": csrfCookie() }, body: body.toString(),
    });
    setBusy(null);
    setNote(r.ok ? "" : "could not save permissions");
    load();
  };

  return (
    <aside className="panel" aria-label="Contact details">
      <Toolbar className="back"><Button variant="quiet" icon="back" onClick={onBack}>Back</Button></Toolbar>
      <div className="who">
        <Avatar name={label} size="lg" />
        <div>
          <b>{label}</b>
          <small>{c?.status ?? ""}{c?.trust && <> · {trustWord(c.trust)}</>}</small>
        </div>
      </div>
      <div>
        <h3>Identity</h3>
        <IdText id={fpr} />
      </div>
      <div>
        <h3>What they may do here</h3>
        {note && <Notice kind="err">{note}</Notice>}
        {c ? c.permissions.map((p) => (
          <div className="perm" key={p.name}>
            <span className="k" title={p.name}>{permLabel(p.name)}</span>
            <button type="button" role="switch" aria-checked={p.on} aria-label={permLabel(p.name)} title={p.name}
              className={"sw" + (p.on ? " on" : "")} disabled={busy === p.name}
              onClick={() => toggle(p.name, !p.on)} />
          </div>
        )) : <p className="muted">Loading…</p>}
        {c && <p className="muted">Preset: {c.preset || "custom"}</p>}
      </div>
      {c && (c.their_permissions ?? []).length > 0 && (
        <div>
          <h3>What they let you do there</h3>
          <div className="rowline">{(c.their_permissions ?? []).map((p) => <Badge key={p} title={p}>{permLabel(p)}</Badge>)}</div>
        </div>
      )}
      <div>
        <h3>Recent activity</h3>
        {audit.length === 0 ? <p className="muted">Nothing recorded for this contact yet.</p> : (
          <div className="audit-mini">
            {audit.map((r) => (
              <div key={r.Seq}>
                <b title={r.Action}>{actionWord(r.Action)}</b>
                <Badge status={r.Outcome} />
                <time dateTime={new Date(r.TS * 1000).toISOString()} title={whenTitle(r.TS * 1000)}>{when(r.TS * 1000)}</time>
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="links">
        <Link to={`/contacts/${encodeURIComponent(fpr)}`}>Open full profile →</Link>
        <Link to="/audit">Full audit trail →</Link>
      </div>
    </aside>
  );
}

function csrfCookie(): string {
  const jar = document.cookie.split("; ");
  return jar.find((c) => c.startsWith("hdtp_csrf"))?.split("=").slice(1).join("=") ?? "";
}

// A media message. Two shapes, and the difference is the point: bytes this node
// already holds open directly, while a URL a contact sent is fetched only when
// the owner asks. Auto-fetching an attacker-supplied URL would let any contact
// drive requests out of this node — into a home LAN, for instance (§7.5).
function MediaBubble({ m, onFetched }: { m: Media; onFetched: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const name = m.filename || "attachment";
  // What the file is, in words ('Excel spreadsheet · 2.2 MB'); its MIME type is in the title.
  const kind = [mediaKind(m.mime, m.filename), fileSize(m.size)].filter(Boolean).join(" · ");

  if (m.hash) {
    const href = "/media/" + encodeURIComponent(m.hash) +
      (currentAccount() ? "?account=" + encodeURIComponent(currentAccount()) : "");
    // Served as an attachment with nosniff and a sandboxing CSP: a file a
    // contact sent must not become script on the portal's own origin.
    return (
      <span className="media">
        <Icon name="clip" size={15} /> <a href={href} download={name}>{name}</a>
        <span className="muted" title={m.mime}>{kind}</span>
      </span>
    );
  }
  return (
    <span className="media">
      <Icon name="link" size={15} /> <span>{name}</span>
      <span className="muted" title={m.mime}>{kind} — not downloaded</span>
      <Button variant="secondary" busy={busy}
        onClick={async () => {
          setBusy(true);
          setErr("");
          const r = await postForm("/media/fetch", { url: m.url ?? "" });
          setBusy(false);
          if (!r.ok) setErr(r.body || "that fetch was refused");
          else onFetched();
        }}>
        Fetch it
      </Button>
      {err && <span className="bad">{err}</span>}
    </span>
  );
}

/**
 * Whether they are around, in words, for the dot's title and the header: the dot is evidence (a
 * message they sent, or one of ours their node took), so the words say when that evidence is from.
 */
function presenceWords(p: Pick<Person, "presence" | "last_seen">): string {
  if (p.presence === "online") return "Online";
  return p.last_seen ? `Away · last seen ${ago(p.last_seen * 1000)}` : "Away · no contact yet";
}

/**
 * One line under a message of ours that has not landed: 'Not delivered yet — trying again until
 * Mon 14:05', or 'Not delivered — <why>' (words.ts's reasons, shared with the cloud). A send still
 * in flight says nothing: the clock beside the time is enough, and words would only alarm. The node
 * has no retry of its own to offer; the sweep keeps trying until the deadline it says.
 */
function Undelivered({ m }: { m: Msg }) {
  let text = "";
  if (m.state === "retrying") text = m.until ? `Not delivered yet — trying again until ${when(m.until * 1000, Date.now(), true)}` : "Not delivered yet — trying again";
  else if (m.state === "expired") text = `Not delivered — ${undeliveredReason("expired")}`;
  else if (m.state === "failed") text = `Not delivered — ${undeliveredReason(null)}`;
  if (!text) return null;
  return <span className="bad" title={m.state}><Icon name="warn" size={14} /> {text}</span>;
}

// Keep the old deep link working: /messages?contact=… is what the contacts page
// and the dashboard navigate to.
export function openConversation(fpr: string) {
  navigate("/messages?contact=" + encodeURIComponent(fpr));
}

// What an outbound message is doing, in the place a messenger puts it: a clock
// while the attempt is in flight, a tick once their node took it. Only a real
// problem gets words — a send in progress used to read "not delivered yet —
// retrying", which describes a failure that had not happened.
function DeliveryMark({ state }: { state?: string }) {
  if (!state) return null;
  const mark: Record<string, { icon: Parameters<typeof Icon>[0]["name"]; title: string }> = {
    sending: { icon: "clock", title: "Sending…" },
    delivered: { icon: "tick", title: "Delivered to their node" },
    retrying: { icon: "warn", title: "Not delivered yet — retrying" },
    expired: { icon: "warn", title: "Never delivered" },
    failed: { icon: "warn", title: "Not delivered" },
  };
  const m = mark[state];
  if (!m) return null;
  return <span className={"mark-" + state} title={m.title} aria-label={m.title}><Icon name={m.icon} size={13} /></span>;
}
