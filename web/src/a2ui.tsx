// The owner's asks and notices, drawn from their A2UI v0.9.1 surface. The catalog is the node's
// (internal/services/asks/catalog.go): a Column root whose first child is the TLDR Text, then Text,
// KeyValue, at most one Choice of ready replies, DateTimeInput, Button, and a TextField last. The node
// parsed every surface before it stored it, so this draws what is there and nothing more. An answer
// goes to POST /asks/{id}/answer, which sends a ready reply or what was written to the contact as the
// owner's own message and makes the one line the agent reads; a date or a button answers without
// sending. A notice, and an ask that is no longer open, offer nothing to press.
import { useState } from "react";
import { postForm } from "./api";
import { Badge, Button, Notice, Toolbar } from "./ui";
import { when, whenTitle } from "./words";

export type Ask = {
  id: string; kind: "ask" | "notice"; thread_id: string; contact: string; for_message_id: string;
  status: "open" | "answered" | "expired" | "withdrawn" | "posted"; tldr: string; surface: unknown;
  answer_text: string; created_at: number; updated_at: number; expires_at: number;
};

type Comp = {
  id: string; component: string; children?: string[]; text?: string; variant?: string; label?: string;
  rows?: { label: string; value: string }[]; options?: { label: string }[];
  enableDate?: boolean; enableTime?: boolean; min?: string; max?: string; child?: string;
};

/** The surface's components by id: the second message's updateComponents. */
function componentsOf(a: Ask): Map<string, Comp> {
  const out = new Map<string, Comp>();
  const msgs = Array.isArray(a.surface) ? a.surface : [];
  for (const m of msgs) {
    const list = (m as { updateComponents?: { components?: Comp[] } }).updateComponents?.components ?? [];
    for (const c of list) out.set(c.id, c);
  }
  return out;
}

/** A datetime-local value ("2026-10-22T14:00") with this browser's offset, as the node reads it (RFC 3339). */
function withOffset(v: string): string {
  const off = -new Date(v).getTimezoneOffset();
  const abs = Math.abs(off);
  const hh = String(Math.floor(abs / 60)).padStart(2, "0");
  const mm = String(abs % 60).padStart(2, "0");
  return `${v.length === 16 ? v + ":00" : v}${off >= 0 ? "+" : "-"}${hh}:${mm}`;
}

const STATUS: Record<Ask["status"], string> = {
  open: "waiting on you", answered: "answered", expired: "expired unanswered", withdrawn: "withdrawn by your agent", posted: "done for you",
};

/**
 * One ask or notice as a card. `from` names the contact it is about, for the Needs you page; the
 * conversation leaves it out. `onAnswered` reloads what the page shows.
 */
export function AskCard({ ask, from, onAnswered }: { ask: Ask; from?: string; onAnswered: () => void }) {
  const comps = componentsOf(ask);
  const root = comps.get("root");
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  const [typed, setTyped] = useState("");
  const [dates, setDates] = useState<Record<string, string>>({});
  const live = ask.kind === "ask" && ask.status === "open";

  const answer = async (component: string, value: string) => {
    setBusy(component); setErr("");
    const r = await postForm(`/asks/${encodeURIComponent(ask.id)}/answer`, { component, value });
    setBusy("");
    if (!r.ok) {
      let detail = "";
      try { detail = (JSON.parse(r.body) as { detail?: string }).detail ?? ""; } catch { /* not JSON */ }
      setErr(detail || `The node answered ${r.status}.`);
    } else setTyped("");
    onAnswered();
  };

  const draw = (id: string, first: boolean) => {
    const c = comps.get(id);
    if (!c) return null;
    switch (c.component) {
      case "Text": {
        // The first child is the TLDR: the card's heading.
        if (first) return <h3 key={id} className="ask-tldr">{c.text}</h3>;
        if (c.variant === "caption") return <p key={id} className="muted">{c.text}</p>;
        return <p key={id}>{c.text}</p>;
      }
      case "KeyValue":
        return (
          <dl key={id} className="ask-kv">
            {(c.rows ?? []).map((r, i) => <div key={i}><dt>{r.label}</dt><dd>{r.value}</dd></div>)}
          </dl>
        );
      case "Choice":
        return (
          <div key={id} className="ask-choice" role="group" aria-label={c.label ?? "Ready replies"}>
            {c.label && <p className="muted">{c.label}</p>}
            <Toolbar>
              {(c.options ?? []).map((o) => (
                <Button key={o.label} variant="secondary" disabled={!live || busy !== ""} busy={busy === id + o.label}
                  title="Sent to them as your reply" onClick={() => { setBusy(id + o.label); answer(id, o.label); }}>{o.label}</Button>
              ))}
            </Toolbar>
          </div>
        );
      case "TextField":
        return live ? (
          <div key={id} className="ask-own">
            {c.variant === "longText"
              ? <textarea rows={3} aria-label={c.label ?? "Write my own"} placeholder={c.label ?? "Write my own"} value={typed} onChange={(e) => setTyped(e.target.value)} />
              : <input type="text" aria-label={c.label ?? "Write my own"} placeholder={c.label ?? "Write my own"} value={typed}
                onChange={(e) => setTyped(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && typed.trim()) answer(id, typed); }} />}
            <Button disabled={!typed.trim() || busy !== ""} busy={busy === id} onClick={() => answer(id, typed)}>Send</Button>
          </div>
        ) : null;
      case "DateTimeInput": {
        const type = c.enableDate && c.enableTime ? "datetime-local" : c.enableDate ? "date" : "time";
        const v = dates[id] ?? "";
        return live ? (
          <div key={id} className="ask-own">
            <input type={type} aria-label={c.label ?? "Pick"} value={v} min={c.min?.slice(0, type === "date" ? 10 : 16)} max={c.max?.slice(0, type === "date" ? 10 : 16)}
              onChange={(e) => setDates((d) => ({ ...d, [id]: e.target.value }))} />
            <Button variant="secondary" disabled={!v || busy !== ""} busy={busy === id} title="Answers your agent; nothing is sent to them"
              onClick={() => answer(id, type === "datetime-local" ? withOffset(v) : v)}>{c.label ?? "Pick"}</Button>
          </div>
        ) : null;
      }
      case "Button": {
        const label = comps.get(c.child ?? "")?.text ?? c.id;
        return (
          <Toolbar key={id}>
            <Button variant={c.variant === "primary" ? "primary" : "secondary"} disabled={!live || busy !== ""} busy={busy === id}
              title="Answers your agent; nothing is sent to them" onClick={() => answer(id, "")}>{label}</Button>
          </Toolbar>
        );
      }
    }
    return null;
  };

  return (
    <article className={"ask-card " + ask.kind + (live ? " live" : "")} aria-label={ask.kind === "ask" ? "Your agent asks" : "Your agent did"}>
      <div className="ask-h">
        <Badge tone={live ? "warn" : ask.status === "posted" || ask.status === "answered" ? "ok" : "neutral"}>{ask.kind === "ask" ? "Your agent asks" : "Your agent did"}</Badge>
        {from && <b>{from}</b>}
        <span className="muted">{STATUS[ask.status]}</span>
        <time className="muted" dateTime={new Date(ask.created_at * 1000).toISOString()} title={whenTitle(ask.created_at * 1000)}>{when(ask.created_at * 1000, Date.now(), true)}</time>
        {live && <span className="muted" title={whenTitle(ask.expires_at * 1000)}>expires {when(ask.expires_at * 1000, Date.now(), true)}</span>}
      </div>
      {(root?.children ?? []).map((id, i) => draw(id, i === 0))}
      {ask.answer_text && <p className="muted">{ask.answer_text}</p>}
      {err && <Notice kind="err">{err}</Notice>}
    </article>
  );
}
