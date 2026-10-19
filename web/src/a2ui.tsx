// The owner's asks and notices, drawn from their A2UI v0.9.1 surface. The catalog is the node's
// (internal/services/asks/catalog.go): A2UI's basic Column, Text, ChoicePicker, TextField,
// DateTimeInput and Button, narrowed, and the node's own KeyValue. A Column root's first child is the
// TLDR Text. The node parsed every surface before it stored it, so this draws what is there and
// nothing more.
//
// A ready reply is a Button whose event is "reply" (asks.ReplyEvent) and whose context is its text:
// one tap posts it. The card keeps the surface's data model, seeded from its updateDataModel: each
// input writes its value at the path it binds, and nothing is sent until the owner presses a Button.
// The Button's action is then posted to POST /asks/{id}/answer as A2UI's client-to-server action, its
// context's {path} entries read from the data model; the node makes the one line the agent reads and
// sends a ready reply or what was written to the contact as the owner's own message. A notice, and an
// ask that is no longer open, offer nothing to press.
import { useState } from "react";
import { postForm } from "./api";
import { Badge, Button, Notice, Toolbar } from "./ui";
import { when, whenTitle } from "./words";

export type Ask = {
  id: string; kind: "ask" | "notice"; thread_id: string; contact: string; for_message_id: string;
  status: "open" | "answered" | "expired" | "withdrawn" | "posted"; tldr: string; surface: unknown;
  answer_text: string; created_at: number; updated_at: number; expires_at: number;
};

type Binding = { path: string };
type Comp = {
  id: string; component: string; children?: string[]; text?: string; variant?: string; label?: string;
  items?: { label: string; value: string }[]; options?: { label: string; value: string }[]; value?: Binding;
  enableDate?: boolean; enableTime?: boolean; min?: string; max?: string; child?: string;
  action?: { event: { name: string; context?: Record<string, unknown> } };
};
type Model = Record<string, unknown>;

/** The surface as the node stored it: its id, its components by id, and the data model it starts from. */
function surfaceOf(a: Ask): { id: string; comps: Map<string, Comp>; model: Model } {
  const comps = new Map<string, Comp>();
  let id = "";
  let model: Model = {};
  const msgs = Array.isArray(a.surface) ? a.surface : [];
  for (const m of msgs as Record<string, { surfaceId?: string; components?: Comp[]; value?: Model }>[]) {
    if (m.createSurface) id = m.createSurface.surfaceId ?? "";
    for (const c of m.updateComponents?.components ?? []) comps.set(c.id, c);
    if (m.updateDataModel?.value) model = m.updateDataModel.value;
  }
  return { id, comps, model };
}

/** The steps of an absolute JSON Pointer (RFC 6901). */
const steps = (pointer: string) => pointer.split("/").slice(1).map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));

/** What the data model holds at pointer. */
function read(model: Model, pointer: string): unknown {
  let cur: unknown = model;
  for (const s of steps(pointer)) cur = cur && typeof cur === "object" ? (cur as Record<string, unknown>)[s] : undefined;
  return cur;
}

/** The data model with v written at pointer, the objects on the way made as needed. */
function write(model: Model, pointer: string, v: unknown): Model {
  const out = structuredClone(model);
  const path = steps(pointer);
  let cur = out;
  for (const s of path.slice(0, -1)) {
    if (!cur[s] || typeof cur[s] !== "object") cur[s] = {};
    cur = cur[s] as Model;
  }
  cur[path[path.length - 1]] = v;
  return out;
}

const isBinding = (v: unknown): v is Binding => !!v && typeof v === "object" && typeof (v as Binding).path === "string";

/** A datetime-local value ("2026-10-22T14:00") with this browser's offset, as the node reads it (RFC 3339). */
function withOffset(v: string): string {
  const off = -new Date(v).getTimezoneOffset();
  const abs = Math.abs(off);
  const hh = String(Math.floor(abs / 60)).padStart(2, "0");
  const mm = String(abs % 60).padStart(2, "0");
  return `${v.length === 16 ? v + ":00" : v}${off >= 0 ? "+" : "-"}${hh}:${mm}`;
}

/** The event of a ready reply's Button (asks.ReplyEvent): its context is the text one tap sends. */
const REPLY = "reply";

const STATUS: Record<Ask["status"], string> = {
  open: "waiting on you", answered: "answered", expired: "expired unanswered", withdrawn: "withdrawn by your agent", posted: "done for you",
};

/**
 * One ask or notice as a card. `from` names the contact it is about, for the Needs you page; the
 * conversation leaves it out. `onAnswered` reloads what the page shows.
 */
export function AskCard({ ask, from, onAnswered }: { ask: Ask; from?: string; onAnswered: () => void }) {
  const surface = surfaceOf(ask);
  const comps = surface.comps;
  const root = comps.get("root");
  const [model, setModel] = useState<Model>(surface.model);
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  const live = ask.kind === "ask" && ask.status === "open";

  // The input bound at path, and what it holds there when the owner has not set it.
  const inputAt = (path: string) => [...comps.values()].find((c) => c.value?.path === path);
  const valueAt = (path: string) => read(model, path) ?? (inputAt(path)?.component === "ChoicePicker" ? [] : "");
  const empty = (v: unknown) => (Array.isArray(v) ? v.length === 0 : typeof v === "string" ? v.trim() === "" : v === undefined);
  const bind = (c: Comp, v: unknown) => { if (c.value) setModel((m) => write(m, c.value!.path, v)); };

  const press = async (b: Comp) => {
    const context: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(b.action?.event.context ?? {})) context[k] = isBinding(v) ? valueAt(v.path) : v;
    const message = JSON.stringify({
      version: "v0.9.1",
      action: { name: b.action?.event.name, surfaceId: surface.id, sourceComponentId: b.id, timestamp: new Date().toISOString(), context },
    });
    setBusy(b.id); setErr("");
    const r = await postForm(`/asks/${encodeURIComponent(ask.id)}/answer`, { message });
    setBusy("");
    if (!r.ok) {
      let detail = "";
      try { detail = (JSON.parse(r.body) as { detail?: string }).detail ?? ""; } catch { /* not JSON */ }
      setErr(detail || `The node answered ${r.status}.`);
    }
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
            {(c.items ?? []).map((r, i) => <div key={i}><dt>{r.label}</dt><dd>{r.value}</dd></div>)}
          </dl>
        );
      case "ChoicePicker": {
        const chosen = c.value ? (valueAt(c.value.path) as string[]) : [];
        return (
          <div key={id} className="ask-choice" role="group" aria-label={c.label ?? "Options"}>
            {c.label && <p className="muted">{c.label}</p>}
            <Toolbar>
              {(c.options ?? []).map((o) => (
                <Button key={o.value} variant="secondary" disabled={!live || busy !== ""} aria-pressed={chosen.includes(o.value)}
                  title="Sent to them as your reply when you press Send" onClick={() => bind(c, chosen.includes(o.value) ? [] : [o.value])}>{o.label}</Button>
              ))}
            </Toolbar>
          </div>
        );
      }
      case "TextField": {
        if (!live) return null;
        const v = c.value ? String(valueAt(c.value.path)) : "";
        return (
          <div key={id} className="ask-own">
            {c.variant === "longText"
              ? <textarea rows={3} aria-label={c.label} placeholder={c.label} value={v} onChange={(e) => bind(c, e.target.value)} />
              : <input type="text" aria-label={c.label} placeholder={c.label} value={v} onChange={(e) => bind(c, e.target.value)} />}
          </div>
        );
      }
      case "DateTimeInput": {
        if (!live) return null;
        const type = c.enableDate && c.enableTime ? "datetime-local" : c.enableDate ? "date" : "time";
        const size = type === "date" ? 10 : type === "time" ? 5 : 16;
        const v = c.value ? String(valueAt(c.value.path)).slice(0, size) : "";
        return (
          <div key={id} className="ask-own">
            <input type={type} aria-label={c.label ?? "Pick"} title={c.label} value={v} min={c.min?.slice(0, size)} max={c.max?.slice(0, size)}
              onChange={(e) => bind(c, type === "datetime-local" && e.target.value ? withOffset(e.target.value) : e.target.value)} />
          </div>
        );
      }
      case "Button": {
        const label = comps.get(c.child ?? "")?.text ?? c.id;
        // A ready reply: full width, its label wrapping, so a long one stays inside the card.
        if (c.action?.event.name === REPLY) {
          return (
            <div key={id} className="ask-reply">
              <Button variant={c.variant === "primary" ? "primary" : "secondary"} disabled={!live || busy !== ""} busy={busy === id}
                title="Sends this reply to them, as you, in one tap" onClick={() => press(c)}>{label}</Button>
            </div>
          );
        }
        const reads = Object.values(c.action?.event.context ?? {}).filter(isBinding);
        const sends = reads.some((b) => ["ChoicePicker", "TextField"].includes(inputAt(b.path)?.component ?? ""));
        const nothing = reads.length > 0 && reads.every((b) => empty(valueAt(b.path)));
        return (
          <Toolbar key={id}>
            <Button variant={c.variant === "primary" ? "primary" : "secondary"} disabled={!live || busy !== "" || nothing} busy={busy === id}
              title={sends ? "Sends your reply to them, as you" : "Answers your agent; nothing is sent to them"} onClick={() => press(c)}>{label}</Button>
          </Toolbar>
        );
      }
    }
    return null;
  };

  return (
    <article className={"ask-card " + (ask.kind === "notice" ? "told" : "asked") + (live ? " live" : "")} aria-label={ask.kind === "ask" ? "Your agent asks" : "Your agent did"}>
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
