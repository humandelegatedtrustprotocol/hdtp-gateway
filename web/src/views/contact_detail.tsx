// One contact: the name you use for them, what they may do here, how far
// their words are trusted, their card re-fetched when you ask, and the way
// out. Every change posts straight to the node and the page re-reads itself
// afterwards.
import { useCallback, useEffect, useState } from "react";
import { getJSON, postForm } from "../api";
import { navigate } from "../router";
import { Avatar, Badge, Button, CsrfFields, EmptyState, Field, Notice, PLUMBING_TOOLS, PageHeader, Readout, Section, permLabel, toolLabel, type Note } from "../ui";

type PermRow = { name: string; on: boolean };
type Data = {
  fingerprint: string; display_name: string; petname: string; status: string;
  preset: string; trust: string; permissions: PermRow[]; their_permissions: string[] | null; presets: string[];
};

// What "Refresh now" found, as the node names it (node.RefreshContact). Unreachable and refused
// both leave the pin exactly as it was; refused is the one worth a second look, so it says why.
function refreshNote(outcome: string, why: string): Note {
  switch (outcome) {
    case "unchanged": return { kind: "ok", text: "Nothing has changed: they serve the card you already hold." };
    case "updated": return { kind: "ok", text: "Their card has changed, and the new one is saved." };
    case "renewed": return { kind: "ok", text: "They have renewed their certificate. The new one is signed by the same identity and is saved." };
    case "unreachable": return { kind: "warn", text: "Their node did not answer. Nothing about this contact has changed." };
    case "refused": return { kind: "err", text: `Their node answered, and what it sent did not verify${why ? ` (${why})` : ""}. Nothing about this contact has changed.` };
    default: return { kind: "err", text: "could not refresh this contact" };
  }
}

const PARENT = { to: "/contacts", label: "People" };
const TRUST: [string, string][] = [["messages_only", "Messages only"], ["may_instruct", "May instruct"]];

export function ContactDetail({ fpr }: { fpr: string }) {
  const [d, setD] = useState<Data | null>(null);
  const [note, setNote] = useState<Note | null>(null);
  const [petname, setPetname] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  // What their node says your agent may call there, asked now. The stored
  // grants are a snapshot taken when you paired and are never refreshed, so a
  // capability granted since — an integration, say — would never appear here.
  const [live, setLive] = useState<{ state: "loading" | "ok" | "off"; tools: string[] }>({ state: "loading", tools: [] });
  const load = useCallback(
    () => getJSON<Data>(`/api/contacts/${encodeURIComponent(fpr)}`).then((x) => { setD(x); setPetname(null); }).catch(() => {}),
    [fpr],
  );
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    let alive = true;
    setLive({ state: "loading", tools: [] });
    getJSON<{ tools?: { name: string }[] }>(`/api/contacts/${encodeURIComponent(fpr)}/tools`)
      .then((r) => { if (alive) setLive({ state: "ok", tools: (r.tools ?? []).map((t) => t.name).filter((n) => !PLUMBING_TOOLS.has(n)) }); })
      .catch(() => { if (alive) setLive({ state: "off", tools: [] }); });
    return () => { alive = false; };
  }, [fpr]);
  if (!d) return <main><PageHeader parent={PARENT} title="Contact" /><EmptyState loading /></main>;
  const base = `/contacts/${encodeURIComponent(fpr)}`;
  const shownName = d.petname || d.display_name || d.fingerprint;
  const trust = d.trust || "messages_only";
  const theirs = d.their_permissions ?? [];

  const savePerms = async (form: HTMLFormElement) => {
    const data = new FormData(form);
    const body = new URLSearchParams();
    for (const [k, v] of data.entries()) body.append(k, String(v));
    // postForm sets one value per key; permissions are a multi-select, so this
    // form posts itself and only borrows the csrf/account plumbing.
    const r = await fetch(`${base}/permissions`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    setNote(r.ok ? { kind: "ok", text: "Saved." } : { kind: "err", text: "could not save permissions" });
    load();
  };
  const saveName = async () => {
    await postForm(`${base}/petname`, { petname: (petname ?? d.petname).trim() });
    setNote({ kind: "ok", text: "Name saved." });
    load();
  };
  const setTrust = async (t: string) => {
    await postForm(`${base}/trust`, { trust: t });
    load();
  };
  const refresh = async () => {
    setRefreshing(true);
    const r = await postForm(`${base}/refresh`, {});
    setRefreshing(false);
    let found: { outcome?: string; why?: string } = {};
    try { found = r.ok ? JSON.parse(r.body) : {}; } catch { /* not JSON: the default note says so */ }
    setNote(refreshNote(found.outcome ?? "", found.why ?? ""));
    load();
  };
  const remove = async () => {
    await postForm(`${base}/remove`, {});
    navigate("/contacts");
  };

  return (
    <main>
      <PageHeader parent={PARENT} leading={<Avatar name={shownName} size="lg" />} title={shownName}
        meta={<><Badge status={d.status} /><Badge>{d.preset || "custom"}</Badge><Badge>{trust.replace(/_/g, " ")}</Badge></>}
        sub={<><Readout value={d.fingerprint} copy />{d.petname && <> · they call themselves “{d.display_name}”</>}</>} />
      {note && <Notice kind={note.kind}>{note.text}</Notice>}

      <Section title="Your name for them"
        description="Optional, and yours alone — they are never told, and no contact can change it. Leave it empty to use the name on their card."
        footer={<Button onClick={saveName}>Save name</Button>}>
        <Field label="Name">
          <input type="text" maxLength={64} placeholder={d.display_name} value={petname ?? d.petname} onChange={(e) => setPetname(e.target.value)} />
        </Field>
      </Section>

      <PermForm d={d} onSubmit={savePerms} />

      <Section title="Trust" description="Whether things they send may INSTRUCT your agent, or are only messages to read.">
        {TRUST.map(([t, label]) => (
          <Field key={t} check label={label} help={t}>
            <input type="radio" name="trust" value={t} checked={trust === t} onChange={() => setTrust(t)} />
          </Field>
        ))}
      </Section>

      <Section title="What they let your agent do"
        description={live.state === "ok"
          ? "Asked of their node just now — this is what your agent may call there."
          : live.state === "loading"
            ? "Asking their node…"
            : "Their node could not be reached, so this is what they granted when you paired — it may be out of date."}>
        {live.state === "ok"
          ? (live.tools.length > 0
            ? <span className="rowline">{live.tools.map((t) => <Badge key={t} mono title={t}>{toolLabel(t)}</Badge>)}</span>
            : <p className="muted">Nothing beyond the plumbing every contact carries.</p>)
          : live.state === "loading"
            ? <EmptyState loading />
            : theirs.length > 0
              ? <span className="rowline">{theirs.map((p) => <Badge key={p} mono>{p}</Badge>)}</span>
              : <p className="muted">Nothing recorded when you paired.</p>}
      </Section>

      <Section title="Their card"
        description="Your node learns a renewed certificate or a changed name the next time the two of you talk, and checks nothing in the background. Ask now if you want it sooner: this reaches this one contact and nobody else. Who they are and where they answer cannot change this way."
        footer={<Button variant="secondary" busy={refreshing} onClick={refresh}>Refresh now</Button>} />

      <Section tone="danger" title="Remove contact"
        description="Deletes the pin, so they can reach nothing. Local by design — they are not told (PACT §6.2)."
        footer={<Button variant="danger" confirm={`Remove ${shownName}? Their pin is deleted and they lose access. This is local: it does not tell them.`} onClick={remove}>Remove contact</Button>} />
    </main>
  );
}

function PermForm({ d, onSubmit }: { d: Data; onSubmit: (f: HTMLFormElement) => void }) {
  return (
    <form onSubmit={(e) => { e.preventDefault(); onSubmit(e.currentTarget); }}>
      <Section title="What they may do here" footer={<Button type="submit">Save</Button>}>
        <CsrfFields />
        {d.permissions.map((p) => (
          <Field key={p.name} check label={permLabel(p.name)} help={p.name} mono>
            <input type="checkbox" name="perm" value={p.name} defaultChecked={p.on} />
          </Field>
        ))}
        <div className="fields">
          <Field label="…or apply a preset wholesale"
            help="A preset replaces the switches above with its bundle. Custom keeps the switches exactly as you set them — a hand-tuned grant carries no preset name.">
            <select name="preset" defaultValue={d.preset}>
              <option value="">custom (no preset)</option>
              {d.presets.map((p) => <option key={p}>{p}</option>)}
            </select>
          </Field>
          <Field check label="apply preset">
            <input type="checkbox" name="apply_preset" value="1" />
          </Field>
        </div>
      </Section>
    </form>
  );
}
