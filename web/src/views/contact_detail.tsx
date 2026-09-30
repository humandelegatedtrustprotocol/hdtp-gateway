// One contact: the name you use for them, what they may do here, how far
// their words are trusted, their card re-fetched when you ask, and the way
// out. Every change posts straight to the node and the page re-reads itself
// afterwards.
import { useCallback, useEffect, useState } from "react";
import { ApiError, failureOf, getJSON, postForm } from "../api";
import { navigate } from "../router";
import { Avatar, Badge, Button, CsrfFields, EmptyState, Failed, Field, Notice, PLUMBING_TOOLS, PageHeader, Section, permLabel, toolLabel, trustWord, type Note } from "../ui";
import { IdText } from "../glance";

type PermRow = { name: string; on: boolean };
type Data = {
  fingerprint: string; display_name: string; petname: string; status: string;
  // whether they were ever a contact: an unblock restores them, or forgets a rejected request
  was_contact: boolean;
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
const TRUST = ["messages_only", "may_instruct"];

export function ContactDetail({ fpr }: { fpr: string }) {
  const [d, setD] = useState<Data | null>(null);
  const [note, setNote] = useState<Note | null>(null);
  const [petname, setPetname] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  // What their node says your agent may call there, asked now. The stored
  // grants are a snapshot taken when you paired and are never refreshed, so a
  // capability granted since — an integration, say — would never appear here.
  const [live, setLive] = useState<{ state: "loading" | "ok" | "off"; tools: string[] }>({ state: "loading", tools: [] });
  // A read that failed is said as a failure, and a contact this node does not hold as that: neither is
  // left on the loading box.
  const [err, setErr] = useState<{ missing: boolean; text: string } | null>(null);
  const load = useCallback(
    () => getJSON<Data>(`/api/contacts/${encodeURIComponent(fpr)}`).then((x) => { setD(x); setPetname(null); setErr(null); })
      .catch((e) => setErr({ missing: e instanceof ApiError && e.status === 404, text: failureOf(e) })),
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
  if (!d) {
    return (
      <main>
        <PageHeader parent={PARENT} title="Contact" />
        {!err ? <EmptyState loading />
          : err.missing ? <EmptyState title="No such contact" action={<Button variant="secondary" to="/contacts">Back to People</Button>}>This node holds no contact with that fingerprint.</EmptyState>
          : <Failed what="this contact" error={err.text} retry={load} />}
      </main>
    );
  }
  const base = `/contacts/${encodeURIComponent(fpr)}`;
  // The name you gave them, else theirs; a contact with neither is "Unnamed contact", and its
  // fingerprint is said once, under it, short and copyable.
  const named = d.petname || d.display_name;
  const shownName = named || "this contact";
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
  // Block, unblock and remove answer with a redirect that carries what happened (`added`) or
  // why not (`err`). A row that is gone afterwards is shown on People, where the owner lands.
  // `gone`: the row does not survive this, so the owner is taken back to People.
  const act = async (path: string, gone: boolean) => {
    const r = await postForm(path, {});
    const err = r.url.searchParams.get("err") || (!r.ok ? r.body || "that did not go through" : "");
    const said = r.url.searchParams.get("added") ?? "";
    if (err) { setNote({ kind: "err", text: err }); return; }
    if (gone) {
      navigate(`/contacts?notice=${encodeURIComponent(said)}`);
      return;
    }
    setNote({ kind: "ok", text: said });
    load();
  };

  return (
    <main>
      <PageHeader parent={PARENT} leading={<Avatar name={named} size="lg" />} title={named || <span className="unnamed">Unnamed contact</span>}
        meta={<><Badge status={d.status} /><Badge>{d.preset || "custom"}</Badge><Badge title={trust}>{trustWord(trust)}</Badge></>}
        sub={<><IdText id={d.fingerprint} />{d.petname && d.display_name && <> · they call themselves “{d.display_name}”</>}</>} />
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
        {TRUST.map((t) => (
          <Field key={t} check label={<span title={t}>{trustWord(t)}</span>}>
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
            ? <span className="rowline">{live.tools.map((t) => <Badge key={t} title={t}>{toolLabel(t)}</Badge>)}</span>
            : <p className="muted">Nothing beyond the plumbing every contact carries.</p>)
          : live.state === "loading"
            ? <EmptyState loading />
            : theirs.length > 0
              ? <span className="rowline">{theirs.map((p) => <Badge key={p} title={p}>{permLabel(p)}</Badge>)}</span>
              : <p className="muted">Nothing recorded when you paired.</p>}
      </Section>

      <Section title="Their card"
        description="Your node learns a renewed certificate or a changed name the next time the two of you talk, and checks nothing in the background. Ask now if you want it sooner: this reaches this one contact and nobody else. Who they are and where they answer cannot change this way."
        footer={<Button variant="secondary" busy={refreshing} onClick={refresh}>Refresh now</Button>} />

      {d.status === "blocked"
        ? <Section title="Unblock"
            description={d.was_contact
              ? "They come back as a contact, with the permissions and trust they had. They are not told, as they were not told of the block."
              : "They were never a contact: this is a request you rejected, or an approach of yours they declined. Unblocking forgets them, so they are a stranger again and may ask again."}
            footer={<Button variant="secondary" onClick={() => act(`${base}/unblock`, !d.was_contact)}>Unblock</Button>} />
        : <Section tone="danger" title="Block"
            description="Silent: they are not told, and from now on they see exactly what a stranger sees and reach nothing. You can unblock them."
            footer={<Button variant="danger" confirm={`Block ${shownName}? They are not told.`} onClick={() => act(`${base}/block`, false)}>Block</Button>} />}

      <Section tone="danger" title="Remove contact"
        description="Deletes the pin, so they can reach nothing. An active contact is told, so their node lets you go too; the removal stands here even if they cannot be reached. A request, or a blocked contact, is removed without telling them."
        footer={<Button variant="danger" confirm={d.status === "active"
          ? `Remove ${shownName}? Their node is told, and their pin is deleted here even if it cannot be reached.`
          : `Remove ${shownName}? Their pin is deleted. They are not told.`} onClick={() => act(`${base}/remove`, true)}>Remove contact</Button>} />
    </main>
  );
}

function PermForm({ d, onSubmit }: { d: Data; onSubmit: (f: HTMLFormElement) => void }) {
  return (
    <form onSubmit={(e) => { e.preventDefault(); onSubmit(e.currentTarget); }}>
      <Section title="What they may do here" footer={<Button type="submit">Save</Button>}>
        <CsrfFields />
        {d.permissions.map((p) => (
          <Field key={p.name} check label={<span title={p.name}>{permLabel(p.name)}</span>}>
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
