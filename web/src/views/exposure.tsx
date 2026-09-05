// The exposure picker: which upstream tools peers may reach, under which names,
// via which recipe. Write-capable tools are flagged and take an acknowledgment —
// the gate itself is server-side; this form just carries the checkbox.
//
// Selections live in state, not in the DOM: the list is searchable and
// filterable, and a row that is filtered out must still be saved as chosen.
import { useCallback, useEffect, useMemo, useState } from "react";
import { csrf, currentAccount, getJSON } from "../api";
import { Badge, Button, EmptyState, Field, List, ListRow, Notice, PageHeader, Section, Tabs, Toolbar, type Note } from "../ui";

type Tool = { name: string; description: string; risk: { write?: boolean; reasons?: string[] }; suggestion: string; exposed: boolean };
type Entry = { tool: string; exposed_name: string; mode: string; recipe?: string; fallback?: string; stale?: boolean };
type Data = { integration: { ID: string; Slug: string }; catalog: { Version: number }; tools: Tool[] | null; entries: Entry[] | null; has_stale: boolean };
type Choice = { on: boolean; name: string; mode: string; recipe: string };
type Filter = "all" | "read" | "write" | "exposed";

const PARENT = { to: "/integrations", label: "Integrations" };

// The same shape the node's SnakeName gives an exposed tool.
const snake = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");

export function Exposure({ id }: { id: string }) {
  const [d, setD] = useState<Data | null>(null);
  const [err, setErr] = useState("");
  const [note, setNote] = useState<Note | null>(null);
  const [choices, setChoices] = useState<Record<string, Choice>>({});
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [ack, setAck] = useState(false);
  const [saving, setSaving] = useState(false);
  const [reconfirming, setReconfirming] = useState(false);

  const load = useCallback(
    () => getJSON<Data>(`/api/integrations/${encodeURIComponent(id)}/exposure`)
      .then((data) => {
        setD(data);
        const next: Record<string, Choice> = {};
        for (const t of data.tools ?? []) {
          const e = (data.entries ?? []).find((x) => x.tool === t.name);
          // SPEC §6.5: the slug prefixes exposed tool names, which is what the
          // core applies when a name is left empty and what the owner MCP's
          // set_exposure publishes. The picker used to pre-fill the bare tool
          // name, so the same tool was called one thing when exposed here and
          // another when exposed by the agent — two surfaces, two names.
          next[t.name] = { on: t.exposed, name: e?.exposed_name || snake(data.integration.Slug + "_" + t.name), mode: e?.mode || "passthrough", recipe: e?.recipe || t.suggestion || "" };
        }
        setChoices(next);
      })
      .catch((e) => setErr(e.status === 409 ? "No catalog snapshot yet — connect first." : String(e))),
    [id],
  );
  useEffect(() => { load(); }, [load]);

  const tools = useMemo(() => d?.tools ?? [], [d]);
  const chosen = tools.filter((t) => choices[t.name]?.on);
  const chosenWrite = chosen.filter((t) => t.risk.write);
  const readOnly = tools.filter((t) => !t.risk.write);
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return tools.filter((t) => {
      if (filter === "read" && t.risk.write) return false;
      if (filter === "write" && !t.risk.write) return false;
      if (filter === "exposed" && !choices[t.name]?.on) return false;
      return !needle || t.name.toLowerCase().includes(needle) || t.description.toLowerCase().includes(needle);
    });
  }, [tools, q, filter, choices]);

  if (err) return <main><PageHeader parent={PARENT} title="Exposure" /><Notice kind="err">{err}</Notice></main>;
  if (!d) return <main><PageHeader parent={PARENT} title="Exposure" /><EmptyState loading /></main>;

  const set = (name: string, patch: Partial<Choice>) => setChoices((c) => ({ ...c, [name]: { ...c[name], ...patch } }));
  const setMany = (names: string[], on: boolean) => setChoices((c) => { const n = { ...c }; for (const x of names) n[x] = { ...n[x], on }; return n; });
  const post = async (path: string, fields: Record<string, string>) => fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Pact-Csrf": csrf() },
    body: new URLSearchParams({ csrf: csrf(), account: currentAccount(), ...fields }).toString(),
  });
  const reconfirm = async () => {
    setReconfirming(true);
    try { await post(`/integrations/${encodeURIComponent(id)}/reconfirm`, {}); load(); } finally { setReconfirming(false); }
  };
  const save = async () => {
    setSaving(true);
    const fields: Record<string, string> = {};
    for (const t of chosen) {
      const c = choices[t.name];
      fields["expose_" + t.name] = "1";
      fields["name_" + t.name] = c.name.trim() || t.name;
      fields["mode_" + t.name] = c.mode;
      fields["recipe_" + t.name] = c.recipe;
    }
    if (ack) fields.ack = "1";
    try {
      const r = await post(`/integrations/${encodeURIComponent(id)}/exposure`, fields);
      setNote(r.ok ? { kind: "ok", text: `Saved — ${chosen.length} tool${chosen.length === 1 ? "" : "s"} exposed.` } : { kind: "err", text: await r.text() });
      if (r.ok) { setAck(false); load(); }
    } finally { setSaving(false); }
  };

  return (
    <main>
      <PageHeader parent={PARENT} title={<>Exposure <span className="muted">·</span> {d.integration.Slug}</>}
        meta={<Badge mono>catalog v{d.catalog.Version}</Badge>}
        sub={<>Nothing is exposed by default. Expose only what the use-case needs, and prefer the <strong>narrowest credential that works</strong>. Read-only tools are the safe default; write-capable ones let contacts change things upstream.</>} />

      {d.has_stale && (
        <Notice kind="warn" action={<Button variant="secondary" busy={reconfirming} onClick={reconfirm}>Reconfirm all stale</Button>}>
          Some exposures are STALE — the upstream tool changed or vanished under them; they serve nothing until reconfirmed.
        </Notice>
      )}

      <Toolbar end={<><Button variant="secondary" onClick={() => setMany(readOnly.map((t) => t.name), true)}>Expose all read-only</Button><Button variant="quiet" onClick={() => setMany(tools.map((t) => t.name), false)}>Clear</Button></>}>
        <input type="search" placeholder="Search tools…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search tools" />
      </Toolbar>
      <Tabs active={filter} onSelect={(k) => setFilter(k as Filter)} items={[
        { key: "all", label: "All", count: tools.length },
        { key: "read", label: "Read-only", count: readOnly.length },
        { key: "write", label: "Write-capable", count: tools.length - readOnly.length },
        { key: "exposed", label: "Exposed", count: chosen.length },
      ]} />

      {shown.length === 0 ? <EmptyState title="No tools match" /> : (
        <List aria-label="Upstream tools">
          {shown.map((t) => {
            const c = choices[t.name];
            const stale = (d.entries ?? []).find((e) => e.tool === t.name)?.stale;
            return (
              <ListRow key={t.name} selected={c.on}
                leading={<input type="checkbox" checked={c.on} onChange={(e) => set(t.name, { on: e.target.checked })} aria-label={`Expose ${t.name}`} />}
                title={<><code>{t.name}</code><Badge tone={t.risk.write ? "warn" : "ok"}>{t.risk.write ? "write" : "read"}</Badge>{stale && <Badge tone="bad">stale</Badge>}{c.on && c.name !== t.name && <span className="muted">as <code>{c.name}</code></span>}</>}
                description={t.description}
                trailing={c.on && <Button variant="link" onClick={() => setOpen((o) => ({ ...o, [t.name]: !o[t.name] }))}>{open[t.name] ? "hide options" : "options"}</Button>}>
                {c.on && open[t.name] && (
                  <div className="fields">
                    <Field label="Expose as"><input type="text" value={c.name} onChange={(e) => set(t.name, { name: e.target.value })} /></Field>
                    <Field label="Mode">
                      <select value={c.mode} onChange={(e) => set(t.name, { mode: e.target.value })}>
                        <option>passthrough</option><option>mapped</option><option>agent</option>
                      </select>
                    </Field>
                    <Field label="Recipe"><input type="text" value={c.recipe} onChange={(e) => set(t.name, { recipe: e.target.value })} placeholder="optional" /></Field>
                    {t.risk.reasons && t.risk.reasons.length > 0 && <p className="help span">Flagged write-capable because: {t.risk.reasons.join("; ")}</p>}
                  </div>
                )}
              </ListRow>
            );
          })}
        </List>
      )}

      <Section sticky
        footer={<><Button busy={saving} disabled={chosenWrite.length > 0 && !ack} onClick={save}>Save exposure</Button></>}>
        <p><strong>{chosen.length}</strong> of {tools.length} exposed{chosenWrite.length > 0 && <> · <Badge tone="warn">{chosenWrite.length} write-capable</Badge></>}</p>
        {note && <Notice kind={note.kind}>{note.text}</Notice>}
        {chosenWrite.length > 0 && (
          <Notice kind="warn">
            <Field check label="I understand the checked write-capable tools let contacts CHANGE things upstream, and I have verified this server. The acknowledgment is recorded.">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
            </Field>
          </Notice>
        )}
      </Section>
    </main>
  );
}
