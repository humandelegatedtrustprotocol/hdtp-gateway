import { useCallback, useEffect, useState } from "react";
import { PresetGrid, type GridRow } from "../preset_grid";
import { presetColumns, samePerms, withPerm } from "../presets";
import { csrf, currentAccount, failureOf, getJSON } from "../api";
import { Actions, Badge, Button, CsrfFields, EmptyState, Failed, Field, HelpTip, List, ListRow, Notice, PageHeader, Section, Toolbar, permLabel } from "../ui";

type SettingRow = {
  key: string; value: string; locked: boolean; reason: string; restart: boolean;
  kind: string; options: string[] | null; label: string; help: string; pending: boolean; running: string;
};
type StorageRow = { account_id: string; label: string; quota_gib: number; retention_days: number; request_expiry_days: number };
type AdapterSetting = { key: string; secret: boolean; set: boolean };
type Data = {
  show_storage: boolean; storage: StorageRow[] | null;
  show_presets: boolean; presets: PresetRow[] | null; preset_perms: string[] | null;
  show_pair: boolean; paired: Record<string, boolean> | null;
  accounts: { id: string; label: string }[] | null;
  notice: string; error: boolean;
  reach: SettingRow[] | null; security: SettingRow[] | null;
  adapter_settings: AdapterSetting[] | null; adapters: string[] | null;
  show_probe: boolean; probe_verdict: string; probe_detail: string;
};

export function Settings() {
  const [d, setD] = useState<Data | null>(null);
  const [err, setErr] = useState("");
  const load = useCallback(() => getJSON<Data>("/api/settings").then((x) => { setD(x); setErr(""); }).catch((e) => setErr(failureOf(e))), []);
  useEffect(() => { load(); }, [load]);
  const header = <PageHeader title="Settings" />;
  if (!d) return <main>{header}{err ? <Failed what="this node's settings" error={err} retry={load} /> : <EmptyState loading />}</main>;

  // Settings posts itself: the knob KEYS are the field names, and unchecked
  // bools must still submit (the handler treats presence as the signal for
  // non-bools and reads bools directly), so a plain form mirrors the old page.
  const submitForm = async (form: HTMLFormElement, path: string): Promise<Data | null> => {
    const body = new URLSearchParams();
    for (const [k, v] of new FormData(form).entries()) body.append(k, String(v));
    const r = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    try {
      const j = (await r.json()) as Data;
      if (j && j.reach !== undefined) { setD(j); return j; }
    } catch { /* fall through */ }
    load();
    return null;
  };

  return (
    <main>
      {header}
      {d.notice && <Notice kind={d.error ? "err" : "ok"}>{d.notice}</Notice>}
      {d.probe_verdict && (
        <Notice kind={d.probe_verdict === "ok" ? "ok" : "warn"}>
          Probe: {d.probe_verdict}{d.probe_detail && <> — {d.probe_detail}</>}
        </Notice>
      )}
      <form onSubmit={(e) => { e.preventDefault(); submitForm(e.currentTarget, "/settings"); }}>
        <CsrfFields />
        <Group title="Reachability" rows={d.reach ?? []} />
        <Group title="Security posture" rows={d.security ?? []} />
        <Actions foot>
          {d.show_probe && (
            <Button variant="secondary" onClick={async (e) => { await submitForm((e.currentTarget as HTMLButtonElement).form!, "/settings/probe"); }}>
              Probe reachability
            </Button>
          )}
          <Button type="submit">Save settings</Button>
        </Actions>
      </form>

      {(d.adapter_settings ?? []).length > 0 && (
        <Section title="Tunnel adapter settings" description="Secret values are stored sealed and never shown again.">
          <List aria-label="Tunnel adapter settings">
            {(d.adapter_settings ?? []).map((a) => (
              <AdapterRow key={a.key} a={a} onSaved={load} />
            ))}
          </List>
        </Section>
      )}

      {d.show_pair && <Pairing d={d} submit={submitForm} />}

      {d.show_storage && (
        <Section title="Storage & retention">
          {(d.storage ?? []).map((s) => <StorageForm key={s.account_id} s={s} onSaved={load} />)}
        </Section>
      )}

      {d.show_presets && <Presets d={d} onSaved={(j) => (j ? setD(j) : load())} />}
    </main>
  );
}

function Group({ title, rows }: { title: string; rows: SettingRow[] }) {
  if (rows.length === 0) return null;
  return (
    <Section title={title}>
      {rows.map((r) => {
        // What the knob's state is stays in view (locked, a restart owed, a save not yet running);
        // what the knob is for, and why it is locked, is behind its `?`.
        const help = [
          r.locked && "locked",
          r.restart && "applies on restart",
          r.pending && `saved; node still runs “${r.running}”`,
        ].filter(Boolean).join(" · ");
        const tip = [r.help, r.locked && `Locked: ${r.reason}`].filter(Boolean).join(" ");
        const control = r.kind === "bool" ? (
          <input type="checkbox" name={r.key} value="1" defaultChecked={r.value === "true" || r.value === "1"} disabled={r.locked} />
        ) : r.kind === "select" ? (
          <select name={r.key} defaultValue={r.value} disabled={r.locked}>
            {(r.options ?? []).map((o) => <option key={o}>{o}</option>)}
          </select>
        ) : (
          <input type="text" name={r.key} defaultValue={r.value} disabled={r.locked} />
        );
        return (
          <Field key={r.key} id={r.key} label={r.label || r.key} help={help || undefined} tip={tip || undefined} check={r.kind === "bool"}>
            {control}
          </Field>
        );
      })}
    </Section>
  );
}

function AdapterRow({ a, onSaved }: { a: AdapterSetting; onSaved: () => void }) {
  const [v, setV] = useState("");
  const save = async () => {
    const body = new URLSearchParams({ csrf: csrf(), account: currentAccount(), key: a.key, value: v });
    await fetch("/settings/adapter", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: body.toString() });
    setV("");
    onSaved();
  };
  return (
    <ListRow
      title={<code>{a.key}</code>}
      meta={<><Badge status={a.set ? "set" : "empty"} />{a.secret && <Badge>secret</Badge>}</>}
      trailing={<Toolbar className="field-save">
        <input aria-label={a.key} type={a.secret ? "password" : "text"} value={v} onChange={(e) => setV(e.target.value)} placeholder="new value" />
        <Button variant="quiet" onClick={save}>Save</Button>
      </Toolbar>}
    />
  );
}

type PresetRow = { name: string; perms: string[] };

// The presets as one grid (preset_grid.tsx, shared with PACT Cloud): a row per preset, a column per
// permission. The node saves a preset whole (`POST /settings/presets`, its name and every `perm`), so
// a row's switches are a draft until its Save; the last row names and adds a new one.
function Presets({ d, onSaved }: { d: Data; onSaved: (j: Data | null) => void }) {
  const presets = d.presets ?? [];
  const columns = presetColumns(d.preset_perms ?? [], presets);
  const [drafts, setDrafts] = useState<Record<string, string[]>>({});
  const [newName, setNewName] = useState("");
  const [newPerms, setNewPerms] = useState<string[]>([]);
  const [busy, setBusy] = useState("");
  const post = async (path: string, body: URLSearchParams) => {
    const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: body.toString() });
    try {
      const j = (await r.json()) as Data;
      if (j && j.reach !== undefined) return j;
    } catch { /* not the page's answer: read it again */ }
    return null;
  };
  const save = async (name: string, perms: readonly string[], isNew: boolean) => {
    setBusy(isNew ? "" : name);
    const body = new URLSearchParams({ csrf: csrf(), name });
    for (const p of perms) body.append("perm", p);
    const j = await post("/settings/presets", body);
    setBusy("");
    if (isNew) { if (j && !j.error) { setNewName(""); setNewPerms([]); } }
    else setDrafts(({ [name]: _, ...rest }) => rest);
    onSaved(j);
  };
  const del = async (name: string) => {
    const j = await post(`/settings/presets/${encodeURIComponent(name)}/delete`, new URLSearchParams({ csrf: csrf() }));
    setDrafts(({ [name]: _, ...rest }) => rest);
    onSaved(j);
  };
  const NEW = "New preset";
  const rows: GridRow[] = presets.map((p) => {
    const perms = drafts[p.name] ?? p.perms;
    const changed = !samePerms(perms, p.perms);
    return {
      name: p.name, perms,
      actions: (
        <Actions>
          <Button variant="quiet" icon="trash" confirm={`Delete the ${p.name} preset? Contacts wearing it keep their switches.`} onClick={() => del(p.name)}>Delete</Button>
          <Button onClick={() => save(p.name, perms, false)} busy={busy === p.name} disabled={!changed}>Save</Button>
        </Actions>
      ),
    };
  });
  rows.push({
    name: NEW, perms: newPerms,
    title: <input className="pg-new" aria-label="New preset's name" placeholder="new preset" title="a-z, 0-9, dash, underscore"
      value={newName} onChange={(e) => setNewName(e.target.value)} />,
    actions: <Actions><Button onClick={() => save(newName.trim(), newPerms, true)} disabled={!newName.trim()}>Add preset</Button></Actions>,
  });
  const toggle = (name: string, perm: string, on: boolean) => {
    if (name === NEW) { setNewPerms((x) => withPerm(x, perm, on)); return; }
    const saved = presets.find((p) => p.name === name)?.perms ?? [];
    setDrafts((all) => ({ ...all, [name]: withPerm(all[name] ?? saved, perm, on) }));
  };
  return (
    <Section title="Contact presets"
      description={<>The bundles offered when you approve someone.<HelpTip label="About contact presets">
        Tick what each preset grants, then Save its row. Editing applies from the next approval or apply;
        grants already made keep their switches. Deleting the last preset restores the documented four.
      </HelpTip></>}>
      <PresetGrid aria-label="Contact presets" rows={rows} columns={columns} label={permLabel} onToggle={toggle} />
    </Section>
  );
}

function StorageForm({ s, onSaved }: { s: StorageRow; onSaved: () => void }) {
  const [quota, setQuota] = useState(String(s.quota_gib));
  const [days, setDays] = useState(String(s.retention_days));
  const [expiry, setExpiry] = useState(String(s.request_expiry_days));
  const save = async () => {
    const body = new URLSearchParams({ csrf: csrf(), account: s.account_id, quota_gib: quota, retention_days: days, request_expiry_days: expiry });
    await fetch("/settings/storage", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: body.toString() });
    onSaved();
  };
  return (
    <>
      <h3>{s.label}</h3>
      <div className="fields">
        <Field label="Quota GiB"><input type="number" min={0} value={quota} onChange={(e) => setQuota(e.target.value)} /></Field>
        <Field label="Retention days" help="0 = keep forever"><input type="number" min={0} value={days} onChange={(e) => setDays(e.target.value)} /></Field>
        <Field label="Requests expire after (days)" help="1–365; 30 by default" tip="A contact request nobody answers, theirs or yours, is dropped after this many days.">
          <input type="number" min={1} max={365} value={expiry} onChange={(e) => setExpiry(e.target.value)} />
        </Field>
      </div>
      <Actions foot><Button onClick={save}>Save</Button></Actions>
    </>
  );
}

// Pairing this node with an ingress on your own domain (SPEC §10). The API has
// always sent `show_pair` and `paired`; nothing read them, so the whole flow was
// portal-shaped and portal-unreachable.
//
// The fingerprint field is the part that matters. Leave it empty and the pairing
// is trust-on-first-use: whatever key answers becomes the pinned one, and the
// node reports it back for you to check against what you were given out of band.
// Fill it in and a mismatch is refused outright.
function Pairing({ d, submit }: { d: Data; submit: (f: HTMLFormElement, p: string) => Promise<Data | null> }) {
  const paired = Object.entries(d.paired ?? {}).filter(([, v]) => v);
  const many = (d.accounts ?? []).length > 1;
  return (
    <Section title="Own-domain ingress"
      description={<>
        Be reached at a name on your own domain.
        <HelpTip label="About own-domain ingress">
          Pair with an ingress you run on your own domain, so people reach you at a name you own rather
          than a tunnel provider's. You need the ingress's pairing URL and a one-time token from it
          (<code>pact-gateway ingress token</code> on that host).
        </HelpTip>
      </>}>
      {paired.length > 0 && (
        <List aria-label="Paired ingresses">
          {paired.map(([adapter]) => (
            <ListRow key={adapter} title={adapter} meta={<Badge tone="ok">paired</Badge>}
              trailing={
                <form onSubmit={(e) => { e.preventDefault(); submit(e.currentTarget, "/settings/unpair"); }}>
                  <CsrfFields />
                  <input type="hidden" name="adapter" value={adapter} />
                  <Toolbar><Button variant="quiet" type="submit">Unpair</Button></Toolbar>
                </form>
              } />
          ))}
        </List>
      )}
      <form onSubmit={(e) => { e.preventDefault(); submit(e.currentTarget, "/settings/pair"); }}>
        <input type="hidden" name="csrf" value={csrf()} />
        <Field label="Ingress pairing URL" id="pair_url"><input name="pair_url" type="text" placeholder="https://ingress.example.com/pair" /></Field>
        <Field label="One-time token" id="token"><input name="token" type="text" /></Field>
        <Field label="Name you want under that domain" id="subdomain"><input name="subdomain" type="text" placeholder="alice" /></Field>
        <Field label="Mode" id="mode">
          <select name="mode" defaultValue="passthrough">
            <option value="passthrough">passthrough — the ingress forwards raw TLS (end-to-end mTLS)</option>
            <option value="terminate">terminate — the ingress holds the certificate and re-originates</option>
          </select>
        </Field>
        <Field label="Ingress key fingerprint" help="Optional." id="ingress_fingerprint"
          tip="Empty: trust on first use — the key that answers is pinned, and the node reports it back for you to check. Filled in: a different key is refused.">
          <input name="ingress_fingerprint" type="text" placeholder="sha256:… — leave empty to trust on first use" />
        </Field>
        {many ? (
          <Field label="Identity to pair" id="pair_account">
            <select name="account" defaultValue={currentAccount()}>
              {(d.accounts ?? []).map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
            </select>
          </Field>
        ) : (
          <input type="hidden" name="account" value={currentAccount()} />
        )}
        <Toolbar className="foot"><Button type="submit">Pair</Button></Toolbar>
      </form>
    </Section>
  );
}
