// Integrations: the MCP servers this node fronts, and the way in to what each
// one exposes. One list row per server — status badge, primary action, the
// rest quiet — with the add form, credentials and OAuth client behind
// disclosures so the page reads as a list, not a wall of forms.
import { useCallback, useEffect, useState } from "react";
import { csrf, currentAccount, failureOf, getJSON, postForm } from "../api";
import { Badge, Button, EmptyState, Failed, Field, List, ListRow, Notice, PageHeader, Readout, Section, Toolbar, type Note } from "../ui";

type Row = { ID: string; Slug: string; Transport: string; Endpoint: string; Command: string; AuthKind: string; Status: string };
type Data = { rows: Row[] | null; can_set_static: boolean; can_set_oauth: boolean };

export function Integrations() {
  const [d, setD] = useState<Data | null>(null);
  const [note, setNote] = useState<Note | null>(null);
  const [adding, setAdding] = useState(false);
  const [slug, setSlug] = useState("");
  const [transport, setTransport] = useState("streamable-http");
  const [endpoint, setEndpoint] = useState("");
  const [command, setCommand] = useState("");
  const [authKind, setAuthKind] = useState("none");
  const [cred, setCred] = useState<Record<string, { header: string; value: string }>>({});
  const [oauth, setOauth] = useState<Record<string, { id: string; secret: string }>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [watching, setWatching] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const load = useCallback(() => getJSON<Data>("/api/integrations").then((x) => { setD(x); setErr(""); }).catch((e) => setErr(failureOf(e))), []);
  useEffect(() => { load(); }, [load]);
  // The provider's sign-in opens in a NEW tab, so this one stays on the list
  // and updates itself: while a flow is out, the row is re-read every two
  // seconds until it leaves "connecting" (five minutes at most).
  useEffect(() => {
    if (!watching) return;
    const started = Date.now();
    const t = window.setInterval(async () => {
      const data = await getJSON<Data>("/api/integrations").catch(() => null);
      if (!data) return;
      setD(data);
      const row = (data.rows ?? []).find((x) => x.ID === watching);
      const done = !row || row.Status !== "connecting";
      if (done || Date.now() - started > 5 * 60 * 1000) {
        setWatching(null);
        if (row?.Status === "ok") setNote({ kind: "ok", text: `${row.Slug} is connected — refresh its catalog, then choose what to expose.` });
        else if (row) setNote({ kind: row.Status === "connecting" ? "warn" : "err", text: `${row.Slug}: ${row.Status.replace("_", " ")}` });
      }
    }, 2000);
    return () => window.clearInterval(t);
  }, [watching]);

  const act = async (path: string, fields: Record<string, string> = {}) => {
    const r = await postForm(path, fields);
    setNote(r.ok ? null : { kind: "err", text: r.body || "that did not work" });
    load();
    return r.ok;
  };
  const add = async () => {
    if (await act("/integrations/create", { slug, transport, endpoint, command, auth_kind: authKind })) {
      setSlug(""); setEndpoint(""); setCommand(""); setAdding(false);
    }
  };
  const authorize = async (id: string) => {
    setBusy(id);
    // Opened synchronously, inside the click, so popup blockers allow it; the
    // URL is filled in once the node has it. It can't be reached from here
    // afterwards (noopener) — the poll above is how this tab learns the result.
    const tab = window.open("", "_blank");
    try {
      const body = new URLSearchParams({ csrf: csrf(), account: currentAccount() });
      const r = await fetch(`/integrations/${id}/connect`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Pact-Csrf": csrf(), Accept: "application/json" },
        body: body.toString(),
      });
      const j = (await r.json().catch(() => ({}))) as { authorize_url?: string; error?: string };
      if (r.ok && j.authorize_url) {
        if (tab) { tab.location.href = j.authorize_url; } else { window.location.assign(j.authorize_url); return; }
        setWatching(id);
        setNote({ kind: "ok", text: "Sign in on the tab that just opened; this page updates when the provider answers." });
        load();
        return;
      }
      tab?.close();
      setNote({ kind: "err", text: j.error || "authorization did not start" });
      load();
    } catch (e) {
      tab?.close();
      setNote({ kind: "err", text: String(e) });
    } finally { setBusy(null); }
  };

  const rows = d?.rows ?? [];
  const header = (
    <PageHeader
      title="Integrations"
      sub="Connect an MCP server, then expose only the tools the use-case needs. Nothing is exposed by default, and write-capable tools take an explicit acknowledgment."
      actions={<Button icon="plus" onClick={() => setAdding((v) => !v)} aria-pressed={adding}>Add integration</Button>}
    />
  );
  if (!d) return <main>{header}{err ? <Failed what="the integrations" error={err} retry={load} /> : <EmptyState loading />}</main>;

  const addForm = (
    <Section title="New integration" description="Give it a short name; the transport and address are what the node dials."
      footer={<><Button onClick={add} disabled={!slug.trim()}>Add</Button>{rows.length > 0 && <Button variant="quiet" onClick={() => setAdding(false)}>Cancel</Button>}</>}>
      <div className="fields">
        <Field label="Name (slug)"><input type="text" value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="calendar" /></Field>
        <Field label="Transport">
          <select value={transport} onChange={(e) => setTransport(e.target.value)}>
            <option>streamable-http</option><option>sse</option><option>stdio-supervised</option>
          </select>
        </Field>
        {transport === "stdio-supervised"
          ? <Field label="Command" help="Run by the node as a supervised child."><input type="text" value={command} onChange={(e) => setCommand(e.target.value)} placeholder="npx some-mcp-server" /></Field>
          : <Field label="Endpoint"><input type="text" value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder="https://…/mcp" /></Field>}
        <Field label="Authentication" help={authKind === "oauth" ? "Registers with the provider automatically on Connect & authorize." : authKind === "static" ? "A header the node attaches to every request; set it after adding." : "Sends no credential."}>
          <select value={authKind} onChange={(e) => setAuthKind(e.target.value)}>
            <option>none</option><option>static</option><option>oauth</option>
          </select>
        </Field>
      </div>
    </Section>
  );

  return (
    <main>
      {header}
      {note && <Notice kind={note.kind}>{note.text}</Notice>}
      {(adding || rows.length === 0) && addForm}
      {rows.length === 0 ? (
        <EmptyState title="No integrations yet">Add an MCP server above; its tools stay private until you expose them.</EmptyState>
      ) : (
        <List aria-label="Integrations">
          {rows.map((row) => {
            const trouble = row.Status === "auth_error" || row.Status === "unreachable";
            const primary = row.AuthKind === "oauth"
              ? <Button busy={busy === row.ID} onClick={() => authorize(row.ID)}>{trouble ? "Reconnect & authorize" : row.Status === "ok" ? "Reconnect" : "Connect & authorize"}</Button>
              : <Button variant={row.Status === "ok" ? "secondary" : "primary"} onClick={() => act(`/integrations/${row.ID}/connect`)}>{trouble || row.Status === "ok" ? "Reconnect" : "Connect"}</Button>;
            return (
              <ListRow key={row.ID}
                leading={<span className="av" aria-hidden="true">{row.Slug.slice(0, 2).toUpperCase()}</span>}
                title={<>{row.Slug}<Badge status={row.Status} /></>}
                meta={<><Badge mono>{row.Transport}</Badge><Badge mono>{row.AuthKind === "none" ? "no auth" : row.AuthKind}</Badge>{(row.Endpoint || row.Command) && <Readout value={row.Endpoint || row.Command} />}</>}
                trailing={<Toolbar>
                  {primary}
                  <Button variant="secondary" to={`/integrations/${row.ID}/exposure`} icon="tool">Exposure</Button>
                  <Button variant="quiet" icon="refresh" aria-label="Refresh catalog" title="Refresh catalog" onClick={() => act(`/integrations/${row.ID}/refresh`)} />
                  <Button variant="quiet" icon="trash" aria-label={`Remove ${row.Slug}`} title="Remove" confirm={`Remove ${row.Slug}? Its exposures stop serving.`} onClick={() => act(`/integrations/${row.ID}/remove`)} />
                </Toolbar>}>
                {row.Status === "auth_error" && (
                  <Notice kind="warn" action={row.AuthKind !== "oauth" && (
                    <Button variant="secondary" onClick={async () => {
                      // Same slug, transport and endpoint, with OAuth — one click instead of
                      // remove-and-retype. A row that never connected has nothing to lose.
                      await postForm(`/integrations/${row.ID}/remove`, {});
                      await act("/integrations/create", { slug: row.Slug, transport: row.Transport, endpoint: row.Endpoint ?? "", command: row.Command ?? "", auth_kind: "oauth" });
                    }}>Re-add with OAuth</Button>
                  )}>
                    {row.AuthKind === "oauth"
                      ? "The upstream reports authorization failed or expired — click Reconnect & authorize to sign in again."
                      : row.AuthKind === "static"
                        ? "The server refused the credential below — update it and reconnect."
                        : "This server requires authentication — it answered 401 and asks to be signed into. Re-add it with OAuth, or remove it and add a static token."}
                  </Notice>
                )}
                {row.AuthKind === "static" && d.can_set_static && (
                  <Section collapsible title="Credential" description="Stored sealed at rest; never rendered back."
                    footer={<Button onClick={() => act(`/integrations/${row.ID}/credential`, { header: cred[row.ID]?.header ?? "Authorization", value: cred[row.ID]?.value ?? "" })}>Save credential</Button>}>
                    <div className="fields">
                      <Field label="Header"><input type="text" value={cred[row.ID]?.header ?? "Authorization"} onChange={(e) => setCred({ ...cred, [row.ID]: { header: e.target.value, value: cred[row.ID]?.value ?? "" } })} /></Field>
                      <Field label="Value"><input type="password" value={cred[row.ID]?.value ?? ""} onChange={(e) => setCred({ ...cred, [row.ID]: { header: cred[row.ID]?.header ?? "Authorization", value: e.target.value } })} /></Field>
                    </div>
                  </Section>
                )}
                {row.AuthKind === "oauth" && d.can_set_oauth && (
                  <Section collapsible title="OAuth client (optional)"
                    description="Leave this empty: on Connect & authorize the node registers itself with the provider automatically. Fill it in only if the provider gave you a client id to use instead."
                    footer={<Button variant="secondary" onClick={() => act(`/integrations/${row.ID}/oauth-client`, { client_id: oauth[row.ID]?.id ?? "", client_secret: oauth[row.ID]?.secret ?? "" })}>Save client</Button>}>
                    <div className="fields">
                      <Field label="Client id"><input type="text" value={oauth[row.ID]?.id ?? ""} onChange={(e) => setOauth({ ...oauth, [row.ID]: { id: e.target.value, secret: oauth[row.ID]?.secret ?? "" } })} /></Field>
                      <Field label="Client secret"><input type="password" value={oauth[row.ID]?.secret ?? ""} onChange={(e) => setOauth({ ...oauth, [row.ID]: { id: oauth[row.ID]?.id ?? "", secret: e.target.value } })} /></Field>
                    </div>
                  </Section>
                )}
              </ListRow>
            );
          })}
        </List>
      )}
    </main>
  );
}
