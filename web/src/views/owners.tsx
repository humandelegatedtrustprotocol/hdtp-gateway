// Owners: the passkeys that open this portal and the bearer tokens an agent
// runs the node with. Token creation answers with the plaintext exactly once,
// so that response is the page state rather than a re-fetch.
import { useCallback, useEffect, useState } from "react";
import { failureOf, getJSON, postForm } from "../api";
import { Badge, Button, EmptyState, Failed, Field, HelpTip, List, ListRow, Notice, PageHeader, Section, Toolbar, type Note } from "../ui";
import { dateOf, whenTitle } from "../words";

type Passkey = { id: string; tag: string; created_at: number };
type Token = { id: string; label: string; account_id?: string; created_at: number; revoked: boolean };
type Data = { notice: string; new_token: string; passkeys: Passkey[] | null; tokens: Token[] | null; accounts: { id: string; label: string }[] | null };

/** A day, said as every date in the portal is (words.ts `dateOf`), from the Unix seconds the node stores. */
function day(unix: number): string {
  return dateOf(unix * 1000);
}

export function Owners() {
  const [d, setD] = useState<Data | null>(null);
  const [label, setLabel] = useState("");
  const [note, setNote] = useState<Note | null>(null);
  const [fresh, setFresh] = useState("");
  const [err, setErr] = useState("");
  const load = useCallback(() => getJSON<Data>("/api/owners").then((x) => { setD(x); setErr(""); }).catch((e) => setErr(failureOf(e))), []);
  useEffect(() => { load(); }, [load]);

  const header = <PageHeader title="Owners" />;
  if (!d) return <main>{header}{err ? <Failed what="the owners" error={err} retry={load} /> : <EmptyState loading />}</main>;

  const post = async (path: string, fields: Record<string, string> = {}) => {
    const r = await postForm(path, fields);
    // These endpoints answer with the owners payload itself — the notice, and
    // for token creation the ONE appearance of the plaintext. Re-fetching would
    // throw that appearance away, so the response body is the state.
    try {
      const j = JSON.parse(r.body || "null") as Data | null;
      if (j && j.passkeys !== undefined) {
        setD(j);
        setNote(j.notice ? { kind: r.ok ? "ok" : "err", text: j.notice } : null);
        setFresh(j.new_token ?? "");
        return;
      }
    } catch { /* not the payload; reload below */ }
    setNote(r.ok ? null : { kind: "err", text: "that did not work" });
    load();
  };

  const passkeys = d.passkeys ?? [];
  const tokens = d.tokens ?? [];
  // Which identity a token acts as: its account, by the name the node lists it under. A token with no
  // account acts for every identity of its owner (auth.Identity: "" = all the owner's accounts).
  const acting = (t: Token) => {
    if (!t.account_id) return "every identity";
    return (d.accounts ?? []).find((a) => a.id === t.account_id)?.label ?? `a removed identity (${t.account_id})`;
  };
  const create = () => { post("/owners/tokens/create", { label }); setLabel(""); };
  return (
    <main>
      {header}
      {note && <Notice kind={note.kind}>{note.text}</Notice>}
      {fresh && (
        <Notice kind="ok" title="Bearer token — shown once, store it now" action={<Button variant="secondary" onClick={() => navigator.clipboard?.writeText(fresh)}>Copy</Button>}>
          <pre>{fresh}</pre>
        </Notice>
      )}
      <Section title="Passkeys"
        description={<>
          The only way in. Register a second on another device.
          <HelpTip label="About passkeys and recovery">
            Every bind requires a session, loopback included. There is deliberately no online recovery path,
            and the last passkey cannot be removed here. If you lose them all, recovery needs shell access on
            the host — <code>pact-gateway passkey reset-wizard</code> mints a one-time link that re-opens registration.
          </HelpTip>
        </>}>
        {passkeys.length === 0 ? <EmptyState title="No passkeys" /> : (
          <List aria-label="Passkeys">
            {passkeys.map((p) => (
              <ListRow key={p.id}
                title={p.tag || <span className="muted">(untagged)</span>}
                meta={<span className="muted" title={whenTitle(p.created_at * 1000)}>added {day(p.created_at)}</span>}
                trailing={<Button variant="quiet" aria-label={`Remove ${p.tag || "the untagged passkey"}`}
                  confirm={`Remove the passkey ${p.tag ? `“${p.tag}”` : "with no tag"}, added ${day(p.created_at)}? It no longer opens this portal.`}
                  onClick={() => post(`/owners/passkeys/${encodeURIComponent(p.id)}/remove`)}>Remove</Button>} />
            ))}
          </List>
        )}
      </Section>
      <Section title="Agent tokens" description="Revocable bearer tokens your own agent uses for the owner MCP.">
        <form className="add-row" onSubmit={(e) => { e.preventDefault(); if (label.trim()) create(); }}>
          <Field label="Label"><input type="text" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="my laptop agent" /></Field>
          <Toolbar><Button type="submit" disabled={!label.trim()}>Create</Button></Toolbar>
        </form>
        <List aria-label="Agent tokens" empty={<EmptyState title="No tokens yet" />}>
          {tokens.map((t) => (
            <ListRow key={t.id}
              title={t.label}
              meta={<><Badge status={t.revoked ? "revoked" : "active"} /><span className="muted">acting as {acting(t)} · made {day(t.created_at)}</span></>}
              trailing={!t.revoked && <Button variant="quiet" aria-label={`Revoke ${t.label}`}
                confirm={`Revoke “${t.label}”? The agent using it is refused from its next call.`}
                onClick={() => post(`/owners/tokens/${encodeURIComponent(t.id)}/revoke`)}>Revoke</Button>} />
          ))}
        </List>
      </Section>
    </main>
  );
}
