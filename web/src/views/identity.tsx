import { useCallback, useEffect, useState } from "react";
import { failureOf, fetchSession, getJSON, postForm } from "../api";
import { Badge, Button, EmptyState, Failed, Field, Notice, PageHeader, Readout, Section, type Note } from "../ui";

type Row = { id: string; slug: string; display_name: string; fingerprint: string; algo: string; web_wallet?: boolean; root_fingerprint?: string };
type Data = { rows: Row[]; notice: string; error: string; can_create: boolean };

export function Identity() {
  const [d, setD] = useState<Data | null>(null);
  const [note, setNote] = useState<Note | null>(null);
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [algo, setAlgo] = useState("p256");
  const [err, setErr] = useState("");
  const load = useCallback(() => getJSON<Data>("/api/identity").then((x) => { setD(x); setErr(""); }).catch((e) => setErr(failureOf(e))), []);
  useEffect(() => { load(); }, [load]);
  if (!d) return <main><PageHeader title="Identity" />{err ? <Failed what="this node's identities" error={err} retry={load} /> : <EmptyState loading />}</main>;

  const create = async () => {
    const r = await postForm("/identity/create", { slug, name, algo });
    // The session now lists a new identity; tell the shell, and select it if none was.
    fetchSession().catch(() => {});
    try {
      const j = JSON.parse(r.body || "null") as Data | null;
      if (j && j.rows !== undefined) {
        setD(j);
        if (j.notice || j.error) setNote({ kind: j.error ? "err" : "ok", text: j.notice || j.error });
        if (!j.error) { setSlug(""); setName(""); }
        return;
      }
    } catch { /* not the payload */ }
    setNote(r.ok ? null : { kind: "err", text: "could not create that identity" });
    load();
  };

  return (
    <main>
      <PageHeader title="Identity" />
      {note && <Notice kind={note.kind}>{note.text}</Notice>}

      {d.can_create && (
        <Section title="Add an identity"
          description="A second identity is how one node serves two people, or keeps work and home apart. Each has its own keypair, contacts and inbox — nothing is shared between them. The slug becomes the endpoint path people reach you on, so it is public; pick it as deliberately as a username."
          footer={<Button onClick={create} disabled={!slug.trim() || !name.trim()}>Create identity</Button>}>
          <div className="fields">
            <Field label="Slug" id="slug"><input type="text" value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="work" /></Field>
            <Field label="Display name" id="name"><input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Alice (work)" /></Field>
            <Field label="Key algorithm" id="algo">
              <select value={algo} onChange={(e) => setAlgo(e.target.value)}>
                <option value="p256">p256</option>
                <option value="ed25519">ed25519</option>
              </select>
            </Field>
          </div>
        </Section>
      )}
      {d.rows.map((a) => (
        // An identity with no root has no certificate, and so no card and no address: that is its status,
        // said as a warning. The key algorithm answers no question an owner asks; it is in the details line.
        <Section key={a.id} title={a.display_name}
          meta={<><Badge mono>{a.slug}</Badge>{!a.root_fingerprint && <Badge tone="warn">no certificate yet</Badge>}</>}
          footer={a.web_wallet ? <Button variant="secondary" href={"/identity/" + encodeURIComponent(a.slug) + "/wallet"}>Sign with my web wallet</Button> : undefined}>
          <p><Readout value={a.fingerprint} copy /></p>
          <p className="help">Host key · {a.algo}</p>
          {!a.root_fingerprint && (
            <>
              <p className="muted">Its first certificate comes from your command-line wallet. Run these three, in order:</p>
              {/* One command a line, whole, with a copy button: inline, they broke mid-token ('install-leaf -slug work-consulting-and-' / 'advisory'). */}
              <Readout block pre copy value={`pact-gateway account csr -slug ${a.slug}\npact id issue\npact-gateway account install-leaf -slug ${a.slug}`} />
            </>
          )}
        </Section>
      ))}
      {d.rows.length === 0 && <EmptyState title="No identities yet" />}
    </main>
  );
}
