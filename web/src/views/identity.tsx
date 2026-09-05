import { useCallback, useEffect, useState } from "react";
import { fetchSession, getJSON, postForm } from "../api";
import { Badge, Button, EmptyState, Field, Notice, PageHeader, Readout, Section, type Note } from "../ui";

type Row = { id: string; slug: string; display_name: string; fingerprint: string; algo: string };
type Data = { rows: Row[]; notice: string; error: string; default_grace: string; max_grace_days: number; can_create: boolean };

export function Identity() {
  const [d, setD] = useState<Data | null>(null);
  const [confirm, setConfirm] = useState<Record<string, string>>({});
  const [grace, setGrace] = useState<Record<string, string>>({});
  const [note, setNote] = useState<Note | null>(null);
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [algo, setAlgo] = useState("p256");
  const load = useCallback(() => getJSON<Data>("/api/identity").then(setD).catch(() => {}), []);
  useEffect(() => { load(); }, [load]);
  if (!d) return <main><PageHeader title="Identity" /><EmptyState loading /></main>;

  const rotate = async (a: Row) => {
    const r = await postForm("/identity/rotate", {
      account_id: a.id, confirm: confirm[a.id] ?? "", grace: grace[a.id] ?? "",
    });
    fetchSession().catch(() => {}); // the fingerprint the shell shows has changed
    // The endpoint answers the identity payload with the outcome in notice/error.
    try {
      const j = JSON.parse(r.body || "null") as Data | null;
      if (j && j.rows !== undefined) {
        setD(j);
        if (j.notice || j.error) setNote({ kind: j.error ? "err" : "ok", text: j.notice || j.error });
        setConfirm({ ...confirm, [a.id]: "" });
        return;
      }
    } catch { /* not the payload */ }
    setNote(r.ok ? null : { kind: "err", text: "rotation failed" });
    load();
  };

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
      <Notice kind="warn">
        <strong>Rotating a key is not undoable.</strong> A new keypair is generated, the old one signs it
        over, and every contact is told. Contacts that stay silent past the grace period must re-pair.
      </Notice>
      {d.rows.map((a) => (
        <Section key={a.id} title={a.display_name} meta={<><Badge mono>{a.slug}</Badge><Badge mono>{a.algo}</Badge></>}
          footer={<Button variant="danger" disabled={(confirm[a.id] ?? "") !== a.slug} onClick={() => rotate(a)}>Rotate this key</Button>}>
          <p><Readout value={a.fingerprint} copy /></p>
          <Field label={<>Type “{a.slug}” to confirm rotation</>}>
            <input type="text" value={confirm[a.id] ?? ""} onChange={(e) => setConfirm({ ...confirm, [a.id]: e.target.value })} />
          </Field>
          <Field label="Grace period" help={<>default {d.default_grace}, at most {d.max_grace_days} days; <code>0</code> retires the old key as soon as contacts have been told — anyone unreachable at that moment is lost</>}>
            <input type="text" placeholder={d.default_grace} value={grace[a.id] ?? ""} onChange={(e) => setGrace({ ...grace, [a.id]: e.target.value })} />
          </Field>
        </Section>
      ))}
      {d.rows.length === 0 && <EmptyState title="No identities yet" />}
    </main>
  );
}
