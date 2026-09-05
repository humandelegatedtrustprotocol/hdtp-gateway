// Contacts, requests and invites are one subject — who can reach you, who wants
// to, and the links that let them — so they are one page with three tabs rather
// than three pages that each hide the other two.
//
// The three routes are kept: /contacts, /requests and /invites each open this
// page on the matching tab, so old links, the dashboard's "waiting" link and the
// nav all still land where they say they will.
import { useCallback, useEffect, useState } from "react";
import { getJSON, postForm } from "../api";
import { usePath } from "../router";
import { Avatar, Badge, Button, EmptyState, Field, List, ListRow, Notice, PageHeader, Readout, Section, Table, Tabs, Toolbar, type Note } from "../ui";

type Contact = { fingerprint: string; label: string; status: string };
type ContactsData = { contacts: Contact[] | null; presets: string[]; can_add: boolean };

type Pending = { fingerprint: string; display_name: string; via_invite?: boolean; invite_label?: string };
type RequestsData = { pending: Pending[] | null; presets: string[] };

type Invite = {
  ID: string; Label: string; MaxUses: number; Uses: number;
  AutoAccept: boolean; Preset: string; RevokedAt: number; ExpiresAt: number;
};
type InvitesData = { invites: Invite[] | null; presets: string[]; public_url: string };

type Tab = "contacts" | "requests" | "invites";

const TAB_PATH: Record<Tab, string> = {
  contacts: "/contacts",
  requests: "/requests",
  invites: "/invites",
};

export function People() {
  const path = usePath();
  const tab: Tab = path.startsWith("/requests") ? "requests" : path.startsWith("/invites") ? "invites" : "contacts";

  const [c, setC] = useState<ContactsData | null>(null);
  const [r, setR] = useState<RequestsData | null>(null);
  const [i, setI] = useState<InvitesData | null>(null);
  const [note, setNote] = useState<Note | null>(null);

  // All three load together: the Requests tab carries a count, and a count you
  // only learn by visiting the tab is not a count worth having.
  const load = useCallback(() => {
    getJSON<ContactsData>("/api/contacts").then(setC).catch(() => {});
    getJSON<RequestsData>("/api/requests").then(setR).catch(() => {});
    getJSON<InvitesData>("/api/invites").then(setI).catch(() => {});
  }, []);
  useEffect(() => { load(); }, [load]);

  const header = <PageHeader title="People" sub="Who can reach you, who wants to, and the links that let them." />;
  if (!c || !r || !i) return <main>{header}<EmptyState loading /></main>;

  const contacts = (c.contacts ?? []).length;
  const waiting = (r.pending ?? []).length;
  const live = (i.invites ?? []).filter((x) => !x.RevokedAt).length;

  return (
    <main>
      {header}
      {note && <Notice kind={note.kind}>{note.text}</Notice>}

      {/* A pending request used to be a top-level nav item. Behind a tab it
          would be invisible, so the count comes to the tab instead. */}
      <Tabs active={tab} items={[
        { key: "contacts", label: "Contacts", to: TAB_PATH.contacts, count: contacts || undefined },
        { key: "requests", label: "Requests", to: TAB_PATH.requests, count: waiting || undefined, urgent: waiting > 0 },
        { key: "invites", label: "Invites", to: TAB_PATH.invites, count: live || undefined },
      ]} />

      {tab === "contacts" && <ContactsTab d={c} onNote={setNote} reload={load} />}
      {tab === "requests" && <RequestsTab d={r} reload={load} />}
      {tab === "invites" && <InvitesTab d={i} reload={load} onNote={setNote} />}
    </main>
  );
}

function ContactsTab({ d, onNote, reload }: {
  d: ContactsData;
  onNote: (n: Note | null) => void;
  reload: () => void;
}) {
  const [invite, setInvite] = useState("");
  const [grant, setGrant] = useState("basic");
  const rows = d.contacts ?? [];

  const accept = async () => {
    const res = await postForm("/contacts/add", { invite_url: invite, grant });
    const added = res.url.searchParams.get("added");
    const err = res.url.searchParams.get("err") || (!res.ok ? res.body || "that invite was not accepted" : "");
    onNote(err ? { kind: "err", text: err } : { kind: "ok", text: added ? `Added ${added}.` : "Invite accepted." });
    setInvite("");
    reload();
  };

  return (
    <>
      {d.can_add && (
        <Section title="Accept an invite"
          description="Your node fetches their card, checks the key matches the fingerprint it claims, and only then redeems — pinning them as a contact."
          footer={<Button onClick={accept} disabled={!invite.trim()}>Accept invite</Button>}>
          <Field label="Invite link" id="inv">
            <input type="text" placeholder="https://their.node/i/…" value={invite} onChange={(e) => setInvite(e.target.value)} />
          </Field>
          <Field label="What may they do here?" id="grant"
            help={<>Their invite decides what YOU may do on their node; this is the other half.{" "}<strong>basic</strong> lets them message you, which is what accepting an invite usually means.</>}>
            <select value={grant} onChange={(e) => setGrant(e.target.value)}>
              {d.presets.map((p) => <option key={p}>{p}</option>)}
              <option value="none">none — they cannot reach me</option>
            </select>
          </Field>
        </Section>
      )}
      <List aria-label="Contacts" empty={<EmptyState title="Nobody yet" action={<Button to="/invites">Create an invite</Button>}>invite someone, or accept an invite above</EmptyState>}>
        {rows.map((x) => (
          <ListRow key={x.fingerprint}
            leading={<Avatar name={x.label} />}
            title={x.label}
            to={`/contacts/${encodeURIComponent(x.fingerprint)}`}
            meta={<Badge status={x.status} />}
            trailing={x.status === "active" && <Button variant="secondary" to={`/messages?contact=${encodeURIComponent(x.fingerprint)}`}>Message</Button>} />
        ))}
      </List>
    </>
  );
}

function RequestsTab({ d, reload }: { d: RequestsData; reload: () => void }) {
  const [preset, setPreset] = useState<Record<string, string>>({});
  const rows = d.pending ?? [];
  return (
    <Section title="Waiting for approval"
      description="Approving pins their key and lets them use whatever the preset grants. The fingerprint is the identity — the name is only what they claim.">
      <Table head={["Who", "Fingerprint", "Grant", ""]} empty={<EmptyState title="Nobody is waiting" />}>
        {rows.map((p) => (
          <tr key={p.fingerprint}>
            <td>
              {p.display_name || <span className="muted">—</span>}
              {p.via_invite && <Badge>via invite{p.invite_label ? `: ${p.invite_label}` : ""}</Badge>}
            </td>
            <td><Readout value={p.fingerprint} /></td>
            <td>
              <select aria-label="Grant preset" value={preset[p.fingerprint] ?? d.presets[0]}
                onChange={(e) => setPreset({ ...preset, [p.fingerprint]: e.target.value })}>
                <option value="">no preset (grant nothing yet)</option>
                {d.presets.map((x) => <option key={x}>{x}</option>)}
              </select>
            </td>
            <td>
              <Toolbar>
                <Button onClick={async () => {
                  await postForm(`/requests/${encodeURIComponent(p.fingerprint)}/approve`,
                    { preset: preset[p.fingerprint] ?? d.presets[0] });
                  reload();
                }}>
                  Approve
                </Button>
                <Button variant="quiet" onClick={async () => {
                  await postForm(`/requests/${encodeURIComponent(p.fingerprint)}/reject`, {});
                  reload();
                }}>
                  Reject
                </Button>
              </Toolbar>
            </td>
          </tr>
        ))}
      </Table>
    </Section>
  );
}

function InvitesTab({ d, reload, onNote }: {
  d: InvitesData; reload: () => void; onNote: (n: Note | null) => void;
}) {
  const [label, setLabel] = useState("");
  const [maxUses, setMaxUses] = useState("1");
  const [auto, setAuto] = useState(false);
  const [preset, setPreset] = useState("basic");
  const [fresh, setFresh] = useState("");
  const link = (tok: string) => (d.public_url ? `${d.public_url}/i/${tok}` : "");

  const create = async () => {
    const res = await postForm("/invites/create", {
      label, max_uses: maxUses, auto_accept: auto ? "1" : "", preset,
    });
    const token = res.url.searchParams.get("new") ?? "";
    // A refusal used to leave the page exactly as it was, which reads as "nothing
    // happened" — the invite silently did not exist.
    if (!res.ok || !token) {
      onNote({ kind: "err", text: res.status === 400
        ? "The invite was not created. Pick the identity it belongs to (bottom of the sidebar) and try again."
        : "The invite was not created (" + (res.body || String(res.status)) + ")." });
      return;
    }
    onNote(null);
    setFresh(token);
    setLabel("");
    reload();
  };

  return (
    <>
      {fresh && link(fresh) && (
        <Notice kind="ok" title="Share this link — it is shown once"
          action={<Button variant="secondary" onClick={() => navigator.clipboard?.writeText(link(fresh))}>Copy</Button>}>
          <pre>{link(fresh)}</pre>
        </Notice>
      )}
      {fresh && !link(fresh) && (
        <Notice kind="warn" action={<Button variant="secondary" to="/settings">Open settings</Button>}>
          The invite exists (token <code>{fresh}</code>), but this node has <strong>no public URL</strong>,
          so there is no link anybody could open. Set one in Settings, then mint a fresh invite.
        </Notice>
      )}
      <Section title="Create an invite" footer={<Button onClick={create}>Create</Button>}>
        <div className="fields">
          <Field label="Label (for you)">
            <input type="text" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="dinner group" />
          </Field>
          <Field label="Max uses">
            <input type="number" min={1} value={maxUses} onChange={(e) => setMaxUses(e.target.value)} />
          </Field>
          <Field label="They get preset">
            <select value={preset} onChange={(e) => setPreset(e.target.value)}>
              {d.presets.map((p) => <option key={p}>{p}</option>)}
            </select>
          </Field>
          <Field check label="auto-accept — redeeming pins them with no approval step">
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
          </Field>
        </div>
      </Section>
      <Table head={["Label", "Uses", "Preset", "Auto", "State", ""]} empty={<EmptyState title="No invites yet" />}>
        {(d.invites ?? []).map((x) => (
          <tr key={x.ID}>
            <td>{x.Label || <span className="muted">—</span>}</td>
            <td>{x.Uses}/{x.MaxUses}</td>
            <td>{x.Preset}</td>
            <td>{x.AutoAccept ? <Badge tone="ok">auto</Badge> : <span className="muted">—</span>}</td>
            <td><Badge status={x.RevokedAt ? "revoked" : "live"} /></td>
            <td>
              {!x.RevokedAt && (
                <Toolbar>
                  <Button variant="quiet" onClick={async () => {
                    await postForm(`/invites/${encodeURIComponent(x.ID)}/revoke`, {});
                    reload();
                  }}>
                    Revoke
                  </Button>
                </Toolbar>
              )}
            </td>
          </tr>
        ))}
      </Table>
    </>
  );
}
