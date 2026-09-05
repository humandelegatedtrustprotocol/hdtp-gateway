// The overview: is this node reachable, who am I on it, and what happened last.
import { useEffect, useState } from "react";
import { getJSON } from "../api";
import { Link } from "../router";
import { Badge, Button, EmptyState, Notice, PageHeader, Readout, Section, Table } from "../ui";

type Posture = { mode: string; seal: string; client_cert: string; tunnel: string; public_url: string; relay: boolean; gateway: string };
type Acct = { slug: string; display_name: string; fingerprint: string; contacts: number; pending: number };
type Audit = { Action: string; ActorKind: string; Outcome: string };
type Data = { posture: Posture; accounts: Acct[]; recent: Audit[] | null };

export function Dashboard() {
  const [d, setD] = useState<Data | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    getJSON<Data>("/api/dashboard").then(setD).catch((e) => setErr(String(e)));
  }, []);
  if (err) return <main><PageHeader title="Overview" /><Notice kind="err">{err}</Notice></main>;
  if (!d) return <main><PageHeader title="Overview" /><EmptyState loading /></main>;
  const reachable = Boolean(d.posture.public_url);
  return (
    <main>
      <PageHeader
        title="Overview"
        sub={reachable ? <>People reach this node at <code>{d.posture.public_url}</code>.</> : "This node has no public address yet."}
        actions={<><Button to="/messages">Open inbox</Button><Button variant="secondary" to="/invites">Invite someone</Button></>}
      />

      {!reachable && (
        <Notice kind="warn" action={<Button variant="secondary" to="/settings">Open settings</Button>}>
          No public URL is set, so your card carries no endpoint and nobody can reach you yet — set one in Settings.
        </Notice>
      )}

      <Section title="Reachability">
        <div className="grid">
          <Cell k="mode" v={d.posture.mode} />
          <Cell k="tunnel" v={d.posture.tunnel || "direct"} />
          <Cell k="sealed envelopes" v={d.posture.seal} />
          <Cell k="client certificates" v={d.posture.client_cert} />
          {d.posture.relay && <Cell k="relay" v="serving" />}
          {d.posture.gateway && <Cell k="my gateway" v={d.posture.gateway} />}
        </div>
      </Section>

      <Section title="Identities">
        <Table head={["account", "fingerprint", "contacts", "waiting"]}
          empty={<EmptyState title="No identities yet">Create one with <code>pact-gateway account create</code>.</EmptyState>}>
          {d.accounts.map((a) => (
            <tr key={a.slug}>
              <td><strong>{a.display_name}</strong><br /><span className="muted">{a.slug}</span></td>
              <td><Readout value={a.fingerprint} /></td>
              <td>{a.contacts}</td>
              <td>{a.pending ? <Link to="/requests"><Badge tone="warn">{String(a.pending)} waiting</Badge></Link> : <span className="muted">0</span>}</td>
            </tr>
          ))}
        </Table>
      </Section>

      <Section title="Recent activity">
        <Table head={["action", "who", "outcome"]} empty={<EmptyState title="Nothing recorded yet" />}>
          {(d.recent ?? []).map((r, i) => (
            <tr key={i}><td><code>{r.Action}</code></td><td>{r.ActorKind}</td><td><Badge status={r.Outcome} /></td></tr>
          ))}
        </Table>
        <p className="help">The full trail, including refusals, is in <Link to="/audit">Audit</Link>.</p>
      </Section>
    </main>
  );
}

function Cell({ k, v }: { k: string; v: string }) {
  return (
    <div className="cell">
      <div className="k">{k}</div>
      <div className="v">{v}</div>
    </div>
  );
}
