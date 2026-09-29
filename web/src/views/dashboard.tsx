// The overview: this node at a glance. Whether people can reach it and what it enforces, as one
// strip; the four numbers an owner acts on; and each identity they administer as a card — its
// address, whether its certificate is current, and its people, each number a link to where it is
// explained. What happened is the Audit page's (the owner, 2026-09-29).
//
// Every number is a field of GET /api/dashboard (dashboard_model.ts); a failed read is said in place,
// never drawn as zeros. The pieces are glance.tsx, which PACT Cloud's overview is built from too.
import { useEffect, useState, type ReactNode } from "react";
import { failureOf, getJSON, setAccount } from "../api";
import { Attention, GlanceBody, IdentityCard, IdentityCards, GlanceSkeleton, StatTile, StatTiles, StatusStrip } from "../glance";
import { certificateView, plural } from "../overview";
import { navigate } from "../router";
import { Button, EmptyState, Notice, PageHeader, Readout, Section } from "../ui";
import { firstWaiting, needsOf, tilesOf, type Account, type Dashboard as Data } from "./dashboard_model";

export function Dashboard() {
  const [d, setD] = useState<Data | null>(null);
  const [err, setErr] = useState("");
  const [now] = useState(() => Date.now());
  useEffect(() => {
    getJSON<Data>("/api/dashboard").then(setD).catch((e) => setErr(failureOf(e)));
  }, []);

  // "Review" opens the first identity with somebody waiting, and says whose when there are several.
  const header = (sub?: ReactNode, waiting?: Account | null, several = false) => (
    <PageHeader
      title="Overview"
      sub={sub}
      actions={<>
        {waiting && <Button onClick={() => { setAccount(waiting.id); navigate("/requests"); }}>
          Review {plural(waiting.pending, "request")}{several ? ` for ${waiting.display_name || waiting.slug}` : ""}
        </Button>}
        <Button variant={waiting ? "secondary" : "primary"} to="/messages">Open inbox</Button>
        <Button variant="secondary" to="/invites">Invite someone</Button>
      </>}
    />
  );

  if (err) {
    return (
      <main className="glance">
        {header()}
        <Notice kind="err" title="Could not read this node's overview">{err}</Notice>
      </main>
    );
  }
  if (!d) return <main className="glance">{header()}<GlanceSkeleton strip /></main>;

  const accounts = d.accounts ?? [];
  const tiles = tilesOf(d, now);
  const reachable = Boolean(d.posture.public_url);
  const one = accounts.length === 1 ? accounts[0] : null;
  // A summed tile links only where one page explains it: with one identity, that identity's page.
  const pick = (a: Account | null) => (a ? () => setAccount(a.id) : undefined);

  return (
    <main className="glance">
      {header(
        reachable ? <>People reach this node at <code>{d.posture.public_url}</code>.</> : "This node has no public address yet.",
        firstWaiting(d), accounts.length > 1,
      )}

      {!reachable && (
        <Notice kind="warn" action={<Button variant="secondary" to="/settings">Open settings</Button>}>
          No public URL is set, so your card carries no endpoint and nobody can reach you yet — set one in Settings.
        </Notice>
      )}

      <StatusStrip aria-label="Reachability" items={[
        { label: "Public address", value: reachable ? <Readout value={d.posture.public_url} /> : <span className="muted">none</span> },
        { label: "Mode", value: d.posture.mode },
        { label: "Tunnel", value: d.posture.tunnel || "direct" },
        { label: "Sealed envelopes", value: d.posture.seal },
        { label: "Client certificates", value: d.posture.client_cert },
      ]} />

      <StatTiles aria-label="This node in numbers">
        <StatTile label="Identities" value={tiles.identities} to="/identity" hint="you administer" />
        <StatTile label="Contacts" value={tiles.contacts} hint="can reach you"
          to={one ? "/contacts" : undefined} onClick={pick(one)} />
        <StatTile label="Waiting" value={tiles.waiting} tone={tiles.waiting ? "warn" : undefined}
          hint={tiles.waiting ? "want your answer" : "nobody is waiting"}
          to={one ? "/requests" : undefined} onClick={pick(one)} />
        <StatTile label="Certificates" value={tiles.attention} tone={tiles.attention ? "warn" : undefined}
          hint={tiles.attention ? "need your wallet" : "all current"} to="/identity" />
      </StatTiles>

      <GlanceBody side={
        <Attention items={needsOf(d, now).map((n) => ({
          key: n.key, tone: n.tone, text: n.text,
          action: n.kind === "waiting"
            ? <Button variant="secondary" onClick={() => { setAccount(n.account.id); navigate("/requests"); }}>Review</Button>
            : <Button variant="secondary" onClick={() => { setAccount(n.account.id); navigate("/identity"); }}>Open its certificate</Button>,
        }))} />
      }>
      {accounts.length === 0 ? (
        <Section title="Identities">
          <EmptyState title="No identities yet">Create one with <code>pact-gateway account create</code>.</EmptyState>
        </Section>
      ) : (
        <IdentityCards>
          {accounts.map((a) => {
            const pickThis = () => setAccount(a.id);
            return (
              <IdentityCard key={a.id}
                name={a.display_name || a.slug}
                handle={a.fingerprint ? <>{a.slug} · <span title={a.fingerprint}>{a.fingerprint.slice(0, 18)}…</span></> : a.slug}
                address={a.certificate === null ? undefined
                  : a.certificate.endpoint ? <Readout value={a.certificate.endpoint} />
                  : <span className="muted">not served: no current certificate</span>}
                certificate={certificateView(a.certificate, now)}
                counts={[
                  { label: "contacts", value: a.contacts, to: "/contacts", onClick: pickThis },
                  { label: "waiting", value: a.pending, tone: a.pending ? "warn" : undefined, to: "/requests", onClick: pickThis },
                ]}
                footer={<Button variant="quiet" to="/identity" icon="key">Certificate</Button>}
              />
            );
          })}
        </IdentityCards>
      )}
      </GlanceBody>
    </main>
  );
}
