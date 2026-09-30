// The overview: this node at a glance. What wants the owner first, when anything does; the four
// numbers an owner acts on; each identity they administer as a card — where it is reached, whether
// its certificate is current, and its people, each number a link to where it is explained; and
// whether people can reach the node and what it enforces, as one strip (below the cards on a phone,
// where it is reference rather than news). What happened is the Audit page's (the owner, 2026-09-29).
//
// Every number is a field of GET /api/dashboard (dashboard_model.ts); a failed read is said in place,
// never drawn as zeros. The pieces are glance.tsx, which PACT Cloud's overview is built from too.
import { useEffect, useState } from "react";
import { failureOf, getJSON, setAccount } from "../api";
import { Attention, GlanceSkeleton, IdText, IdentityCard, IdentityCards, StatTile, StatTiles, StatusStrip } from "../glance";
import { certificateView } from "../overview";
import { navigate } from "../router";
import { Button, EmptyState, Notice, PageHeader, Readout, Section } from "../ui";
import { addressOf, needsOf, tilesOf, type Account, type Dashboard as Data } from "./dashboard_model";

export function Dashboard() {
  const [d, setD] = useState<Data | null>(null);
  const [err, setErr] = useState("");
  const [now] = useState(() => Date.now());
  useEffect(() => {
    getJSON<Data>("/api/dashboard").then(setD).catch((e) => setErr(failureOf(e)));
  }, []);

  // The list of what needs the owner carries its own buttons, so the header does not repeat them.
  const header = (
    <PageHeader
      title="Overview"
      actions={<>
        <Button variant="secondary" to="/invites">Invite someone</Button>
        <Button to="/messages">Open inbox</Button>
      </>}
    />
  );

  if (err) {
    return (
      <main className="glance">
        {header}
        <Notice kind="err" title="Could not read this node's overview">{err}</Notice>
      </main>
    );
  }
  if (!d) return <main className="glance">{header}<GlanceSkeleton strip /></main>;

  const accounts = d.accounts ?? [];
  const tiles = tilesOf(d, now);
  const reachable = Boolean(d.posture.public_url);
  const one = accounts.length === 1 ? accounts[0] : null;
  // A summed tile links only where one page explains it: with one identity, that identity's page.
  const pick = (a: Account | null) => (a ? () => setAccount(a.id) : undefined);
  const needs = needsOf(d, now);
  const attention = (
    <Attention items={needs.map((n) => ({
      key: n.key, tone: n.tone, text: n.text,
      action: n.kind === "waiting"
        ? <Button variant="secondary" onClick={() => { setAccount(n.account.id); navigate("/requests"); }}>Review</Button>
        : <Button variant="secondary" onClick={() => { setAccount(n.account.id); navigate("/identity"); }}>Open its certificate</Button>,
    }))} />
  );

  return (
    <main className="glance">
      {header}

      {!reachable && (
        <Notice kind="warn" action={<Button variant="secondary" to="/settings">Open settings</Button>}>
          No public URL is set, so your card carries no endpoint and nobody can reach you yet — set one in Settings.
        </Notice>
      )}

      {needs.length > 0 && attention}

      <div className="gl-flow">
        {/* Unreachable, the notice above says so; the strip does not say it a third time. */}
        <StatusStrip aria-label="Reachability" items={[
          ...(reachable ? [{ label: "Public address", value: <Readout value={d.posture.public_url} /> }] : []),
          { label: "Mode", value: d.posture.mode },
          { label: "Tunnel", value: d.posture.tunnel || "direct" },
          { label: "Sealed envelopes", value: d.posture.seal },
          { label: "Client certificates", value: d.posture.client_cert },
        ]} />

        <StatTiles aria-label="This node in numbers">
          <StatTile label="Identities" value={tiles.identities} to="/identity" hint="you administer" />
          <StatTile label="Active contacts" value={tiles.contacts} hint="can reach you"
            to={one ? "/contacts" : undefined} onClick={pick(one)} />
          <StatTile label="Waiting" value={tiles.waiting} tone={tiles.waiting ? "warn" : undefined}
            hint={tiles.waiting ? "want your answer" : "nobody is waiting"}
            to={one ? "/requests" : undefined} onClick={pick(one)} />
          <StatTile label="Certificates" value={tiles.attention} tone={tiles.attention ? "warn" : undefined}
            hint={tiles.attention ? "need your wallet" : "all current"} to="/identity" />
        </StatTiles>

        {needs.length === 0 && attention}

        {accounts.length === 0 ? (
          <Section title="Identities">
            <EmptyState title="No identities yet">Create one with <code>pact-gateway account create</code>.</EmptyState>
          </Section>
        ) : (
          <IdentityCards>
            {accounts.map((a) => {
              // Every link on a card is about that card's identity: it selects it before it lands.
              const pickThis = () => setAccount(a.id);
              const endpoint = a.certificate?.endpoint ?? "";
              return (
                <IdentityCard key={a.id}
                  name={a.display_name || a.slug}
                  // A long slug gives way (an ellipsis, the whole of it in the tooltip); the fingerprint and its copy button do not.
                  handle={a.fingerprint ? <><span className="gl-slug" title={a.slug}>{a.slug} ·</span><IdText id={a.fingerprint} /></> : <span className="gl-slug" title={a.slug}>{a.slug}</span>}
                  // No address line for an identity with no current certificate: its pill says why.
                  address={endpoint ? <span title={endpoint}><Readout value={addressOf(endpoint, d.posture.public_url)} /></span> : undefined}
                  certificate={certificateView(a.certificate, now)}
                  // One identity: the tiles above are its numbers, so the card does not repeat them.
                  counts={one ? [] : [
                    { label: "active contacts", value: a.contacts, to: "/contacts", onClick: pickThis },
                    { label: "waiting", value: a.pending, tone: a.pending ? "warn" : undefined, to: "/requests", onClick: pickThis },
                  ]}
                  footer={<Button variant="quiet" to="/identity" onClick={pickThis} icon="key">Certificate</Button>}
                />
              );
            })}
          </IdentityCards>
        )}
      </div>
    </main>
  );
}
