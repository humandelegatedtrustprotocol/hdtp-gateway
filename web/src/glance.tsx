// The pieces the overview and the audit trail are built from, for both portals: the node's
// (web/src) and PACT Cloud's (portal/src, copied verbatim by the cloud's gateway/scripts/harvest.sh).
// They import only what both portals' ui.tsx and router.tsx export alike, so the copy is the file.
// Their look is the block at the end of style.css headed "the overview at a glance", which both
// stylesheets carry byte for byte.
//
// What the two pages do with them differs — the node's overview leads with reachability, the
// cloud's with the plan — and lives in each portal's own view; what a number or a name LOOKS like,
// and what a failed read looks like, is here once.
import { useState, type ReactNode } from "react";
import { Link } from "./router";
import { Avatar, Badge, type Tone } from "./ui";
import { shortId, type Detail, type Named as NamedId, type Part } from "./audit_names";
import { shown, type CertificateView, type Count } from "./overview";

/**
 * One number the page read, as a tile: what it counts, the number, and a line under it. A tile that
 * links goes where its number is explained. A read that failed shows as one — a dash and "could not
 * read", in the refusal's tone — and never links, since there is nothing behind it to explain.
 */
export function StatTile({ label, value, of, hint, tone, to, onClick, failure }: {
  label: string;
  value: Count;
  /** The allowance the number is held to ("2 of 3"), when there is one. */
  of?: number | null;
  hint?: ReactNode;
  tone?: Tone;
  to?: string;
  onClick?: () => void;
  /** Why the read failed, for the tooltip; the tile itself says only that it did. */
  failure?: string;
}) {
  const failed = value === null;
  const cls = "gl-tile" + toneClass(failed ? "bad" : tone);
  const body = (
    <>
      <span className="k">{label}</span>
      <span className="v">{shown(value)}{!failed && of != null && <small>of {of}</small>}</span>
      <span className="h">{failed ? "could not read" : hint}</span>
    </>
  );
  if (to && !failed) return <Link to={to} className={cls} onClick={onClick}>{body}</Link>;
  return <div className={cls} title={failed ? failure : undefined}>{body}</div>;
}

/**
 * A tone as this module's own class (`gl-warn`, `gl-bad`, `gl-ok`), with its leading space; "" for
 * none. Not the bare word: `.bad` is the inbox's failed-delivery mark, and a tile wearing it took its
 * layout.
 */
function toneClass(tone: Tone | undefined): string {
  return tone && tone !== "neutral" ? ` gl-${tone}` : "";
}

/** The row the tiles sit in: four across on a wide screen, two on a narrow one. */
export function StatTiles({ children, "aria-label": label }: { children: ReactNode; "aria-label"?: string }) {
  return <div className="gl-tiles" role="group" aria-label={label}>{children}</div>;
}

/** A line of facts about the whole node or workspace, each a label and a value, wrapping as it must. */
export function StatusStrip({ items, "aria-label": label }: {
  items: { label: string; value: ReactNode; tone?: Tone }[];
  "aria-label"?: string;
}) {
  return (
    <div className="gl-strip" role="list" aria-label={label}>
      {items.map((it) => (
        <div key={it.label} role="listitem" className={toneClass(it.tone).trim() || undefined}>
          <span className="k">{it.label}</span><span className="v">{it.value}</span>
        </div>
      ))}
    </div>
  );
}

/** One of an identity's numbers on its card, and where it is explained. */
export type CardCount = { label: string; value: Count; of?: number | null; tone?: Tone; to?: string; onClick?: () => void };

/**
 * One identity, at a glance: who, where they are reached, whether their certificate is current, and
 * their numbers — each a link to where it is explained. `onClick` on a count is how a card for an
 * identity other than the selected one selects it before the link lands.
 */
export function IdentityCard({ name, handle, address, status, certificate, counts, footer }: {
  name: string;
  handle?: ReactNode;
  address?: ReactNode;
  status?: ReactNode;
  /** The certificate as `certificateView` says it, or a failure to show in its place. */
  certificate: CertificateView | { failed: string };
  counts: CardCount[];
  footer?: ReactNode;
}) {
  return (
    <article className="gl-id" aria-label={name}>
      <div className="top">
        <Avatar name={name} />
        <div className="who"><b>{name}</b>{handle && <small>{handle}</small>}</div>
        {status}
      </div>
      {address && <div className="addr">{address}</div>}
      <div className="cert">
        {"failed" in certificate
          ? <Badge tone="bad" title={certificate.failed}>certificate could not be read</Badge>
          : <Badge tone={certificate.tone} title={certificate.until ? `not after ${new Date(certificate.until).toUTCString()}` : undefined}>{certificate.text}</Badge>}
      </div>
      {counts.length > 0 && <div className="counts">
        {counts.map((c) => {
          const failed = c.value === null;
          const cls = toneClass(failed ? "bad" : c.tone).trim() || undefined;
          const body = <><b>{shown(c.value)}{!failed && c.of != null && <small> / {c.of}</small>}</b><span>{failed ? `${c.label}: could not read` : c.label}</span></>;
          return c.to && !failed
            ? <Link key={c.label} to={c.to} className={cls} onClick={c.onClick}>{body}</Link>
            : <div key={c.label} className={cls}>{body}</div>;
        })}
      </div>}
      {footer && <div className="foot">{footer}</div>}
    </article>
  );
}

/** The cards, as many across as fit. */
export function IdentityCards({ children }: { children: ReactNode }) {
  return <div className="gl-ids">{children}</div>;
}

/** One thing that wants the owner: what, and the button that takes them to it. */
export type AttentionItem = { key: string; tone: Tone; text: ReactNode; action?: ReactNode };

/**
 * What wants the owner now, as a short list beside the identities (under the tiles on a phone): the
 * page's own numbers turned into things to do. Nothing in it is a number the page did not read.
 */
export function Attention({ items, failed, title = "Needs you" }: { items: AttentionItem[]; failed?: ReactNode; title?: string }) {
  return (
    <section className="gl-side" aria-label={title}>
      <h2>{title}</h2>
      {failed ?? (items.length === 0
        ? <p className="muted">Nothing needs you right now.</p>
        : (
          <ul>
            {items.map((it) => (
              <li key={it.key} className={toneClass(it.tone).trim() || undefined}>
                <span className="t">{it.text}</span>
                {it.action}
              </li>
            ))}
          </ul>
        ))}
    </section>
  );
}

/** The identities and what needs the owner, side by side on a wide screen and stacked on a phone. */
export function GlanceBody({ side, children }: { side: ReactNode; children: ReactNode }) {
  return <div className="gl-body">{side}<div className="gl-main">{children}</div></div>;
}

/** The overview's shape while it loads: the strip, the tiles and a card, as quiet blocks. No motion. */
export function GlanceSkeleton({ strip, cards = 1 }: { strip?: boolean; cards?: number }) {
  return (
    <div aria-busy="true" aria-label="Loading">
      {strip && <div className="gl-skel strip" />}
      <div className="gl-tiles">{[0, 1, 2, 3].map((i) => <div key={i} className="gl-skel" />)}</div>
      <div className="gl-ids">{Array.from({ length: cards }, (_, i) => <div key={i} className="gl-skel card" />)}</div>
    </div>
  );
}

/**
 * An id, said by its name, with the id one step away: in the tooltip, and under the name, short, as
 * a button that copies the whole of it. A name the page could not resolve says what it knows —
 * "removed owner", "deleted key", "a contact" — in a quieter face, and the id is still there: the
 * trail stays verifiable whatever became of what it names.
 */
export function Named({ n, note }: { n: NamedId; note?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard?.writeText(n.id).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); });
  };
  return (
    <span className="nm" title={n.id || undefined}>
      <span className={"nm-name" + (n.state === "named" ? "" : " " + n.state)}>
        {n.name}{n.state === "revoked" && <> <Badge tone="bad">revoked</Badge></>}
      </span>
      {n.id && (
        <span className="nm-sub">
          {note && <span className="nm-note">{note}</span>}
          {(
            <button type="button" className="nm-id" onClick={copy} aria-label={`Copy ${n.id}`}>
              {copied ? "copied" : shortId(n.id)}
            </button>
          )}
        </span>
      )}
    </span>
  );
}

/** A row's locator (`resourceParts`): each id by its name, its kind under it, the rest as written. */
export function Locator({ parts }: { parts: Part[] }) {
  return (
    <span className="nm-parts">
      {parts.map((p, i) => "named" in p
        ? <Named key={i} n={p.named} note={p.label} />
        : <code key={i}>{p.text}</code>)}
    </span>
  );
}

/** A details bag (`detailParts`): each member that is an id by its name, the rest as text. */
export function Details({ parts }: { parts: Detail[] }) {
  if (parts.length === 0) return <span className="muted">—</span>;
  return (
    <span className="nm-parts">
      {parts.map((p, i) => "named" in p
        ? <Named key={i} n={p.named} note={p.key.replace(/_/g, " ")} />
        : <span key={i} className="nm-kv">{p.key && <span className="nm-note">{p.key.replace(/_/g, " ")}</span>}{p.text}</span>)}
    </span>
  );
}
