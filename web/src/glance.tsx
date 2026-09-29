// The pieces the overview and the audit trail are built from, for both portals: the node's
// (web/src) and PACT Cloud's (portal/src, copied verbatim from the node commit its portal/HARVESTED
// records). They import only what both portals' ui.tsx and router.tsx export alike, so the copy is
// the file. Their look is the block at the end of style.css headed "the overview at a glance",
// which both stylesheets carry byte for byte.
//
// What the two pages do with them differs — the node's overview leads with reachability, the
// cloud's with the plan — and lives in each portal's own view; what a number, a name, an id or a
// failed read LOOKS like is here once.
import { Fragment, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "./router";
import { Avatar, Badge, Icon, type Tone } from "./ui";
import { detailLabel, kindSaid, nameBreaks, resolved, shortId, type Detail, type Named as NamedId, type Part, type Said } from "./audit_names";
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
      <span className="v">{shown(value)}{!failed && of != null && <small>of {shown(of)}</small>}</span>
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

/** The row the tiles sit in: as many across as fit the page, four on anything wider than a phone. */
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
 * An identity's certificate, said on its card. A current one is a quiet line, not a pill: a pill is
 * for what wants the owner, and a healthy certificate drawn in a coloured pill on every card read as
 * a warning beside the ones that were. A pill holds the state's word ("renewal due"); how long is
 * the muted line beside it.
 */
function CertificateLine({ c }: { c: CertificateView | { failed: string } }) {
  if ("failed" in c) {
    return <span className="gl-cert"><Badge tone="bad" title={c.failed}>unreadable</Badge><span className="muted">the certificate could not be read</span></span>;
  }
  const title = c.until ? `not after ${new Date(c.until).toUTCString()}` : undefined;
  if (c.tone === "ok" || c.tone === "neutral") {
    return <span className="gl-cert muted" title={title}>{c.tone === "ok" ? "Certificate " : ""}{c.text}{c.detail ? ` · ${c.detail}` : ""}</span>;
  }
  return <span className="gl-cert" title={title}><Badge tone={c.tone}>{c.text}</Badge>{c.detail && <span className="muted">{c.detail}</span>}</span>;
}

/**
 * One identity, at a glance: who, where they are reached, whether their certificate is current, and
 * their numbers — each a link to where it is explained. `onClick` on a count is how a card for an
 * identity other than the selected one selects it before the link lands. A page that shows the same
 * numbers in its tiles (one identity) passes no counts.
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
        <div className="who"><b title={name}>{name}</b>{handle && <small>{handle}</small>}</div>
        {status}
      </div>
      {address && <div className="addr">{address}</div>}
      <div className="cert"><CertificateLine c={certificate} /></div>
      {counts.length > 0 && <div className="counts">
        {counts.map((c) => {
          const failed = c.value === null;
          const cls = toneClass(failed ? "bad" : c.tone).trim() || undefined;
          const body = <><b>{shown(c.value)}{!failed && c.of != null && <small> / {shown(c.of)}</small>}</b><span>{failed ? `${c.label}: could not read` : c.label}</span></>;
          return c.to && !failed
            ? <Link key={c.label} to={c.to} className={cls} onClick={c.onClick}>{body}</Link>
            : <div key={c.label} className={cls}>{body}</div>;
        })}
      </div>}
      {footer && <div className="foot">{footer}</div>}
    </article>
  );
}

/** The cards, as many across as fit; a lone card is not stretched across the page. */
export function IdentityCards({ children }: { children: ReactNode }) {
  return <div className="gl-ids">{children}</div>;
}

/** One thing that wants the owner: what, and the button that takes them to it. */
export type AttentionItem = { key: string; tone: Tone; text: ReactNode; action?: ReactNode };

/**
 * What wants the owner now: the page's own numbers turned into things to do, first on the page when
 * there are any, each with the button that does it. With nothing to do it is one quiet line, not a
 * box. Nothing in it is a number the page did not read.
 */
export function Attention({ items, failed, title = "Needs you" }: { items: AttentionItem[]; failed?: ReactNode; title?: string }) {
  if (!failed && items.length === 0) return <p className="gl-quiet">Nothing needs you right now.</p>;
  return (
    <section className="gl-needs" aria-label={title}>
      <h2>{title}</h2>
      {failed ?? (
        <ul>
          {items.map((it) => (
            <li key={it.key} className={toneClass(it.tone).trim() || undefined}>
              <span className="t">{it.text}</span>
              {it.action}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
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
 * The button that copies a whole id: an icon, named for a screen reader by what it copies. It is
 * drawn when its row is hovered or holds the focus (and always on a screen with no hover), so a
 * table of names does not read as a table of buttons.
 */
export function CopyId({ id }: { id: string }) {
  const [done, setDone] = useState(false);
  const copy = () => {
    navigator.clipboard?.writeText(id).then(() => { setDone(true); setTimeout(() => setDone(false), 1500); });
  };
  return (
    <button type="button" className={"nm-copy" + (done ? " done" : "")} onClick={copy} aria-label={`Copy ${id}`} title={done ? "Copied" : `Copy ${id}`}>
      <Icon name={done ? "check" : "copy"} size={12} />
    </button>
  );
}

/** An id that has no name to stand in for it: its head and tail, the whole of it in the tooltip, and a copy button. */
export function IdText({ id }: { id: string }) {
  return <span className="nm-idt"><span className="nm-id" title={id}>{shortId(id)}</span><CopyId id={id} /></span>;
}

/** Text that may break after its dots and underscores (a tool's name, an action), and nowhere else. */
export function Breakable({ text }: { text: string }) {
  const bits = text.split(/(?<=[._])/);
  return <>{bits.map((b, i) => <span key={i}>{b}{i < bits.length - 1 && <wbr />}</span>)}</>;
}

/**
 * An id, said by its name. A name that says who it is shows nothing else: the whole id is in the
 * tooltip, and the copy button beside it copies it. A name the page could not resolve ("removed
 * owner", "not in your contacts") is drawn in a quieter face and keeps its id, short, in view — there
 * the id is the one thing that tells two of them apart — so the trail stays verifiable whatever became
 * of what it names; such a name is short and the page's own, so it is never cut to two lines. Nor is
 * an operator's: "PACT Cloud · <their address>" is the one fact that says which of ours acted. `note`
 * is the kind, said quietly after a name somebody chose, where the name does not say it already.
 */
export function Named({ n, note }: { n: NamedId; note?: string }) {
  const known = resolved(n);
  return (
    <span className="nm" title={n.id ? `${n.name}\n${n.id}` : n.name}>
      <span className={"nm-t" + (known ? "" : " quiet") + (n.kind === "operator" ? " whole" : "")}>
        <span className="nm-name"><NameText name={n.name} /></span>
        {n.state === "revoked" && <> <Badge tone="bad">revoked</Badge></>}
        {note && !kindSaid(n) && <span className="nm-note">{note}</span>}
        {!known && n.id && <span className="nm-id">{shortId(n.id)}</span>}
      </span>
      {n.id && <CopyId id={n.id} />}
    </span>
  );
}

/**
 * A name, breakable only where `nameBreaks` says: between words, after an address's `@`, after a
 * handle's underscores and dots. A piece too long for any column may break anywhere (`nm-long`).
 */
function NameText({ name }: { name: string }) {
  return <>{nameBreaks(name).map((run, r) => run.map((p, i) => (
    <Fragment key={`${r}.${i}`}>{i > 0 && <wbr />}{p.long ? <span className="nm-long">{p.text}</span> : p.text}</Fragment>
  )))}</>;
}

/** A labelled value, the way a locator and a details bag are both drawn: a faint key, then the value. */
function KV({ k, children }: { k: string; children: ReactNode }) {
  return <span className="nm-kv">{k && <span className="nm-k">{k}</span>}{children}</span>;
}

/** A locator's or a detail's value, drawn by what it is. */
function valueOf(p: Detail | Part): ReactNode {
  if ("named" in p) return <Named n={p.named} />;
  if ("at" in p) return <span title={new Date(p.at).toString()}>{whenOf(p.at)}</span>;
  if ("items" in p) {
    return <>{p.items.map((x, i) => <span key={i}>{i > 0 && ", "}{typeof x === "string" ? <Breakable text={x} /> : <Named n={x} />}</span>)}</>;
  }
  if ("url" in p) return <UrlText url={p.url} />;
  if ("id" in p && p.id) return <IdText id={p.text} />;
  return <Breakable text={p.text} />;
}

/** An address: its host and the start of its path, the whole of it in the tooltip, and a copy button. */
function UrlText({ url }: { url: string }) {
  let shown = url;
  try {
    const u = new URL(url);
    const path = u.pathname === "/" ? "" : u.pathname.length > 18 ? `${u.pathname.slice(0, 16)}…` : u.pathname;
    shown = u.host + path;
  } catch {
    // Not a URL after all: said as written.
  }
  return <span className="nm-url"><span title={url}>{shown}</span><CopyId id={url} /></span>;
}

/**
 * A row's locator (`resourceParts`, less what `aboutParts` leaves out): each part a faint label and
 * its value — an id by its name, a tool by its name, an opaque id short with a copy button.
 */
export function Locator({ parts }: { parts: Part[] }) {
  if (parts.length === 0) return <span className="muted">—</span>;
  return (
    <span className="nm-parts">
      {parts.map((p, i) => "named" in p
        ? <KV key={i} k={detailLabel(p.label)}><Named n={p.named} /></KV>
        : "key" in p ? <KV key={i} k={detailLabel(p.key)}>{valueOf(p)}</KV>
        : <span key={i} className="nm-kv">{p.text}</span>)}
    </span>
  );
}

/**
 * A details bag (`detailParts`): what the event says, as labelled values in one wrapping line, and
 * then the door and credential it came through ("via portal", "via Claude Desktop"). Two lines at
 * most until asked for more, so one long reason does not make every row tall.
 */
export function Details({ said }: { said: Said }) {
  const [open, setOpen] = useState(false);
  const [long, setLong] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  useLayoutEffect(() => {
    const el = ref.current;
    if (el && !open) setLong(el.scrollHeight > el.clientHeight + 1);
  }, [said, open]);
  const { parts, via, credential } = said;
  if (parts.length === 0 && !via && !credential) return <span className="muted">—</span>;
  return (
    <span className="nm-det-wrap">
      <span ref={ref} className={"nm-det" + (open ? " open" : "")}>
        {parts.map((p, i) => <KV key={i} k={detailLabel(p.key)}>{valueOf(p)}</KV>)}
        {(via || credential) && (
          <span className="nm-kv nm-via">
            <span className="nm-k">via</span>
            {credential ? <Named n={credential} note={credential.kind === "grant" ? "app" : "key"} /> : via}
          </span>
        )}
      </span>
      {(long || open) && <button type="button" className="nm-more" onClick={() => setOpen(!open)}>{open ? "less" : "more"}</button>}
    </span>
  );
}

/**
 * When, said for a trail read from the present backwards: the time for today, the weekday and time
 * within the week, the date after that. The tooltip beside it carries the whole instant.
 */
export function whenOf(ms: number, now = Date.now()): string {
  const d = new Date(ms);
  const today = new Date(now);
  if (d.toDateString() === today.toDateString()) return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const days = (today.getTime() - d.getTime()) / 86_400_000;
  if (days > 0 && days < 6) return d.toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" });
  if (d.getFullYear() === today.getFullYear()) return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  return d.toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" });
}
