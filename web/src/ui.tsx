// The portal's shared pieces: avatars, the brand mark, line icons, and the
// primitives every view is composed from (see the block at the end).
import type { ReactNode } from "react";

export function initialsOf(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

// A stable colour per name, from a fixed palette that reads on white and dark.
const PALETTE = ["#4E8F7E", "#7A6FB0", "#C08A45", "#5B7FB5", "#B05A7A", "#5E9A5B", "#8A6E4B"];
function hue(name: string): string {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return PALETTE[h % PALETTE.length];
}

export function Avatar({ name, size, me }: { name: string; size?: "sm" | "lg"; me?: boolean }) {
  const cls = "av" + (size ? " " + size : "") + (me ? " me" : "");
  return <span className={cls} style={me ? undefined : { background: hue(name) }} aria-hidden="true">{initialsOf(name)}</span>;
}

export function Mark({ className }: { className?: string }) {
  const id = "mk" + Math.floor(Math.random() * 1e6);
  return (
    <svg className={"mark" + (className ? " " + className : "")} viewBox="0 0 64 64" aria-hidden="true">
      <defs><clipPath id={id}><rect x="6" y="6" width="34" height="34" rx="11" /></clipPath></defs>
      <rect className="mk" x="6" y="6" width="34" height="34" rx="11" />
      <rect className="mk" x="24" y="24" width="34" height="34" rx="11" />
      <rect className="hi" x="24" y="24" width="34" height="34" rx="11" clipPath={`url(#${id})`} />
    </svg>
  );
}

export function Brand({ small }: { small?: boolean }): ReactNode {
  return (
    <>
      <Mark />
      <span className="wm">PACT{!small && <small>gateway</small>}</span>
    </>
  );
}

// Line icons in one style (1.8 stroke, round caps) — the same family as the
// sidebar's, so nothing in the inbox is an emoji rendered by whatever font the
// visitor's OS ships.
const PATHS: Record<string, string> = {
  clip: "M21.4 11.1l-8.6 8.6a5.5 5.5 0 0 1-7.8-7.8l9-9a3.7 3.7 0 0 1 5.2 5.2l-9 9a1.8 1.8 0 0 1-2.6-2.6l8.3-8.3",
  link: "M10 13a5 5 0 0 0 7 .5l3-3a5 5 0 0 0-7-7l-1.5 1.5M14 11a5 5 0 0 0-7-.5l-3 3a5 5 0 0 0 7 7l1.5-1.5",
  warn: "M12 9v4M12 17h.01M10.3 3.9L2.5 17.5A2 2 0 0 0 4.2 20.5h15.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
  tool: "M14.7 6.3a4 4 0 0 0 5 5L14 17a2 2 0 0 1-3 0l-1-1a2 2 0 0 1 0-3l5.7-5.7zM4 20l4-4",
  close: "M6 6l12 12M18 6L6 18",
  back: "M15 5l-7 7 7 7",
  menu: "M4 7h16M4 12h16M4 17h16",
  // a window with its right column: the contact panel
  panel: "M3 5h18v14H3zM15 5v14",
  // arrows out of / into the corners: full-width thread, and back
  expand: "M15 4h5v5M9 20H4v-5M20 4l-6 6M4 20l6-6",
  collapse: "M10 4v5H5M14 20v-5h5M10 9L4 3M14 15l6 6",
  plus: "M12 5v14M5 12h14",
  file: "M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5M9 13h6M9 17h6",
  image: "M4 6a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zM8.5 10a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3zM20 15l-5-5-8 8",
  calendar: "M4 7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zM4 11h16M8 3v4M16 3v4",
  calendarCheck: "M4 7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zM4 11h16M8 3v4M16 3v4M9 16l2 2 4-4",
  calendarX: "M4 7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zM4 11h16M8 3v4M16 3v4M10 15l4 4M14 15l-4 4",
  activity: "M3 12h4l3-8 4 16 3-8h4",
  plug: "M9 3v5M15 3v5M6 8h12v3a6 6 0 0 1-12 0zM12 17v4",
  spark: "M12 3l2.2 5.8L20 11l-5.8 2.2L12 19l-2.2-5.8L4 11l5.8-2.2z",
  copy: "M8 8h11v11H8zM5 16H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h11a1 1 0 0 1 1 1v1",
  refresh: "M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5",
  trash: "M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3",
  external: "M14 4h6v6M20 4l-9 9M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5",
  check: "M5 12l4 4L19 7",
  chevron: "M9 6l6 6-6 6",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
  logout: "M10 17l5-5-5-5M15 12H3M14 4h5a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-5",
  people: "M15 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0zM4 21v-1a5 5 0 0 1 5-5h6a5 5 0 0 1 5 5v1",
  inbox: "M4 5h16v11H8l-4 4z",
  card: "M3 6h18v12H3zM7 10h6M7 14h4",
  home: "M4 11l8-7 8 7v9h-5v-6H9v6H4z",
  key: "M15 7a4 4 0 1 1-4 4l-7 7v3h3l1-1v-2h2v-2h2l1-1a4 4 0 0 1 2-8z",
  shield: "M12 3l7 4v5c0 4.5-3 8-7 9-4-1-7-4.5-7-9V7z",
  cog: "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM4 12h2M18 12h2M12 4v2M12 18v2M6.3 6.3l1.4 1.4M16.3 16.3l1.4 1.4M6.3 17.7l1.4-1.4M16.3 7.7l1.4-1.4",
  list: "M4 6h16M4 12h16M4 18h10",
  rail: "M11 17l-5-5 5-5M18 17l-5-5 5-5",
  unrail: "M13 7l5 5-5 5M6 7l5 5-5 5",
  clock: "M12 7v5l3 2M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z",
  tick: "M4 12l5 5L20 6",
  ticks: "M2 12l5 5L17 6M12.5 16.5L22 6",
};
export function Icon({ name, size }: { name: keyof typeof PATHS; size?: number }) {
  const px = size ?? 16;
  return (
    <svg className="ic" width={px} height={px} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={PATHS[name]} />
    </svg>
  );
}

/* ------------------------------------------------------------------------
 * The portal's primitives. Every page is composed from these and nothing
 * else: one page header, one section, one toolbar, one button set, one field,
 * one badge set, one list row, one table, one notice, one empty state, one
 * readout. A view that needs something these cannot express changes the
 * primitive, not the view — the rule the lint on inline styles enforces.
 * ---------------------------------------------------------------------- */
import { Children, cloneElement, isValidElement, useEffect, useId, useRef, useState, type MouseEvent, type ReactElement } from "react";
import { Link } from "./router";

export type IconName = keyof typeof PATHS;

// PageHeader: crumb to the parent (the only back affordance a page has), the
// title with badges beside it, the description under it, actions on the right.
export function PageHeader({ title, sub, parent, meta, leading, actions }: {
  title: ReactNode; sub?: ReactNode; parent?: { to: string; label: string }; meta?: ReactNode; leading?: ReactNode; actions?: ReactNode;
}) {
  return (
    <header className="page-h">
      <div className="page-t">
        {parent && <nav className="crumb" aria-label="Parent"><Link to={parent.to}><Icon name="back" size={14} /> {parent.label}</Link></nav>}
        <div className="page-tt">
          {leading}
          <div>
            <h1>{title}{meta && <span className="meta">{meta}</span>}</h1>
            {sub && <p className="sub">{sub}</p>}
          </div>
        </div>
      </div>
      {actions && <div className="actions">{actions}</div>}
    </header>
  );
}

// Section: the one card. `footer` is its action row; `sticky` pins it to the
// bottom of the viewport (a save bar); `collapsible` renders a disclosure.
export function Section({ title, description, meta, footer, tone, collapsible, open, sticky, className, children }: {
  title?: ReactNode; description?: ReactNode; meta?: ReactNode; footer?: ReactNode; tone?: "danger"; collapsible?: boolean; open?: boolean; sticky?: boolean; className?: string; children?: ReactNode;
}) {
  const cls = "card" + (tone ? " " + tone : "") + (sticky ? " sticky" : "") + (className ? " " + className : "");
  const head = title && <>{title}{meta && <span className="meta">{meta}</span>}</>;
  const body = (
    <>
      {description && <p className="help">{description}</p>}
      {children}
      {footer && <div className="toolbar foot">{footer}</div>}
    </>
  );
  if (collapsible) {
    return (
      <details className={cls} open={open}>
        <summary><h2>{head}</h2></summary>
        <div className="card-body">{body}</div>
      </details>
    );
  }
  return <section className={cls}>{head && <h2>{head}</h2>}{body}</section>;
}

// Toolbar: the only container buttons live in. `end` is right-aligned.
export function Toolbar({ children, end, className }: { children?: ReactNode; end?: ReactNode; className?: string }) {
  return <div className={"toolbar" + (className ? " " + className : "")}>{children}{end && <span className="end">{end}</span>}</div>;
}

export type ButtonVariant = "primary" | "secondary" | "quiet" | "danger" | "link";
export function Button({ variant = "primary", to, href, download, icon, busy, confirm, disabled, type = "button", form, onClick, title, id, className, children, ...rest }: {
  variant?: ButtonVariant; to?: string; href?: string; download?: string; icon?: IconName; busy?: boolean; confirm?: string;
  disabled?: boolean; type?: "button" | "submit"; form?: string; onClick?: (e: MouseEvent) => void; title?: string; id?: string;
  // className is for behaviour hooks the stylesheet already keys on (.back, .signout…), never for looks.
  className?: string; "aria-label"?: string; "aria-pressed"?: boolean; children?: ReactNode;
}) {
  const cls = "btn " + variant + (icon && !children ? " icon" : "") + (busy ? " busy" : "") + (className ? " " + className : "");
  const inner = <>{icon && <Icon name={icon} size={16} />}{children}</>;
  const click = (e: MouseEvent) => {
    if (confirm && !window.confirm(confirm)) { e.preventDefault(); return; }
    onClick?.(e);
  };
  if (to) return <Link to={to} className={cls} onClick={click} title={title} {...rest}>{inner}</Link>;
  if (href) return <a href={href} download={download} className={cls} onClick={click} title={title} id={id} {...rest}>{inner}</a>;
  return <button type={type} form={form} className={cls} onClick={click} disabled={disabled || busy} aria-busy={busy || undefined} title={title} id={id} {...rest}>{inner}</button>;
}

// Field: label above the control, help below it. `check` puts a checkbox
// or switch inline with its text.
export function Field({ label, help, mono, check, id, children }: { label: ReactNode; help?: ReactNode; mono?: boolean; check?: boolean; id?: string; children: ReactElement }) {
  const helpCls = "help" + (mono ? " mono" : "");
  const auto = useId();
  const fid = id ?? auto;
  const control = isValidElement(children) ? cloneElement(children as ReactElement<{ id?: string }>, { id: fid }) : children;
  if (check) {
    return (
      <div className="field check">
        <label className="inline" htmlFor={fid}>{control}<span>{label}</span></label>
        {help && <p className={helpCls}>{help}</p>}
      </div>
    );
  }
  return (
    <div className="field">
      <label htmlFor={fid}>{label}</label>
      {control}
      {help && <p className={helpCls}>{help}</p>}
    </div>
  );
}

export type Tone = "neutral" | "ok" | "warn" | "bad";
// Outcomes are a bounded vocabulary in Go, but a wide one, and this has to
// colour a row it has never seen. The good and waiting cases are named exactly;
// a refusal is recognised by shape, so a code added tomorrow lands red rather
// than quietly grey — the audit view counts these as refusals, and a refusal
// the portal cannot recognise is one the owner never sees.
const OK = /^(ok|active|live|allowed|paired|set|read|delivered|delivered_on_retry|accepted|sealed|connected|rebuilt|started|stopped)$/;
const WARN = /^(connecting|pending|pending_in|pending_out|pending_approval|write|waiting|retrying|queued|late|skipped|replayed)$/;
const BAD = /(denied|error|failed|refused|reject|invalid|unreachable|unavailable|expired|revoked|blocked|mismatch|_required|unknown|^not_|too_large|missing|unreadable|^bad_|stale|undelivered)/;
export function toneOf(status: string): Tone {
  if (OK.test(status)) return "ok";
  if (WARN.test(status)) return "warn";
  if (BAD.test(status)) return "bad";
  return "neutral";
}
// Badge: four tones × {text, mono, count}. `status` derives tone and label.
export function Badge({ tone, mono, count, status, title, children }: { tone?: Tone; mono?: boolean; count?: boolean; status?: string; title?: string; children?: ReactNode }) {
  const t = tone ?? (status ? toneOf(status) : "neutral");
  const cls = "pill" + (t !== "neutral" ? " " + t : "") + (mono ? " mono" : "") + (count ? " count" : "");
  return <span className={cls} title={title}>{children ?? status?.replace(/_/g, " ")}</span>;
}

// Tabs: route tabs (`to`) and state filters (`onSelect`) are the same control.
export function Tabs({ items, active, onSelect }: { items: { key: string; label: ReactNode; to?: string; count?: number; urgent?: boolean }[]; active: string; onSelect?: (k: string) => void }) {
  return (
    <nav className="tabs">
      {items.map((it) => {
        const cls = "tab" + (it.key === active ? " on" : "");
        const body = <>{it.label}{it.count !== undefined && <Badge count tone={it.urgent ? "warn" : "neutral"}>{it.count}</Badge>}</>;
        return it.to
          ? <Link key={it.key} to={it.to} className={cls}>{body}</Link>
          : <button key={it.key} type="button" className={cls} onClick={() => onSelect?.(it.key)} aria-pressed={it.key === active}>{body}</button>;
      })}
    </nav>
  );
}

// List / ListRow: a bordered list of records. A long description clamps to
// two lines and the row itself offers more/less.
export function List({ children, empty, "aria-label": label }: { children?: ReactNode; empty?: ReactNode; "aria-label"?: string }) {
  const n = Children.count(children);
  return <div className="list" role="list" aria-label={label}>{n === 0 ? (empty ?? <EmptyState title="Nothing here yet" />) : children}</div>;
}
export function ListRow({ leading, title, to, meta, description, trailing, selected, children }: {
  leading?: ReactNode; title: ReactNode; to?: string; meta?: ReactNode; description?: string; trailing?: ReactNode; selected?: boolean; children?: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const long = (description?.length ?? 0) > 140;
  return (
    <div className={"row" + (selected ? " on" : "")} role="listitem">
      {leading && <div className="lead">{leading}</div>}
      <div className="main">
        <div className="title">{to ? <Link to={to}>{title}</Link> : title}</div>
        {meta && <div className="meta">{meta}</div>}
        {description && <div className={"desc" + (open ? " open" : "")}>{description}</div>}
        {long && <div className="desc-more"><Button variant="link" onClick={() => setOpen(!open)}>{open ? "less" : "more"}</Button></div>}
      </div>
      {trailing && <div className="trail">{trailing}</div>}
      {children && <div className="body">{children}</div>}
    </div>
  );
}

// Table: owns the overflow wrapper and the empty row.
export function Table({ head, children, empty }: { head: ReactNode[]; children?: ReactNode; empty?: ReactNode }) {
  const n = Children.count(children);
  return (
    <div className="table-wrap">
      <table>
        <thead><tr>{head.map((h, i) => h === "" ? <th key={i} className="actions" aria-label="Actions" /> : <th key={i}>{h}</th>)}</tr></thead>
        <tbody>{n === 0 ? <tr><td colSpan={head.length}>{empty ?? <EmptyState title="Nothing here yet" />}</td></tr> : children}</tbody>
      </table>
    </div>
  );
}

export type NoticeKind = "ok" | "warn" | "err";
export type Note = { kind: NoticeKind; text: string };
// Notice: one idiom for feedback; `action` holds buttons or a check field.
export function Notice({ kind, title, action, id, children }: { kind: NoticeKind; title?: ReactNode; action?: ReactNode; id?: string; children?: ReactNode }) {
  return (
    <div className={"notice " + kind} role={kind === "err" ? "alert" : "status"} id={id}>
      <div className="body">{title && <strong className="title">{title}</strong>}{children}</div>
      {action && <div className="act">{action}</div>}
    </div>
  );
}

// EmptyState: the only loading and empty rendering.
export function EmptyState({ title, action, loading, children }: { title?: ReactNode; action?: ReactNode; loading?: boolean; children?: ReactNode }) {
  if (loading) return <div className="empty loading" aria-busy="true" />;
  return (
    <div className="empty">
      {title && <h3>{title}</h3>}
      {children && <p>{children}</p>}
      {action && <div className="toolbar center">{action}</div>}
    </div>
  );
}

// Readout: a fingerprint, endpoint, command or signature — mono, breakable,
// optionally copyable.
export function Readout({ value, copy, block }: { value: string; copy?: boolean; block?: boolean }) {
  const [done, setDone] = useState(false);
  const btn = copy && (
    <Button variant="link" title="Copy to clipboard" onClick={() => { navigator.clipboard?.writeText(value).then(() => { setDone(true); setTimeout(() => setDone(false), 1500); }); }}>
      {done ? "Copied" : "Copy"}
    </Button>
  );
  if (block) return <div className="readout block"><code>{value}</code>{btn}</div>;
  return <span className="readout"><code>{value}</code>{btn && <> {btn}</>}</span>;
}

// CsrfFields: what every self-posting form carries.
import { csrf, currentAccount } from "./api";
export function CsrfFields() {
  return <><input type="hidden" name="csrf" value={csrf()} /><input type="hidden" name="account" value={currentAccount()} /></>;
}

// permLabel: the human name of a PACT permission (SPEC §5).
export function permLabel(name: string): string {
  const L: Record<string, string> = {
    "message.text": "Messages", "message.media": "Media & files", "status.view": "See status",
    "calendar.availability": "Availability", "calendar.book": "Book time",
  };
  if (L[name]) return L[name];
  if (name.startsWith("integration.")) {
    const slug = name.slice("integration.".length);
    return slug.charAt(0).toUpperCase() + slug.slice(1) + " tools";
  }
  return name;
}

// Menu: a popover anchored to its trigger — the account switcher today, a row's
// overflow tomorrow. It closes on Escape, on a click outside, and on choosing,
// so no view has to own that behaviour.
export function Menu({ trigger, align = "down", className, label, children }: {
  trigger: ReactNode; align?: "up" | "down"; className?: string; label?: string; children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: Event) => { if (!wrap.current?.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", away); document.removeEventListener("keydown", esc); };
  }, [open]);
  return (
    <div className="menu-wrap" ref={wrap}>
      <button type="button" className={"menu-trigger" + (className ? " " + className : "")}
        aria-haspopup="menu" aria-expanded={open} aria-label={label} onClick={() => setOpen((v) => !v)}>
        {trigger}
      </button>
      {open && <div className={"menu " + align} role="menu" onClick={() => setOpen(false)}>{children}</div>}
    </div>
  );
}

export function MenuItem({ lead, icon, selected, danger, to, onClick, children }: {
  lead?: ReactNode; icon?: IconName; selected?: boolean; danger?: boolean; to?: string; onClick?: () => void; children: ReactNode;
}) {
  const cls = "menu-item" + (selected ? " on" : "") + (danger ? " danger" : "");
  const inner = <>{lead}{icon && <Icon name={icon} size={15} />}<span className="mi-label">{children}</span>{selected && <Icon name="check" size={14} />}</>;
  if (to) return <Link to={to} className={cls} role="menuitem">{inner}</Link>;
  return <button type="button" className={cls} role="menuitem" onClick={onClick}>{inner}</button>;
}

export function MenuHead({ children }: { children: ReactNode }) { return <div className="menu-head">{children}</div>; }
export function MenuSep() { return <div className="menu-sep" role="separator" />; }

// The tools every contact tier carries: the wire's own plumbing, not a
// capability anybody granted. Both the composer's menu and the contact page
// hide them, and they must hide the same set.
export const PLUMBING_TOOLS = new Set([
  "send_message", "send_media", "get_card", "update_contact", "remove_contact",
  "sealed_call", "request_contact", "redeem_invite", "contact_accepted", "contact_rejected",
]);

// toolLabel: a peer's tool name as a person reads it.
export function toolLabel(name: string): string {
  const L: Record<string, string> = {
    get_status: "Status", check_availability: "Availability", book_slot: "Book time", cancel_booking: "Cancel booking",
  };
  return L[name] ?? name.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
}

// Chips: toggleable filters. Tabs are a navigation bar with a rule under them
// and one active item; a filter row is a set of independent switches that can
// all be off, which is a different thing and looked wrong borrowed.
export function Chips({ children, "aria-label": label }: { children?: ReactNode; "aria-label"?: string }) {
  return <div className="chips" role="group" aria-label={label}>{children}</div>;
}

export function Chip({ on, count, tone, onClick, children }: {
  on?: boolean; count?: number; tone?: Tone; onClick?: () => void; children: ReactNode;
}) {
  return (
    <button type="button" className={"chip" + (on ? " on" : "") + (tone && tone !== "neutral" ? " " + tone : "")}
      aria-pressed={on} onClick={onClick}>
      {children}{count !== undefined && <span className="n">{count}</span>}
    </button>
  );
}
