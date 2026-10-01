// The shell: a sidebar with the brand, the places, and the identity you are
// acting as — the same rules the server-rendered portal had: no chrome on the
// login and setup views, and every bind needs a session (§8.3).
import { useEffect, useState } from "react";
import type { ReactElement } from "react";
import { Link, RouterProvider, usePath, navigate } from "./router";
import { currentAccount, fetchSession, getJSON, onAccountChange, onSessionChange, postForm, setAccount, subscribe } from "./api";
import type { LiveEvent } from "./api";
import type { Session } from "./api";
import { Avatar, Brand, Button, CountChip, EmptyState, Icon, Menu, MenuHead, MenuItem, MenuSep, PageHeader, tallyCount, titleWithTally, type Tally } from "./ui";
import { Dashboard } from "./views/dashboard";
import { People } from "./views/people";
import { ContactDetail } from "./views/contact_detail";
import { Messages } from "./views/messages";
import { CardView } from "./views/card";
import { Integrations } from "./views/integrations";
import { Exposure } from "./views/exposure";
import { Identity } from "./views/identity";
import { Owners } from "./views/owners";
import { Settings } from "./views/settings";
import { Audit } from "./views/audit";
import { Login } from "./views/login";
import { Setup } from "./views/setup";

// `counts` is what the link's badge counts, as a screen reader hears it after the number ('7 unread').
type Item = { to: string; label: string; icon: string; match?: string[]; counts?: string };
const PLACES: Item[] = [
  { to: "/messages", label: "Inbox", icon: "inbox", counts: "unread" },
  { to: "/contacts", label: "People", icon: "people", match: ["/contacts", "/requests", "/invites"], counts: "requests waiting" },
  { to: "/card", label: "My card", icon: "card" },
  { to: "/integrations", label: "Integrations", icon: "plug" },
];
const SIDE_KEY = "pact.side";
const NODE: Item[] = [
  { to: "/", label: "Overview", icon: "home" },
  { to: "/identity", label: "Identity", icon: "key" },
  { to: "/owners", label: "Owners", icon: "shield" },
  { to: "/settings", label: "Settings", icon: "cog" },
  { to: "/audit", label: "Audit", icon: "list" },
];


export function App() {
  return (
    <RouterProvider>
      <Root />
    </RouterProvider>
  );
}

function Root() {
  const path = usePath();
  const [session, setSession] = useState<Session | null>(null);
  const [account, setAcct] = useState(currentAccount());
  const [open, setOpen] = useState(false);
  // The sidebar can fold to an icon rail; the choice persists per browser.
  const [mini, setMini] = useState<boolean>(() => { try { return localStorage.getItem(SIDE_KEY) === "1"; } catch { return false; } });
  const toggleMini = () => setMini((v) => { try { localStorage.setItem(SIDE_KEY, v ? "0" : "1"); } catch { /* ignore */ } return !v; });
  useEffect(() => onAccountChange(() => setAcct(currentAccount())), []);
  // Re-read on every navigation, not only across auth transitions: an identity
  // created on the Identity page changes which accounts exist and which one is
  // selected, and a shell that learns that only on reload sends every write
  // with no account — which, with two identities, the node cannot fill in.
  useEffect(() => {
    fetchSession().then(setSession).catch(() => setSession(null));
  }, [path]);
  useEffect(() => onSessionChange(setSession), []);
  useEffect(() => setOpen(false), [path]); // the drawer closes on every navigation

  if (session === null) return null; // first paint: nothing beats a flash of the wrong view

  // §8.3: with zero passkeys the portal leads to the wizard and nowhere else.
  // location.search comes ALONG: on a non-loopback first run the setup token is
  // in it, and the wizard's own gate refuses without one — dropping it here
  // would redirect the owner from a working link to a 403.
  if (session.needs_setup && path !== "/setup") {
    navigate("/setup" + location.search);
    return null;
  }
  // Before the session check: this is also the recovery path, reached with a
  // token while passkeys exist. The server decides whether it opens (§8.6).
  if (path === "/setup") return <Setup />;
  if (path === "/login") return <Login />;
  // No session, no portal — on every bind (§8.3).
  if (!session.signed_in) return <Login />;

  const view = route(path, account);
  const me = session.accounts.find((a) => a.id === account) ?? session.accounts[0];
  return (
    <div className={"shell" + (mini ? " side-min" : "")}>
      <div className="topbar">
        <button className="nav-toggle" onClick={() => setOpen(true)} aria-label="Open navigation"><Icon name="menu" /></button>
        <Link className="side-brand" to="/"><Brand /></Link>
      </div>
      {open && <div className="scrim" onClick={() => setOpen(false)} />}
      <aside className={"side" + (open ? " open" : "")} aria-label="Navigation">
        <div className="side-top">
          <Link className="side-brand" to="/"><Brand /></Link>
          <button className="rail-btn" onClick={toggleMini} title={mini ? "Expand sidebar" : "Collapse sidebar"} aria-label={mini ? "Expand sidebar" : "Collapse sidebar"} aria-pressed={mini}>
            <Icon name={mini ? "unrail" : "rail"} />
          </button>
        </div>
        <Counts>
          {(counts) => (
            <nav className="side-nav">
              <div className="grp"><span>Your agent</span></div>
              {PLACES.map((it) => <NavLink key={it.to} it={it} path={path}
                badge={it.to === "/messages" ? counts.unread : it.to === "/contacts" ? counts.pending : 0}
                warn={it.to === "/contacts"} />)}
              <div className="grp"><span>This node</span></div>
              {NODE.map((it) => <NavLink key={it.to} it={it} path={path} />)}
            </nav>
          )}
        </Counts>
        <div className="side-foot">
          {/* One control for who you are acting as: the identity you are using,
              and — behind it — the others, the identity page and signing out.
              The name used to be printed twice, once as a label and once inside
              a bare <select> that was the only unstyled control in the shell. */}
          {me && (
            <Menu align="up" className="acct-btn" label="Account and identity" trigger={<>
              <Avatar name={me.display_name} me />
              <span className="who"><b>{me.display_name}</b><small>{me.slug}</small></span>
              <Icon name="chevron" size={14} />
            </>}>
              {session.accounts.length > 1 && <MenuHead>Acting as</MenuHead>}
              {session.accounts.length > 1 && session.accounts.map((a) => (
                <MenuItem key={a.id} selected={a.id === me.id} onClick={() => setAccount(a.id)}
                  lead={<Avatar name={a.display_name} size="sm" me={a.id === me.id} />}>
                  <b>{a.display_name}</b><small>{a.slug}</small>
                </MenuItem>
              ))}
              {session.accounts.length > 1 && <MenuSep />}
              <MenuItem icon="key" to="/identity">Manage identities</MenuItem>
              <MenuItem icon="logout" danger onClick={async () => { await postForm("/logout", {}); location.href = "/login"; }}>Sign out</MenuItem>
            </Menu>
          )}
        </div>
      </aside>
      <div className="content">{view}</div>
    </div>
  );
}

function NavLink({ it, path, badge, warn }: { it: Item; path: string; badge?: Tally; warn?: boolean }) {
  const active = it.to === "/" ? path === "/" : (it.match ?? [it.to]).some((p) => path.startsWith(p));
  return (
    <Link to={it.to} className={active ? "active" : undefined} title={it.label}>
      <Icon name={it.icon} />
      <span className="lbl">{it.label}</span>
      {badge !== undefined && tallyCount(badge) > 0 ? <CountChip n={badge} noun={it.counts} tone={warn ? "warn" : "ok"} /> : null}
    </Link>
  );
}

// Unread messages and waiting requests, kept fresh by the event stream so the
// sidebar tells you before you go looking. The tab title carries the count, and
// a message that arrives while you are looking elsewhere gets a toast that
// opens it — the sidebar badge alone is easy to miss mid-task.
type Toast = { id: number; fpr: string; label: string };
//
// `unread` is the Inbox chip as the node counted it (GET /api/conversations `unread`): the sum over the
// page of conversations, `capped` when that is a floor — a conversation stopped at its cap, or one past
// the page has unread too — so it reads "50+". It used to be summed here from the rows' numbers, which
// the node never filled.
function Counts({ children }: { children: (c: { unread: Tally; pending: number }) => ReactElement }) {
  const [c, setC] = useState<{ unread: Tally; pending: number }>({ unread: 0, pending: 0 });
  const [toasts, setToasts] = useState<Toast[]>([]);
  useEffect(() => {
    let alive = true;
    let labels: Record<string, string> = {};
    const load = (e?: LiveEvent) => {
      Promise.all([
        getJSON<{ contacts: { fingerprint: string; label: string }[] | null; unread: Tally }>("/api/conversations").then((d): Tally => {
          labels = Object.fromEntries((d.contacts ?? []).map((p) => [p.fingerprint, p.label]));
          return d.unread ?? 0;
        }).catch((): Tally => 0),
        getJSON<{ pending: unknown[] | null }>("/api/requests").then((d) => (d.pending ?? []).length).catch(() => 0),
      ]).then(([unread, pending]) => {
        if (!alive) return;
        setC({ unread, pending });
        // A message about a contact whose conversation is not on screen right now.
        if (e?.kind === "message" && e.contact_fpr) {
          const viewing = location.pathname === "/messages" && new URLSearchParams(location.search).get("contact") === e.contact_fpr && document.visibilityState === "visible";
          if (!viewing) {
            const id = Date.now();
            setToasts((t) => [...t.slice(-2), { id, fpr: e.contact_fpr!, label: labels[e.contact_fpr!] ?? "a contact" }]);
            setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 8000);
          }
        }
      });
    };
    load();
    const off = subscribe(load);
    const offAcct = onAccountChange(() => load());
    // The Inbox marked a conversation read (views/messages.tsx): the chip drops now, not at the next event.
    const onRead = () => load();
    addEventListener("pact:counts", onRead);
    return () => { alive = false; off(); offAcct(); removeEventListener("pact:counts", onRead); };
  }, []);
  useEffect(() => {
    document.title = titleWithTally(document.title, c.unread);
  }, [c.unread]);
  return (
    <>
      {children(c)}
      {toasts.length > 0 && (
        <div className="toasts" aria-live="polite">
          {toasts.map((t) => (
            <Link key={t.id} to={"/messages?contact=" + encodeURIComponent(t.fpr)} className="toast" onClick={() => setToasts((x) => x.filter((y) => y.id !== t.id))}>
              <span className="dot online" />
              <span><b>New message</b> from {t.label}</span>
            </Link>
          ))}
        </div>
      )}
    </>
  );
}

function route(path: string, account: string) {
  // `account` participates so every view remounts when the identity changes.
  const seg = path.split("/").filter(Boolean);
  const key = account + ":" + path;
  if (path === "/" || path === "") return <Dashboard key={key} />;
  if (path === "/contacts" || path === "/requests" || path === "/invites") return <People key={key} />;
  if (seg[0] === "contacts" && seg.length === 2) return <ContactDetail key={key} fpr={decodeURIComponent(seg[1])} />;
  if (path === "/messages" || path === "/inbox") return <Messages key={key} />;
  if (path === "/card") return <CardView key={key} />;
  if (path === "/integrations") return <Integrations key={key} />;
  if (seg[0] === "integrations" && seg[2] === "exposure") return <Exposure key={key} id={decodeURIComponent(seg[1])} />;
  if (path === "/identity") return <Identity key={key} />;
  if (path === "/owners") return <Owners key={key} />;
  if (path === "/settings") return <Settings key={key} />;
  if (path === "/audit") return <Audit key={key} />;
  return (
    <main>
      <PageHeader title="Not here" />
      <EmptyState action={<Button variant="secondary" to="/">Back to the overview</Button>}>
        Nothing lives at <code>{path}</code>.
      </EmptyState>
    </main>
  );
}
