// Audit: the node's append-only log, newest first, with the filters you need to
// find one entry among thousands. Everything filters in the browser against the
// rows already fetched, so a chip answers instantly and the trail is never
// re-queried to narrow it.
//
// Every id a row carries is shown by the name a person knows it by — an owner's
// name, a token's label, a contact's name, an identity's — from the directory
// the answer carries beside its rows (audit_names.ts). The id is in each name's
// tooltip and its copy button, and in view only where no name could be found:
// the trail stays verifiable, it just stops reading like a list of UUIDs.
import { useCallback, useEffect, useMemo, useState } from "react";
import { accountName, currentAccount, failureOf, getJSON } from "../api";
import { aboutParts, actorOf, namedIn, resourceParts, searchText, type Directory, type Named as NamedId, type Part } from "../audit_names";
import { Locator, Named } from "../glance";
import { Badge, Button, Chip, ChipPick, Chips, EmptyState, Notice, PageHeader, Table, Toolbar, toneOf } from "../ui";
import { actionWord, CHIPS_SHOWN, clockOf, kindLabel, whenTitle, withDays } from "../words";

type Row = { Seq: number; TS: number; ActorKind: string; ActorID: string; Action: string; Resource: string; Outcome: string };
type Data = { rows: Row[] | null; actor: string; limit?: number; names?: Directory };

/** A row with its ids said, and the text the search box matches: the row's own, and every name. */
type Said = { row: Row; actor: NamedId; about: Part[]; haystack: string };

export function Audit() {
  const [d, setD] = useState<Data | null>(null);
  // A failed read is said as one. It used to be swallowed, which left the page loading for ever.
  const [err, setErr] = useState("");
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<string | null>(null);
  const [action, setAction] = useState<string | null>(null);
  const [refusedOnly, setRefusedOnly] = useState(false);
  const load = useCallback(() => getJSON<Data>("/api/audit", { limit: "1000" })
    .then((r) => { setD(r); setErr(""); })
    .catch((e) => setErr(failureOf(e))), []);
  useEffect(() => { load(); }, [load]);

  const said = useMemo<Said[]>(() => {
    const names = d?.names ?? {};
    // The trail is the selected identity's (getJSON sends it as `account`), named in the header: a
    // row's own `account:<it>` only repeats it, so it is not drawn. A node-level row names none.
    const here = currentAccount();
    return (d?.rows ?? []).map((row) => {
      const actor = actorOf({ kind: row.ActorKind, id: row.ActorID, action: row.Action, resource: row.Resource }, names);
      const parts = resourceParts(row.Resource, names);
      const raw = `${row.Seq} ${row.ActorKind} ${row.ActorID} ${row.Action} ${row.Resource} ${row.Outcome}`;
      return { row, actor, about: aboutParts(parts, here, actor), haystack: searchText(raw, [actor, ...namedIn(parts)]) };
    });
  }, [d]);
  // A refusal is an outcome the badge already paints red: one definition of
  // "something was denied", shared with every other surface.
  const isRefusal = (r: Row) => toneOf(r.Outcome) === "bad";
  const kinds = useMemo(() => {
    const n: Record<string, number> = {};
    for (const { row: r } of said) n[r.ActorKind || "system"] = (n[r.ActorKind || "system"] ?? 0) + 1;
    return Object.entries(n).sort((a, b) => b[1] - a[1]);
  }, [said]);
  // The actions actually present, commonest first — a fixed list would name
  // things this node has never done and omit the one you are looking for.
  const actions = useMemo(() => {
    const n: Record<string, number> = {};
    for (const { row: r } of said) n[r.Action] = (n[r.Action] ?? 0) + 1;
    // Every one: the commonest have chips, and the rest are in 'More' (they were cut at twelve, and the
    // commonest refusal on a busy node was not among them).
    return Object.entries(n).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }, [said]);
  const refusals = useMemo(() => said.filter((s) => isRefusal(s.row)).length, [said]);

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return said.filter(({ row: r, haystack }) => {
      if (kind && (r.ActorKind || "system") !== kind) return false;
      if (action && r.Action !== action) return false;
      if (refusedOnly && !isRefusal(r)) return false;
      return !needle || haystack.includes(needle);
    });
  }, [said, q, kind, action, refusedOnly]);

  // The trail is one identity's, and the header says whose: the row's own account is left out of each
  // row because this names it (a node-level trail, with no identity chosen, names none).
  const here = currentAccount();
  const header = (
    <PageHeader title="Audit" meta={here ? <Badge>{accountName()}</Badge> : undefined} sub="Append-only and hash-chained; refusals are recorded as loudly as successes."
      actions={<Button variant="secondary" icon="refresh" onClick={load}>Refresh</Button>} />
  );
  if (err) return <main className="wide">{header}<Notice kind="err" title="Could not read the audit trail" action={<Button variant="secondary" onClick={load}>Try again</Button>}>{err}</Notice></main>;
  if (!d) return <main className="wide">{header}<EmptyState loading /></main>;

  const filtering = Boolean(q || kind || action || refusedOnly);
  return (
    <main className="wide">
      {header}
      <Toolbar end={filtering ? <Button variant="quiet" onClick={() => { setQ(""); setKind(null); setAction(null); setRefusedOnly(false); }}>Clear filters</Button> : undefined}>
        <input type="search" placeholder="Search by name or id, action, outcome…" value={q}
          onChange={(e) => setQ(e.target.value)} aria-label="Search the audit trail" />
      </Toolbar>
      <Chips aria-label="Filter by actor and outcome" className="has-picks">
        <Chip on={refusedOnly} tone="bad" count={refusals} onClick={() => setRefusedOnly((v) => !v)}>Refusals</Chip>
        {kinds.map(([k, n]) => (
          <Chip key={k} className="picked" on={kind === k} count={n} title={k} onClick={() => setKind(kind === k ? null : k)}>{kindLabel(k)}</Chip>
        ))}
        <ChipPick label="Filter by actor" all="Anyone" value={kind} options={kinds} onChange={setKind} say={(k) => kindLabel(k)} />
        <ChipPick label="Filter by action" all="Any action" value={action} options={actions} onChange={setAction} say={actionWord} />
      </Chips>
      <Chips aria-label="Filter by action" className="phone-pick">
        {actions.slice(0, CHIPS_SHOWN).map(([a, n]) => (
          <Chip key={a} on={action === a} count={n} title={a} onClick={() => setAction(action === a ? null : a)}>{actionWord(a)}</Chip>
        ))}
        {actions.length > CHIPS_SHOWN && (
          <ChipPick className="chip-more" label="More actions" all={`More (${actions.length - CHIPS_SHOWN})`} value={action}
            options={actions.slice(CHIPS_SHOWN)} onChange={setAction} say={actionWord} />
        )}
      </Chips>
      <p className="muted">
        {shown.length === said.length ? `${said.length} entries` : `${shown.length} of ${said.length} entries`}
        {d.limit !== undefined && said.length >= d.limit && <> · newest {d.limit}; older entries are not loaded</>}
      </p>
      {/* The outcome sits beside the time, where it cannot scroll out of view: this page's promise is
          that a refusal is as loud as a success. */}
      <div className="audit-t">
        <Table stack={false} head={["Seq", "When", "Outcome", "Who", "Action", "About"]}
          empty={<EmptyState title={filtering ? "Nothing matches those filters" : "Nothing recorded yet"} />}>
          {/* A heading for each day; the cell says the clock. The entry's number is in the time's title
              beside the whole instant: it is for checking the chain, not a question of its own. */}
          {withDays(shown, (s) => s.row.TS * 1000).map((x) => "day" in x ? (
            <tr key={x.key} className="day"><td colSpan={6}>{x.day}</td></tr>
          ) : (
            <tr key={x.row.row.Seq}>
              <td className="c-seq">{x.row.row.Seq}</td>
              <td className="c-when" title={`#${x.row.row.Seq} · ${whenTitle(x.row.row.TS * 1000)}`}>{clockOf(x.row.row.TS * 1000, true)}</td>
              <td className="c-out"><Badge status={x.row.row.Outcome} /></td>
              <td className="c-who"><Named n={x.row.actor} note={kindLabel(x.row.row.ActorKind || "system").toLowerCase()} /></td>
              <td className="c-act"><span className="act" title={x.row.row.Action}>{actionWord(x.row.row.Action)}</span></td>
              <td className="c-about" data-resource={x.row.row.Resource}><Locator parts={x.row.about} /></td>
            </tr>
          ))}
        </Table>
      </div>
    </main>
  );
}
