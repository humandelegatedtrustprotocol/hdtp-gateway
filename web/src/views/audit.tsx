// Audit: the node's append-only log, newest first, with the filters you need to
// find one entry among thousands. Everything filters in the browser against the
// rows already fetched, so a chip answers instantly and the trail is never
// re-queried to narrow it.
import { useCallback, useEffect, useMemo, useState } from "react";
import { getJSON } from "../api";
import { Badge, Button, Chip, Chips, EmptyState, PageHeader, Readout, Table, Toolbar, toneOf } from "../ui";

type Row = { Seq: number; TS: number; ActorKind: string; ActorID: string; Action: string; Resource: string; Outcome: string };
type Data = { rows: Row[] | null; actor: string; limit?: number };

export function Audit() {
  const [d, setD] = useState<Data | null>(null);
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<string | null>(null);
  const [action, setAction] = useState<string | null>(null);
  const [refusedOnly, setRefusedOnly] = useState(false);
  const load = useCallback(() => getJSON<Data>("/api/audit", { limit: "1000" }).then(setD).catch(() => {}), []);
  useEffect(() => { load(); }, [load]);

  const rows = useMemo(() => d?.rows ?? [], [d]);
  // A refusal is an outcome the badge already paints red: one definition of
  // "something was denied", shared with every other surface.
  const isRefusal = (r: Row) => toneOf(r.Outcome) === "bad";
  const kinds = useMemo(() => {
    const n: Record<string, number> = {};
    for (const r of rows) n[r.ActorKind || "system"] = (n[r.ActorKind || "system"] ?? 0) + 1;
    return Object.entries(n).sort((a, b) => b[1] - a[1]);
  }, [rows]);
  // The actions actually present, commonest first — a fixed list would name
  // things this node has never done and omit the one you are looking for.
  const actions = useMemo(() => {
    const n: Record<string, number> = {};
    for (const r of rows) n[r.Action] = (n[r.Action] ?? 0) + 1;
    return Object.entries(n).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 12);
  }, [rows]);
  const refusals = useMemo(() => rows.filter(isRefusal).length, [rows]);

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (kind && (r.ActorKind || "system") !== kind) return false;
      if (action && r.Action !== action) return false;
      if (refusedOnly && !isRefusal(r)) return false;
      if (!needle) return true;
      return `${r.Seq} ${r.ActorKind} ${r.ActorID} ${r.Action} ${r.Resource} ${r.Outcome}`.toLowerCase().includes(needle);
    });
  }, [rows, q, kind, action, refusedOnly]);

  const header = (
    <PageHeader title="Audit" sub="Append-only and hash-chained; refusals are recorded as loudly as successes."
      actions={<Button variant="secondary" icon="refresh" onClick={load}>Refresh</Button>} />
  );
  if (!d) return <main className="wide">{header}<EmptyState loading /></main>;

  const filtering = Boolean(q || kind || action || refusedOnly);
  return (
    <main className="wide">
      {header}
      <Toolbar end={filtering ? <Button variant="quiet" onClick={() => { setQ(""); setKind(null); setAction(null); setRefusedOnly(false); }}>Clear filters</Button> : undefined}>
        <input type="search" placeholder="Search actor, action, resource, outcome…" value={q}
          onChange={(e) => setQ(e.target.value)} aria-label="Search the audit trail" />
      </Toolbar>
      <Chips aria-label="Filter by actor and outcome">
        <Chip on={refusedOnly} tone="bad" count={refusals} onClick={() => setRefusedOnly((v) => !v)}>Refusals</Chip>
        {kinds.map(([k, n]) => (
          <Chip key={k} on={kind === k} count={n} onClick={() => setKind(kind === k ? null : k)}>{k}</Chip>
        ))}
      </Chips>
      <Chips aria-label="Filter by action">
        {actions.map(([a, n]) => (
          <Chip key={a} on={action === a} count={n} onClick={() => setAction(action === a ? null : a)}>{a}</Chip>
        ))}
      </Chips>
      <p className="muted">
        {shown.length === rows.length ? `${rows.length} entries` : `${shown.length} of ${rows.length} entries`}
        {d.limit !== undefined && rows.length >= d.limit && <> · newest {d.limit}; older entries are not loaded</>}
      </p>
      <Table head={["Seq", "When", "Actor", "Action", "Resource", "Outcome"]}
        empty={<EmptyState title={filtering ? "Nothing matches those filters" : "Nothing recorded yet"} />}>
        {shown.map((r) => (
          <tr key={r.Seq}>
            <td className="muted">{r.Seq}</td>
            <td className="muted" title={new Date(r.TS * 1000).toISOString()}>{when(r.TS)}</td>
            <td>{r.ActorKind}{r.ActorID && <> <Readout value={r.ActorID} /></>}</td>
            <td><code>{r.Action}</code></td>
            <td>{r.Resource ? <Readout value={r.Resource} /> : <span className="muted">—</span>}</td>
            <td><Badge status={r.Outcome} /></td>
          </tr>
        ))}
      </Table>
    </main>
  );
}

// The clock for today, the date for anything older: a trail read from the
// present backwards is mostly today, and a full timestamp on every row buries
// the one thing that varies.
function when(unix: number): string {
  const d = new Date(unix * 1000);
  const today = new Date();
  const sameDay = d.toDateString() === today.toDateString();
  return sameDay
    ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
