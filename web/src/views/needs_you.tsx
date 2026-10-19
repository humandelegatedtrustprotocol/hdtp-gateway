// Needs you: the asks your agent is waiting on you to answer (GET /api/asks?status=open), newest
// first, each a card that leads with its TLDR and answers where it stands. An answered ask leaves the
// list; the sidebar's badge counts what is left (app.tsx Counts).
import { useCallback, useEffect, useState } from "react";
import { failureOf, getJSON, subscribe } from "../api";
import { AskCard, type Ask } from "../a2ui";
import { Button, EmptyState, Failed, PageHeader } from "../ui";

export function NeedsYou() {
  const [list, setList] = useState<Ask[] | null>(null);
  const [labels, setLabels] = useState<Record<string, string>>({});
  const [err, setErr] = useState("");
  const load = useCallback(() => {
    getJSON<{ asks: Ask[] | null }>("/api/asks", { status: "open" })
      .then((d) => { setList(d.asks ?? []); setErr(""); })
      .catch((e) => setErr(failureOf(e)));
    // Who each ask is about, by the name the Inbox shows; the fingerprint stands in until it is read.
    getJSON<{ contacts: { fingerprint: string; label: string }[] | null }>("/api/conversations")
      .then((d) => setLabels(Object.fromEntries((d.contacts ?? []).map((p) => [p.fingerprint, p.label]))))
      .catch(() => { /* the fingerprint stays */ });
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => subscribe(load), [load]);
  const answered = () => { load(); dispatchEvent(new Event("hdtp:counts")); };

  const header = <PageHeader title="Needs you" sub="What your agent is waiting on you to decide. A ready reply or what you write is sent as your own message." />;
  if (list === null) return <main>{header}{err ? <Failed what="what your agent asks you" error={err} retry={load} /> : <EmptyState loading />}</main>;
  return (
    <main>
      {header}
      {err && <Failed what="what your agent asks you" error={err} retry={load} />}
      {list.length === 0 && <EmptyState title="Nothing waiting on you">When your agent needs you to decide something, it shows here and in the conversation it is about.</EmptyState>}
      <div className="asks">
        {list.map((a) => (
          <div key={a.id}>
            <AskCard ask={a} from={labels[a.contact] ?? a.contact} onAnswered={answered} />
            <Button variant="quiet" icon="inbox" to={"/messages?contact=" + encodeURIComponent(a.contact)}>Open the conversation</Button>
          </div>
        ))}
      </div>
    </main>
  );
}
