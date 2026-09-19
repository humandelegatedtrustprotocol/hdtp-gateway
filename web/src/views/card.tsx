import { useEffect, useState } from "react";
import { currentAccount, getJSON } from "../api";
import { Button, EmptyState, Notice, PageHeader, Readout, Section } from "../ui";

type Data = { card: string; sig: string; slug: string };

export function CardView() {
  const [d, setD] = useState<Data | null>(null);
  const [err, setErr] = useState("");
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    getJSON<Data>("/api/card").then(setD).catch(() => setErr("No card yet — this account may have no public endpoint."));
  }, []);
  const header = (
    <PageHeader
      title="Your card"
      sub="This vCard is your address: hand it to people the way you would a phone number. The certificate inside names your identity — the root you hold in your wallet — and that is what everyone pins."
      actions={d && <Button href={"/card.vcf" + (currentAccount() ? "?account=" + encodeURIComponent(currentAccount()) : "")} download={`${d.slug}.vcf`}>Download {d.slug}.vcf</Button>}
    />
  );
  if (err) return <main><PageHeader title="Your card" /><Notice kind="warn">{err}</Notice></main>;
  if (!d) return <main>{header}<EmptyState loading /></main>;
  const copy = () => {
    navigator.clipboard?.writeText(d.card).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); });
  };
  return (
    <main>
      {header}
      <Section title="vCard" footer={<Button variant="secondary" icon="copy" onClick={copy}>{copied ? "Copied" : "Copy"}</Button>}>
        <pre>{d.card}</pre>
        {d.sig && <p className="muted">signature: <Readout value={d.sig} /></p>}
      </Section>
    </main>
  );
}
