import { useCallback, useEffect, useState } from "react";
import { ApiError, currentAccount, failureOf, getJSON } from "../api";
import { Button, EmptyState, Failed, Notice, PageHeader, Readout, Section, useFlash } from "../ui";
import { CopyId, IdText, UrlText } from "../glance";

// endpoint, root_fingerprint and kid are read by the node from the card's own certificate
// (manage_pages.go getAPICard), under the names the cloud's card read uses.
type Data = { card: string; sig: string; slug: string; endpoint: string; root_fingerprint: string; kid: string };

export function CardView() {
  const [d, setD] = useState<Data | null>(null);
  // "none": the identity has no certificate yet (404); any other refusal is said as the failure it is.
  const [err, setErr] = useState<"none" | string>("");
  const [copied, flash] = useFlash();
  const load = useCallback(() => {
    setErr("");
    getJSON<Data>("/api/card").then(setD).catch((e) => setErr(e instanceof ApiError && e.status === 404 ? "none" : failureOf(e)));
  }, []);
  useEffect(() => { load(); }, [load]);
  const download = "/card.vcf" + (currentAccount() ? "?account=" + encodeURIComponent(currentAccount()) : "");
  const header = (
    <PageHeader
      title="Your card"
      sub="This vCard is your address: hand it to people the way you would a phone number. The certificate inside names your identity — the root you hold in your wallet — and that is what everyone pins."
    />
  );
  if (err === "none") return <main>{header}<Notice kind="warn">No card yet — this identity has no certificate, so it has nothing to hand out. The Identity page says how its wallet makes one.</Notice></main>;
  if (err) return <main>{header}<Failed what="your card" error={err} retry={load} /></main>;
  if (!d) return <main>{header}<EmptyState loading /></main>;
  const copy = () => {
    navigator.clipboard?.writeText(d.card).then(flash);
  };
  return (
    <main>
      {header}
      <Section title="What it says"
        footerStatus={copied ? "Copied" : null}
        footer={<>
          <Button variant="secondary" icon="copy" onClick={copy}>Copy vCard</Button>
          <Button href={download} download={`${d.slug}.vcf`}>Download</Button>
        </>}>
        <dl className="facts">
          <dt>Address</dt><dd><UrlText url={d.endpoint} /></dd>
          <dt>Root</dt><dd><IdText id={d.root_fingerprint} /><span className="muted"> — your identity: what contacts pin</span></dd>
          <dt>Host key</dt><dd><IdText id={d.kid} /><span className="muted"> — this node's key, which a renewal replaces</span></dd>
        </dl>
        <details className="raw">
          <summary>Show vCard</summary>
          <pre>{d.card}</pre>
          {d.sig && <p className="muted">Signature <Readout value={d.sig} /> <CopyId id={d.sig} /></p>}
        </details>
      </Section>
    </main>
  );
}
