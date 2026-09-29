// The node's overview as numbers: what GET /api/dashboard answered, and nothing the page invents.
// A module of its own, with no import that is not a file (`../overview.ts`), so `node --test` runs it
// as it is (web/test/overview_test.mjs holds each tile to the field it is read from).
import { certificateView, plural, total, type Certificate, type CertificateView, type Count } from "../overview.ts";

/** GET /api/dashboard's `posture`: the deployment state in effect (internal/internalui/dashboard.go). */
export type Posture = { mode: string; seal: string; client_cert: string; tunnel: string; public_url: string };

/** One identity this owner administers, as GET /api/dashboard answers it. */
export type Account = {
  id: string;
  slug: string;
  display_name: string;
  fingerprint: string;
  /** Active contacts. */
  contacts: number;
  /** What the Requests tab holds: contact requests and contacts waiting at a new address. */
  pending: number;
  /** The leaf, from the reader Settings · identity renders; null where the node has none wired. */
  certificate: (Certificate & { endpoint?: string }) | null;
};

export type Dashboard = { posture: Posture; accounts: Account[] | null };

/** The four tiles. Each is one field of the answer, summed across the identities, or counted from them. */
export type Tiles = { identities: Count; contacts: Count; waiting: Count; attention: Count };

export function tilesOf(d: Dashboard, now: number): Tiles {
  const accounts = d.accounts ?? [];
  return {
    identities: accounts.length,
    contacts: total(accounts.map((a) => a.contacts)),
    waiting: total(accounts.map((a) => a.pending)),
    // Certificates that want the owner: a renewal due, none current, or none signed yet — the
    // reader's own flags, as certificateView says them.
    attention: accounts.filter((a) => needsAttention(certificateView(a.certificate, now))).length,
  };
}

/** A certificate is the owner's to act on when it is anything but current and well dated. */
export function needsAttention(v: CertificateView): boolean {
  return v.tone === "warn" || v.tone === "bad";
}

/** The first identity with somebody waiting, which the header's "Review" button opens. */
export function firstWaiting(d: Dashboard): Account | null {
  return (d.accounts ?? []).find((a) => a.pending > 0) ?? null;
}

/** One thing that wants the owner, from the answer: people waiting on an identity, or its certificate. */
export type Need = { key: string; tone: "warn" | "bad"; kind: "waiting" | "certificate"; account: Account; text: string };

/**
 * What the "Needs you" list says: each identity with somebody waiting, and each certificate that is
 * not current — the same fields the tiles count, turned into things to do. Certificates first when
 * one has lapsed (nobody can reach that identity), then the people waiting, then renewals due.
 */
export function needsOf(d: Dashboard, now: number): Need[] {
  const out: Need[] = [];
  for (const a of d.accounts ?? []) {
    const name = a.display_name || a.slug;
    const v = certificateView(a.certificate, now);
    if (needsAttention(v)) out.push({ key: `cert-${a.id}`, tone: v.tone === "bad" ? "bad" : "warn", kind: "certificate", account: a, text: `${name}: ${v.text}` });
    if (a.pending > 0) out.push({ key: `wait-${a.id}`, tone: "warn", kind: "waiting", account: a, text: `${plural(a.pending, "person", "people")} waiting for ${name}` });
  }
  const rank = (n: Need) => (n.tone === "bad" ? 0 : n.kind === "waiting" ? 1 : 2);
  return out.sort((x, y) => rank(x) - rank(y));
}
