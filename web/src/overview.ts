// The overview's arithmetic, for both portals: the node's (web/src) and PACT Cloud's (portal/src,
// copied verbatim by the cloud's gateway/scripts/harvest.sh). Pure, and with no imports but a type,
// so both portals' tests run it as it is.
//
// Two rules every number on the overview keeps, and this is where they are kept:
//   - A count is what an endpoint answered, or `null` when that read failed. A failure is never
//     drawn as a zero: "0 waiting" after a read that failed tells a person nobody is waiting.
//   - A certificate's state is the server's own flags (`certified`, `renewal_due`, `expired`, and
//     on the node `served`); the page derives nothing but the days between now and `not_after`.
import type { Tone } from "./ui";

/** A count an endpoint answered, or null when its read failed. */
export type Count = number | null;

/** The sum of counts, or null when any of them could not be read: a total with a hole in it is not a total. */
export function total(parts: readonly Count[]): Count {
  let n = 0;
  for (const p of parts) {
    if (p === null) return null;
    n += p;
  }
  return n;
}

/** Whole days from `now` (ms) until an ISO instant, rounded down; negative once it has passed. */
export function daysUntil(iso: string, now: number): number {
  return Math.floor((Date.parse(iso) - now) / 86_400_000);
}

/**
 * A certificate as the reader answered it. `served` is the node's (a certified identity whose host
 * holds a current leaf); the cloud answers `expired` instead, and a cloud certificate is served when
 * it is certified, dated and not expired.
 */
export type Certificate = {
  certified: boolean;
  served?: boolean;
  not_after?: string | null;
  renewal_due: boolean;
  expired?: boolean;
};

export type CertificateView = { tone: Tone; text: string; days: number | null; until: string | null };

/** What the overview says of an identity's certificate. `null` is a certificate this page was not given. */
export function certificateView(c: Certificate | null | undefined, now: number): CertificateView {
  if (!c) return { tone: "neutral", text: "certificate not known", days: null, until: null };
  if (!c.certified) return { tone: "warn", text: "not signed by a wallet yet", days: null, until: null };
  const served = c.served ?? (!c.expired && Boolean(c.not_after));
  if (c.expired || !served || !c.not_after) return { tone: "bad", text: c.expired ? "certificate expired" : "no current certificate", days: null, until: null };
  const days = daysUntil(c.not_after, now);
  const left = days <= 0 ? "expires today" : days === 1 ? "1 day left" : `${days} days left`;
  if (c.renewal_due) return { tone: "warn", text: `renewal due · ${left}`, days, until: c.not_after };
  return { tone: "ok", text: `valid · ${left}`, days, until: c.not_after };
}

/** "3" for a count, "—" for a read that failed. */
export function shown(n: Count): string {
  return n === null ? "—" : String(n);
}

/** A plural said plainly: `plural(1, "request")` is "1 request", `plural(2, …)` "2 requests". */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}
