// The overview's arithmetic, for both portals: the node's (web/src) and BatonDeck's (portal/src,
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

/**
 * What the overview says of a certificate: a tone, the state in a word or two (`text`, what a pill
 * holds), and how long, where that matters (`detail`, the muted line beside it).
 */
export type CertificateView = { tone: Tone; text: string; detail: string | null; days: number | null; until: string | null };

/**
 * What the overview says of an identity's certificate. `null` is a certificate this page was not
 * given. A leaf past its `not_after` is expired whatever the flags say: the node keeps it `served`
 * until its hourly retire sweep, and in that hour peers already refuse it — "renewal due" there
 * would understate an outage.
 */
export function certificateView(c: Certificate | null | undefined, now: number): CertificateView {
  const none = { detail: null, days: null, until: null };
  if (!c) return { tone: "neutral", text: "certificate not known", ...none };
  if (!c.certified) return { tone: "warn", text: "not signed yet", ...none };
  const lapsed = c.not_after ? Date.parse(c.not_after) <= now : false;
  if (c.expired || lapsed) return { tone: "bad", text: "certificate expired", ...none };
  const served = c.served ?? Boolean(c.not_after);
  if (!served || !c.not_after) return { tone: "bad", text: "no current certificate", ...none };
  const days = daysUntil(c.not_after, now);
  const left = days <= 0 ? "expires today" : days === 1 ? "1 day left" : `${days} days left`;
  if (c.renewal_due) return { tone: "warn", text: "renewal due", detail: left, days, until: c.not_after };
  return { tone: "ok", text: "valid", detail: left, days, until: c.not_after };
}

/** "1,284" for a count, in the reader's own grouping; "—" for a read that failed. */
export function shown(n: Count): string {
  return n === null ? "—" : n.toLocaleString();
}

/**
 * A plural said plainly: `plural(1, "request")` is "1 request", `plural(2, …)` "2 requests". The
 * number is grouped the way `shown` groups it, so a line of "Needs you" says "12,345 people" over a
 * tile that says "12,345", never "12345".
 */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${shown(n)} ${n === 1 ? one : many}`;
}
