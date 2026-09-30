// The words the portal says a status, a tool and a permission in, and a status's tone.
//
// ONE module for both portals: the node's (web/src) and PACT Cloud's (portal/src, copied verbatim
// from the node commit its portal/HARVESTED file records, held to it by the cloud's
// gateway/scripts/check-harvested.mjs). The two ports' tone tables had already drifted when they were
// two copies (the node's OK lacked `rotated`, its WARN `queued`, and neither knew `rate_limited`), so
// there is one table now. Pure, with no imports: both portals' tests run it as it ships, the node's with
// `node --test` (web/test/words_test.mjs, which holds the tones to what the Go emitters write) and the
// cloud's with vitest (portal/test/words.test.ts, the same against the cloud's emitters and PACT's codes).

export type Tone = "neutral" | "ok" | "warn" | "bad";

// Outcomes are a bounded vocabulary in each emitter, but a wide one, and this has to colour a row it has
// never seen. The good and waiting cases are named exactly; a refusal is recognised by shape, so a code
// added tomorrow lands red rather than quietly grey — the audit pages count these as refusals, and a
// refusal the portal cannot recognise is one the owner never sees (`rate_limited` was grey, and the
// Refusals chip missed it, on the page that promises refusals are recorded as loudly as successes).
const OK = /^(ok|active|live|allowed|paired|set|read|delivered|delivered_on_retry|accepted|sealed|connected|rebuilt|started|rotated|stopped|stored|restored|renewed|updated)$/;
const WARN = /^(connecting|pending|pending_in|pending_out|pending_approval|pending_new_address|write|waiting|retrying|queued|late|skipped|replayed|partial)$/;
const BAD = /(denied|error|failed|refused|reject|invalid|unreachable|unavailable|expired|revoked|blocked|mismatch|_required|unknown|(^|_)not_|too_large|missing|unreadable|^bad_|stale|undelivered|_limited$|_inactive$|superseded|unpaired|_cap$|^own_invite$|^internal$)/;

/** A status's tone: ok, waiting (warn), refused (bad), or neither. */
export function toneOf(status: string): Tone {
  if (OK.test(status)) return "ok";
  if (WARN.test(status)) return "warn";
  if (BAD.test(status)) return "bad";
  return "neutral";
}

/** A status code as the words a badge says: `rate_limited` → "rate limited". */
export function statusWord(status: string): string {
  return status.replace(/_/g, " ");
}

/** A slug or a snake_case name as words, the first capitalised: `google_calendar` → "Google calendar". */
function words(s: string): string {
  const w = s.replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim();
  return w.charAt(0).toUpperCase() + w.slice(1);
}

/**
 * The display names of integrations, by slug, where the page has them (an installed integration's own
 * name, a catalogue entry's): "GitHub" rather than the slug's "Github". Optional everywhere: a peer's
 * integration is theirs, and its slug said as words is all this side can know of it.
 */
export type IntegrationNames = Readonly<Record<string, string>>;

/** An integration's name: the one the page was given, else its slug as words. */
export function integrationName(slug: string, names?: IntegrationNames): string {
  const given = names?.[slug]?.trim();
  return given || words(slug);
}

const PERMS: Readonly<Record<string, string>> = {
  "message.text": "Messages", "message.media": "Media & files", "status.view": "See status",
  "calendar.availability": "Availability", "calendar.book": "Book time",
};

/**
 * A PACT permission (SPEC §5) as an owner reads it: `message.media` → "Media & files",
 * `integration.github` → "GitHub tools". A permission that names one tool (`integration.github.search`,
 * `deepwiki_ask_wiki_question`) is that tool's label. A dotted name this does not know stays as written:
 * it is somebody's own permission, and guessing its words would say something it may not mean.
 */
export function permLabel(name: string, names?: IntegrationNames): string {
  if (PERMS[name]) return PERMS[name];
  const one = /^integration\.([^.]+)$/.exec(name);
  if (one) return `${integrationName(one[1], names)} tools`;
  if (name.startsWith("integration.") || !name.includes(".")) return toolLabel(name, names);
  return name;
}

const TOOLS: Readonly<Record<string, string>> = {
  get_status: "Status", check_availability: "Availability", book_slot: "Book time", cancel_booking: "Cancel booking",
};

/**
 * A tool's name as an owner reads it. An integration's tool is its integration's name and the tool's:
 * `integration.github.search` → "GitHub · Search"; a bare `integration.<slug>` is that integration's
 * tools, as its permission is. Anything else is its words: `deepwiki_ask_wiki_question` → "Deepwiki ask
 * wiki question". Where it is shown, the raw name goes in the title: the label is for reading, the name
 * is what the wire and the audit trail say.
 */
export function toolLabel(name: string, names?: IntegrationNames): string {
  if (TOOLS[name]) return TOOLS[name];
  const m = /^integration\.([^.]+)\.(.+)$/.exec(name);
  if (m) return `${integrationName(m[1], names)} · ${words(m[2].replace(/\./g, " "))}`;
  const one = /^integration\.([^.]+)$/.exec(name);
  if (one) return `${integrationName(one[1], names)} tools`;
  return words(name);
}
