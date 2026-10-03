// The words the portal says a status, a tool and a permission in, and a status's tone.
//
// ONE module for both portals: the node's (web/src) and BatonDeck's (portal/src, copied verbatim
// from the node commit its portal/HARVESTED file records, held to it by the cloud's
// gateway/scripts/check-harvested.mjs). The two ports' tone tables had already drifted when they were
// two copies (the node's OK lacked `rotated`, its WARN `queued`, and neither knew `rate_limited`), so
// there is one table now. Pure, with no imports: both portals' tests run it as it ships, the node's with
// `node --test` (web/test/words_test.mjs, which holds the tones to what the Go emitters write) and the
// cloud's with vitest (portal/test/words.test.ts, the same against the cloud's emitters and HDTP's codes).

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
 * A HDTP permission (SPEC §5) as an owner reads it: `message.media` → "Media & files",
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

const ACTIONS: Readonly<Record<string, string>> = {
  get_status: "Get status", check_availability: "Check availability", book_slot: "Book", cancel_booking: "Cancel booking",
};

/**
 * The words on the button that calls a tool: a built-in tool's verb ("Check availability"), an integration's
 * tool its own name ("Search", "Create issue"), and anything else "Run". The dock's title says which tool; the button says what pressing it does.
 */
export function toolAction(name: string): string {
  if (ACTIONS[name]) return ACTIONS[name];
  const m = /^integration\.([^.]+)\.(.+)$/.exec(name);
  return m ? words(m[2].replace(/\./g, " ")) : "Run";
}

/**
 * A name's initials, for an avatar: the first letter or digit of its first and last words, or the first
 * two of a one-word name. Only letters and digits count ('Konstantin (board)' is not 'K('), a part in
 * brackets is a note about the name rather than the name, and so is what follows a ' · ' (a namesake's
 * short fingerprint: 'Alice · zS_0RT…' is Alice). A word cut short with an ellipsis is an id, not a name,
 * and gives no letters. Nothing left means nothing to draw: the avatar shows a neutral figure instead.
 */
export function initialsOf(name: string): string {
  const plain = name.split(/\s+·\s+/)[0].replace(/\([^)]*\)?|\[[^\]]*\]?/g, " ");
  const parts = plain.split(/\s+/)
    .filter((w) => !/…|\.\.\./.test(w))
    .map((w) => [...w].filter((ch) => /[\p{L}\p{N}]/u.test(ch)))
    .filter((cs) => cs.length > 0);
  if (parts.length === 0) return "";
  if (parts.length === 1) return parts[0].slice(0, 2).join("").toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

const TRUST: Readonly<Record<string, string>> = { messages_only: "Messages only", may_instruct: "May instruct your agent" };

/** A contact's trust flag as words: `messages_only` → "Messages only", `may_instruct` → "May instruct your agent". */
export function trustWord(flag: string): string {
  return TRUST[flag] ?? statusWord(flag);
}

/**
 * What a tool's input field is called on the form: its schema's title; else its description, when that
 * is short enough to be a label ('Search query' rather than 'q'); else its name. The name, when it is not
 * the label, is shown beside it small, since it is what the tool's own documentation calls the field. A
 * description that became the label is not said again as help.
 */
export function fieldLabel(name: string, schema: { title?: string; description?: string }): { text: string; help: string } {
  const desc = (schema.description ?? "").trim();
  if (schema.title) return { text: schema.title, help: desc };
  if (desc && desc.length <= 48 && !desc.includes("\n")) return { text: desc.replace(/\.$/, ""), help: "" };
  return { text: name, help: desc };
}

// ---------------------------------------------------------------- dates and numbers
//
// One way to say a time, for every table, list and line of both portals (the design review found five
// or more: '20:45:14', '28 Sept, 19:55', '29/09/2026, 20:48:01', ISO days, '8 December 2026'). Built by
// hand rather than through toLocaleString, whose words and order depend on the browser's locale ('28
// Sept' in one, 'Sep 28' in the next): the page is written in English, and a date in it reads one way.
// The time is the reader's own clock; the title of any of them (whenTitle) is the whole instant, zone
// and all, so an hour that looks wrong can be checked.

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DAY_MS = 86_400_000;

const two = (n: number) => String(n).padStart(2, "0");
/** Midnight at the start of `ms`'s day, on the reader's clock. */
const dayStart = (ms: number) => { const d = new Date(ms); return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime(); };
/** How many calendar days `ms` is before `now` (0 today, 1 yesterday, negative for a day to come). */
const daysBefore = (ms: number, now: number) => Math.round((dayStart(now) - dayStart(ms)) / DAY_MS);

/** The clock: '14:05', or '14:05:09' with seconds. */
export function clockOf(ms: number, seconds = false): string {
  const d = new Date(ms);
  return `${two(d.getHours())}:${two(d.getMinutes())}` + (seconds ? `:${two(d.getSeconds())}` : "");
}

/** A day, without its time: '28 Sep' this year, '28 Sep 2025' in another. */
export function dateOf(ms: number, now = Date.now()): string {
  const d = new Date(ms);
  const day = `${d.getDate()} ${MONTHS[d.getMonth()]}`;
  return d.getFullYear() === new Date(now).getFullYear() ? day : `${day} ${d.getFullYear()}`;
}

/**
 * When something happened, for a table or a list: '14:05' today, 'Yesterday 14:05', 'Mon 14:05' within
 * the week, '28 Sep' this year, '28 Sep 2025' before it. `time` keeps the clock on a date too ('28 Sep
 * 14:05'): inside a conversation, and on any deadline, the hour is part of the answer.
 */
export function when(ms: number, now = Date.now(), time = false): string {
  if (!ms) return "";
  const back = daysBefore(ms, now);
  if (back === 0) return clockOf(ms);
  if (back === 1) return `Yesterday ${clockOf(ms)}`;
  if (back > 1 && back < 7) return `${DAYS[new Date(ms).getDay()]} ${clockOf(ms)}`;
  return time ? `${dateOf(ms, now)} ${clockOf(ms)}` : dateOf(ms, now);
}

/** A day heading for a list read newest first: 'Today', 'Yesterday', 'Sun 28 Sep', '28 Sep 2025'. */
export function dayOf(ms: number, now = Date.now()): string {
  const back = daysBefore(ms, now);
  if (back === 0) return "Today";
  if (back === 1) return "Yesterday";
  const d = new Date(ms);
  return d.getFullYear() === new Date(now).getFullYear() ? `${DAYS[d.getDay()]} ${dateOf(ms, now)}` : dateOf(ms, now);
}

/**
 * How long ago, for last-seen and signed-in: 'just now', '5 min ago', '3 h ago', '4 days ago', then the
 * date. A time to come is said as one: 'in 5 min', 'in 3 h', 'in 12 days', then the date.
 */
export function ago(ms: number, now = Date.now()): string {
  if (!ms) return "";
  const s = Math.round((now - ms) / 1000);
  const past = s >= 0;
  const a = Math.abs(s);
  const say = (n: number, unit: string) => (past ? `${n} ${unit} ago` : `in ${n} ${unit}`);
  if (a < 90) return past ? "just now" : "in a minute";
  if (a < 3600) return say(Math.round(a / 60), "min");
  if (a < 86_400) return say(Math.round(a / 3600), "h");
  const days = Math.round(a / 86_400);
  if (days < 30) return say(days, days === 1 ? "day" : "days");
  return dateOf(ms, now);
}

/** The whole instant, for a title: 'Mon 28 Sep 2026, 14:05:09 GMT+1'. */
export function whenTitle(ms: number): string {
  const d = new Date(ms);
  const off = -d.getTimezoneOffset();
  const zone = off === 0 ? "UTC" : `GMT${off > 0 ? "+" : "-"}${Math.floor(Math.abs(off) / 60)}${Math.abs(off) % 60 ? ":" + two(Math.abs(off) % 60) : ""}`;
  return `${DAYS[d.getDay()]} ${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()}, ${clockOf(ms, true)} ${zone}`;
}

/** A count, grouped: 1,246 and 233,808. Laid out in a `.num` cell (right-aligned, tabular figures). */
export function num(n: number): string {
  return n.toLocaleString("en-GB");
}

// ---------------------------------------------------------------- the audit trail's filters

const KINDS: Readonly<Record<string, string>> = {
  owner: "Owner", token: "Agent key", contact: "Contact", peer: "Contact", guest: "Stranger",
  cli: "Command line", operator: "Operator", system: "System",
};

/**
 * An audit row's actor kind, as a filter says it. `cli` is the node's command line; BatonDeck writes its
 * operators under that kind (the Go store's CHECK has no `operator`), so the cloud passes its own word.
 */
export function kindLabel(kind: string, own: Readonly<Record<string, string>> = {}): string {
  return own[kind] ?? KINDS[kind] ?? words(kind);
}

/** An audit action as words, the code kept for its title: `identity_gate` → "Identity gate". */
export function actionWord(action: string): string {
  return words(action.replace(/\./g, " "));
}

// ---------------------------------------------------------------- messages

const REASONS: Readonly<Record<string, string>> = {
  pending_approval: "they have not seen your acceptance yet",
  unavailable: "their address did not answer",
  envelope_invalid: "their answer could not be verified as theirs",
  permission_denied: "they do not take messages from you",
  rate_limited: "they are taking no more right now",
  too_large: "it is larger than they accept",
  seal_required: "they take only sealed messages, and this one was not",
  expired: "its deadline passed, and it is no longer being tried",
};

/**
 * Why an outbound message did not arrive, in words, from the code the portal was given: a HDTP §12
 * refusal (`last_refusal` on the cloud, the stored status on the node) or `expired`. A code this does not
 * know says only that it did not arrive, rather than guessing; the code itself goes in the title.
 */
export function undeliveredReason(code: string | null | undefined): string {
  return (code && REASONS[code]) || "it did not arrive";
}

const KINDS_BY_EXT: Readonly<Record<string, string>> = {
  pdf: "PDF", doc: "Word document", docx: "Word document", odt: "Document", rtf: "Document", txt: "Text file", md: "Text file",
  xls: "Excel spreadsheet", xlsx: "Excel spreadsheet", ods: "Spreadsheet", csv: "CSV table",
  ppt: "PowerPoint deck", pptx: "PowerPoint deck", odp: "Presentation", key: "Keynote deck",
  zip: "Zip archive", gz: "Archive", tar: "Archive", "7z": "Archive", json: "JSON file", vcf: "Contact card", ics: "Calendar invite",
  png: "Image", jpg: "Image", jpeg: "Image", gif: "Image", webp: "Image", heic: "Image", svg: "Image",
  mp3: "Audio", m4a: "Audio", wav: "Audio", ogg: "Audio", mp4: "Video", mov: "Video", webm: "Video",
};

/**
 * What a file is, as an owner reads it: 'Excel spreadsheet', not
 * 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'. From the file's extension first,
 * then the MIME type's family; the MIME type itself goes in the title, where it can still be read.
 */
export function mediaKind(mime: string | undefined, filename?: string): string {
  const ext = /\.([A-Za-z0-9]{1,5})$/.exec(filename ?? "")?.[1]?.toLowerCase();
  if (ext && KINDS_BY_EXT[ext]) return KINDS_BY_EXT[ext];
  const m = (mime ?? "").toLowerCase();
  if (m === "application/pdf") return "PDF";
  if (m.includes("spreadsheet") || m.includes("excel")) return "Spreadsheet";
  if (m.includes("presentation") || m.includes("powerpoint")) return "Presentation";
  if (m.includes("wordprocessing") || m.includes("msword")) return "Word document";
  if (m.startsWith("image/")) return "Image";
  if (m.startsWith("audio/")) return "Audio";
  if (m.startsWith("video/")) return "Video";
  if (m.startsWith("text/")) return "Text file";
  if (m.includes("zip") || m.includes("compressed")) return "Archive";
  return "File";
}

/** A file's size, as a message says it: '2.2 MB', '640 KB', '12 B'. (A plan's allowance is said by the cloud's usage page, in whole units.) */
export function fileSize(n: number | undefined): string {
  if (!n) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  if (n < 1024 ** 3) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(1)} GB`;
}

// ---------------------------------------------------------------- invites and contacts

export type InviteState = "revoked" | "expired" | "used_up" | "live";

/**
 * What an invite is, as redemption judges it, in its order: revoked, then expired, then spent (a
 * `maxUses` of 0 is unlimited). Both portals' lists carry the facts and no state; the node's read 'live'
 * on expired and spent invites, and counted them in the tab.
 */
export function inviteState(x: { revoked: boolean; expiresAt: number; uses: number; maxUses: number }, now = Date.now()): InviteState {
  if (x.revoked) return "revoked";
  if (x.expiresAt > 0 && x.expiresAt <= now) return "expired";
  if (x.maxUses !== 0 && x.uses >= x.maxUses) return "used_up";
  return "live";
}

/** An invite's uses: '9 of 10', or '17 used · no limit' where it has none (`maxUses` 0). */
export function usesText(uses: number, maxUses: number): string {
  return maxUses === 0 ? `${num(uses)} used · no limit` : `${num(uses)} of ${num(maxUses)}`;
}

const CONTACT: Readonly<Record<string, string>> = {
  active: "active", pending_in: "asked you", pending_out: "you asked", blocked: "blocked",
};

/**
 * A contact's state as the owner says it, not as the store does ('pending in'): the one word a pill on a
 * contact says. `active` is the state nearly every contact is in, so a list pills only the others
 * (`contactPill`).
 */
export function contactStatusWord(status: string): string {
  return CONTACT[status] ?? statusWord(status);
}

/** Whether a contact's state is worth a pill in a list: every state but the ordinary one. */
export function contactPill(status: string): boolean {
  return status !== "active";
}

/**
 * A list read newest first, with a heading before the first entry of each day ('Today', 'Sun 28 Sep'):
 * the audit trail's cells then say only the clock. Consecutive entries of one day share one heading.
 */
export function withDays<T>(rows: readonly T[], msOf: (r: T) => number, now = Date.now()): ({ day: string; key: string } | { row: T })[] {
  const out: ({ day: string; key: string } | { row: T })[] = [];
  let last = "";
  for (const row of rows) {
    const day = dayOf(msOf(row), now);
    if (day !== last) { out.push({ day, key: `${day}-${out.length}` }); last = day; }
    out.push({ row });
  }
  return out;
}

/** How many of a filter's options a row of chips shows before the rest go into 'More'. */
export const CHIPS_SHOWN = 8;

// ---------------------------------------------------------------- a count the server may have capped

/**
 * A count as a chip shows it. A number is exact. `{ count, capped }` is how an API answers a count it
 * stops at a cap of its own on a hot read (BatonDeck's GET /v1/identities/:slug/badges, `unread`):
 * `capped` says there were more than `count`, and `count` is then that cap. The view never knows the
 * cap; it is whatever the answer says.
 */
export type Tally = number | { count: number; capped: boolean };

function tallyOf(t: Tally): { count: number; capped: boolean } {
  return typeof t === "number" ? { count: t, capped: false } : t;
}

/** How many, as a number to test against: a capped tally is at least its cap. */
export function tallyCount(t: Tally): number {
  return tallyOf(t).count;
}

/** The chip's figure: '50+' when the server stopped counting at 50, '7' when it counted 7. */
export function tallyText(t: Tally): string {
  const { count, capped } = tallyOf(t);
  return capped ? `${num(count)}+` : num(count);
}

/** What a screen reader hears for the chip: 'more than 50 unread', '7 unread' ('7' with no noun). */
export function tallyLabel(t: Tally, noun?: string): string {
  const { count, capped } = tallyOf(t);
  const n = capped ? `more than ${num(count)}` : num(count);
  return noun ? `${n} ${noun}` : n;
}

/** The tab title with the count in front, '(50+) Inbox', or without one at none; any earlier count is replaced. */
export function titleWithTally(title: string, t: Tally): string {
  const base = title.replace(/^\(\d[\d,]*\+?\) /, "");
  return tallyCount(t) > 0 ? `(${tallyText(t)}) ${base}` : base;
}
