// The portal's status tones and its tool and permission names (web/src/words.ts), run as it ships:
// `node --test` strips its types. PACT Cloud runs its verbatim copy of the module under its own suite
// (portal/test/words.test.ts), against the cloud's emitters; its check-harvested.mjs holds the copy to
// this file's module byte for byte, so the two ports' tone tables are one table.
//
// The tones are held to what the node WRITES: every audit call in the Go sources whose outcome is a
// string literal is read out of the source, and each outcome found must be one this table has decided.
// A new outcome fails here until somebody says what colour it is — which is how `rate_limited` stayed
// grey, and out of the Refusals count, with nobody deciding it should.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  actionWord, ago, clockOf, contactPill, contactStatusWord, dateOf, dayOf, fieldLabel, fileSize, initialsOf, inviteState, kindLabel, mediaKind, num,
  permLabel, statusWord, toneOf, toolAction, toolLabel, trustWord, undeliveredReason, usesText, when, whenTitle, withDays,
} from "../src/words.ts";

const repo = fileURLToPath(new URL("../..", import.meta.url));

/**
 * Each outcome the node's audit calls write, with the tone its badge has: ok (it happened), warn
 * (waiting on somebody), bad (refused or failed: counted as a refusal), neutral (a routing decision).
 */
export const OUTCOMES = {
  ok: "ok", paired: "ok", started: "ok", stopped: "ok", stored: "ok",
  pending: "warn", pending_approval: "warn", pending_new_address: "warn", pending_out: "warn", late: "warn", skipped: "warn",
  bad_hello: "bad", bad_request: "bad", blobs_skipped_unreadable_media: "bad", blocked_silent: "bad", contact_cap: "bad",
  denied: "bad", envelope_invalid: "bad", error: "bad", failed: "bad", identity_required: "bad", invite_invalid: "bad",
  missing_bytes: "bad", not_found: "bad", not_our_domain: "bad", not_the_paired_ingress: "bad", own_invite: "bad",
  refused: "bad", refused_last: "bad", refused_origin: "bad", rejected: "bad", seal_required: "bad", superseded_leaf: "bad",
  terminate_not_configured: "bad", terminate_unavailable: "bad", too_large: "bad", unavailable: "bad", unknown: "bad",
  unpaired: "bad", unreachable: "bad", unreadable: "bad",
  certificate_renewed: "neutral", passthrough: "neutral", terminate: "neutral",
  // Written through a variable, so no literal names them at the call: the limiter's refusal
  // (internal/public/servers.go, Refusal.Code) and the peer refusals the sealed door audits.
  rate_limited: "bad", permission_denied: "bad", blocked_or_unknown: "bad",
};

/** Where a variable-written outcome comes from: the literal must still be in that file. */
const VIA_VARIABLE = {
  rate_limited: "internal/public/servers.go",
  permission_denied: "internal/public/servers.go",
  blocked_or_unknown: "internal/public/servers.go",
};

function goFiles(dir, out = []) {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) goFiles(p, out);
    else if (p.endsWith(".go") && !p.endsWith("_test.go")) out.push(p);
  }
  return out;
}

/**
 * Every outcome a call to an audit function (`audit`, `d.audit`, `n.opts.audit`, `recordAudit`…) passes
 * as a string literal in its last argument, with where. The arguments are read with their parentheses
 * and strings balanced, so a call over several lines is read whole.
 */
export function literalOutcomes(src) {
  const found = [];
  for (const m of src.matchAll(/\b(?:\w+\.)*(?:audit|Audit|recordAudit)\(/g)) {
    let i = m.index + m[0].length;
    let depth = 1;
    let inStr = false;
    for (; i < src.length && depth > 0; i++) {
      const c = src[i];
      if (inStr) { if (c === "\\") i++; else if (c === '"') inStr = false; continue; }
      if (c === '"') inStr = true; else if (c === "(") depth++; else if (c === ")") depth--;
    }
    const last = /"([a-z][a-z0-9_]*)"\s*,?\s*$/.exec(src.slice(m.index + m[0].length, i - 1));
    if (last) found.push({ outcome: last[1], line: src.slice(0, m.index).split("\n").length });
  }
  return found;
}

test("every outcome the node writes has a decided tone, and has it", () => {
  const written = new Map();
  for (const f of [...goFiles(join(repo, "internal")), ...goFiles(join(repo, "cmd"))]) {
    for (const { outcome, line } of literalOutcomes(readFileSync(f, "utf8"))) {
      if (!written.has(outcome)) written.set(outcome, `${f.slice(repo.length)}:${line}`);
    }
  }
  // The control: the scan reads real calls, or an empty scan would pass.
  for (const known of ["ok", "envelope_invalid", "pending_approval", "unavailable"]) assert.ok(written.has(known), `the scan did not find ${known}`);
  const undecided = [...written].filter(([o]) => !(o in OUTCOMES)).map(([o, at]) => `${o} (${at})`);
  assert.deepEqual(undecided, [], "an outcome the node writes has no decided tone: add it to OUTCOMES");
  for (const [o, file] of Object.entries(VIA_VARIABLE)) {
    assert.ok(readFileSync(join(repo, file), "utf8").includes(`"${o}"`), `${file} no longer writes ${o}`);
  }
  const wrong = Object.entries(OUTCOMES).filter(([o, tone]) => toneOf(o) !== tone).map(([o, tone]) => `${o}: ${toneOf(o)}, not ${tone}`);
  assert.deepEqual(wrong, []);
});

test("the scan reads a call over several lines, and a call whose outcome is not a literal names none", () => {
  assert.deepEqual(literalOutcomes('d.audit("settings_storage",\n\t"account:"+a+fmt.Sprint(n),\n\t"ok")').map((x) => x.outcome), ["ok"]);
  assert.deepEqual(literalOutcomes('d.audit("guest", "sealed_call", "account:"+id, r.Code())').map((x) => x.outcome), []);
  assert.deepEqual(literalOutcomes('n.opts.audit("rate_limited", "account:"+id+" bucket:"+b, "refused")').map((x) => x.outcome), ["refused"]);
});

test("a status is said in words", () => {
  assert.equal(statusWord("rate_limited"), "rate limited");
  assert.equal(statusWord("delivered_on_retry"), "delivered on retry");
});

test("a tool and a permission are said as an owner reads them, the integration's name first", () => {
  const cases = [
    [toolLabel("integration.github.search"), "Github · Search"],
    [toolLabel("integration.github.search", { github: "GitHub" }), "GitHub · Search"],
    [toolLabel("integration.internal-knowledge-base.query_documents_by_semantic_similarity"), "Internal knowledge base · Query documents by semantic similarity"],
    [toolLabel("integration.linear.create_issue"), "Linear · Create issue"],
    [toolLabel("integration.google_calendar"), "Google calendar tools"],
    [toolLabel("deepwiki_ask_wiki_question"), "Deepwiki ask wiki question"],
    [toolLabel("check_availability"), "Availability"],
    [permLabel("integration.github", { github: "GitHub" }), "GitHub tools"],
    [permLabel("integration.google_calendar"), "Google calendar tools"],
    [permLabel("message.media"), "Media & files"],
    [permLabel("integration.github.search", { github: "GitHub" }), "GitHub · Search"],
    [permLabel("deepwiki_ask_wiki_question"), "Deepwiki ask wiki question"],
    [permLabel("custom.thing"), "custom.thing"],
  ];
  assert.deepEqual(cases.map(([got]) => got), cases.map(([, want]) => want));
  // No label is the raw dotted name an owner cannot read.
  assert.ok(!/^Integration\./.test(toolLabel("integration.linear.create_issue")));
});

// What the module answers for an avatar, a tool's button, a trust flag and a field's label. PACT Cloud's
// portal/test/words.test.ts runs its verbatim copy of the module against the same initials and some of
// the other cases.
export const INITIALS = [
  ["Aarav Mehta", "AM"],
  ["Research assistant (bot)", "RA"],
  ["Acme Logistics Procurement Agent (EU-West)", "AA"],
  ["Konstantin (board)", "KO"],
  ["Alice · zS_0RTYx…jEobtk", "AL"],
  ["research-bot@lab.example", "RE"],
  ["Björn Þórðarson", "BÞ"],
  ["JNljQ3XfOgp7…", ""],
  ["JNljQ3Xf...KWTDKw", ""],
  ["(bot)", ""],
  ["", ""],
];

test("an avatar's initials are letters and digits of the name, never punctuation or an id", () => {
  for (const [name, want] of INITIALS) assert.equal(initialsOf(name), want, name);
});

test("a tool's button says what pressing it does", () => {
  assert.equal(toolAction("integration.github.search"), "Search");
  assert.equal(toolAction("integration.linear.create_issue"), "Create issue");
  assert.equal(toolAction("check_availability"), "Check availability");
  assert.equal(toolAction("deepwiki_ask_wiki_question"), "Run");
});

test("a trust flag is said in words", () => {
  assert.equal(trustWord("messages_only"), "Messages only");
  assert.equal(trustWord("may_instruct"), "May instruct your agent");
  assert.equal(trustWord("something_new"), "something new");
});

test("a tool's field is labelled by its title, else a short description, else its name", () => {
  assert.deepEqual(fieldLabel("q", { description: "Search query." }), { text: "Search query", help: "" });
  assert.deepEqual(fieldLabel("q", { title: "Query", description: "What to look for" }), { text: "Query", help: "What to look for" });
  const long = "The repository to search, as owner/name; leave empty to search every repository you can read";
  assert.deepEqual(fieldLabel("repo", { description: long }), { text: "repo", help: long });
  assert.deepEqual(fieldLabel("limit", {}), { text: "limit", help: "" });
});

// ---- dates and numbers: one way to say a time (the design review counted five or more formats). Every
// instant is built on the reader's own clock, so the cases hold in any time zone the suite runs in.
const at = (y, mo, d, h = 0, mi = 0, sec = 0) => new Date(y, mo - 1, d, h, mi, sec).getTime();
const NOW = at(2026, 9, 30, 15, 0);

test("a time is the clock today, the weekday this week, the date after", () => {
  assert.equal(when(at(2026, 9, 30, 9, 5), NOW), "09:05");
  assert.equal(when(at(2026, 9, 29, 23, 59), NOW), "Yesterday 23:59");
  assert.equal(when(at(2026, 9, 28, 14, 46), NOW), "Mon 14:46");
  assert.equal(when(at(2026, 9, 24, 8, 0), NOW), "Thu 08:00");
  assert.equal(when(at(2026, 9, 23, 8, 0), NOW), "23 Sep");
  assert.equal(when(at(2025, 9, 28, 8, 0), NOW), "28 Sep 2025");
  // Inside a thread, and on a deadline, the hour stays.
  assert.equal(when(at(2026, 9, 2, 7, 3), NOW, true), "2 Sep 07:03");
  assert.equal(when(at(2025, 12, 31, 23, 0), NOW, true), "31 Dec 2025 23:00");
  assert.equal(when(0, NOW), "");
});

test("a day heading, a clock and a date say the same day the same way", () => {
  assert.equal(dayOf(at(2026, 9, 30, 0, 0), NOW), "Today");
  assert.equal(dayOf(at(2026, 9, 29, 12), NOW), "Yesterday");
  assert.equal(dayOf(at(2026, 9, 27, 12), NOW), "Sun 27 Sep");
  assert.equal(dayOf(at(2025, 9, 27, 12), NOW), "27 Sep 2025");
  assert.equal(clockOf(at(2026, 9, 30, 7, 4, 9)), "07:04");
  assert.equal(clockOf(at(2026, 9, 30, 7, 4, 9), true), "07:04:09");
  assert.equal(dateOf(at(2026, 12, 8), NOW), "8 Dec");
  assert.equal(dateOf(at(2027, 12, 8), NOW), "8 Dec 2027");
});

test("how long ago, and how long until, in words", () => {
  assert.equal(ago(NOW - 30_000, NOW), "just now");
  assert.equal(ago(NOW - 5 * 60_000, NOW), "5 min ago");
  assert.equal(ago(NOW - 3 * 3_600_000, NOW), "3 h ago");
  assert.equal(ago(NOW - 86_400_000, NOW), "1 day ago");
  assert.equal(ago(NOW - 4 * 86_400_000, NOW), "4 days ago");
  assert.equal(ago(NOW + 12 * 86_400_000, NOW), "in 12 days");
  assert.equal(ago(NOW + 2 * 3_600_000, NOW), "in 2 h");
  assert.equal(ago(at(2026, 6, 1), NOW), "1 Jun");
});

test("a title carries the whole instant, seconds and zone", () => {
  const t = whenTitle(at(2026, 9, 28, 14, 5, 9));
  assert.match(t, /^Mon 28 Sep 2026, 14:05:09 (UTC|GMT[+-]\d{1,2}(:\d\d)?)$/);
});

test("a list read newest first gets one heading per day", () => {
  const rows = [at(2026, 9, 30, 12), at(2026, 9, 30, 9), at(2026, 9, 29, 20), at(2026, 9, 27, 8)];
  const out = withDays(rows, (r) => r, NOW).map((x) => ("day" in x ? x.day : "row"));
  assert.deepEqual(out, ["Today", "row", "row", "Yesterday", "row", "Sun 27 Sep", "row"]);
});

test("a count is grouped", () => {
  assert.equal(num(1246), "1,246");
  assert.equal(num(233808), "233,808");
  assert.equal(num(7), "7");
});

// ---- the audit trail's filters: every actor kind the node's store can hold (its CHECK) has a word,
// and none of them is the code itself.
test("every actor kind the node records has a word of its own", () => {
  const mig = readFileSync(join(repo, "migrations/sqlite/0001_init.sql"), "utf8");
  const kinds = /actor_kind TEXT NOT NULL CHECK \(actor_kind IN \(([^)]*)\)\)/.exec(mig)[1].match(/'([^']+)'/g).map((k) => k.slice(1, -1));
  assert.ok(kinds.length >= 6, `read ${kinds.length} kinds from the CHECK`);
  for (const k of kinds) {
    const w = kindLabel(k);
    assert.match(w, /^[A-Z][a-z]+( [a-z]+)*$/, `${k} is said as ${w}`);
  }
  assert.equal(kindLabel("token"), "Agent key");
  assert.equal(kindLabel("cli"), "Command line");
  assert.equal(kindLabel("guest"), "Stranger");
  assert.equal(kindLabel("cli", { cli: "Operator" }), "Operator");
  assert.equal(actionWord("identity_gate"), "Identity gate");
  assert.equal(actionWord("operator.suspend"), "Operator suspend");
});

// ---- messages
test("an undelivered message says why in words, and a code it does not know says only that it did not arrive", () => {
  for (const code of ["pending_approval", "unavailable", "envelope_invalid", "permission_denied", "rate_limited", "too_large", "seal_required", "expired"]) {
    const w = undeliveredReason(code);
    assert.notEqual(w, "it did not arrive", code);
    assert.ok(!w.includes("_"), code);
  }
  assert.equal(undeliveredReason("something_new"), "it did not arrive");
  assert.equal(undeliveredReason(null), "it did not arrive");
});

test("a file is said by what it is, not by its MIME type", () => {
  assert.equal(mediaKind("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "q3.xlsx"), "Excel spreadsheet");
  assert.equal(mediaKind("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "noext"), "Spreadsheet");
  assert.equal(mediaKind("application/pdf", "a"), "PDF");
  assert.equal(mediaKind("image/png", ""), "Image");
  assert.equal(mediaKind("application/octet-stream", "blob"), "File");
  assert.equal(fileSize(2.2 * 1024 * 1024), "2.2 MB");
  assert.equal(fileSize(640 * 1024), "640 KB");
  assert.equal(fileSize(0), "");
});

// ---- invites and contacts
test("an invite's state is redemption's: revoked, then expired, then used up", () => {
  const live = { revoked: false, expiresAt: NOW + 86_400_000, uses: 0, maxUses: 1 };
  assert.equal(inviteState(live, NOW), "live");
  assert.equal(inviteState({ ...live, revoked: true, expiresAt: NOW - 1 }, NOW), "revoked");
  assert.equal(inviteState({ ...live, expiresAt: NOW - 1, uses: 1 }, NOW), "expired");
  assert.equal(inviteState({ ...live, uses: 500, maxUses: 500 }, NOW), "used_up");
  assert.equal(inviteState({ ...live, uses: 17, maxUses: 0 }, NOW), "live");
  assert.equal(usesText(9, 10), "9 of 10");
  assert.equal(usesText(17, 0), "17 used · no limit");
  assert.equal(usesText(1200, 5000), "1,200 of 5,000");
});

test("every contact state the node stores has an owner's word, and only the ordinary one goes unpilled", () => {
  const mig = readFileSync(join(repo, "migrations/sqlite/0002_contacts.sql"), "utf8");
  const states = /status\s+TEXT NOT NULL CHECK \(status IN \(([^)]*)\)\)/.exec(mig)[1].match(/'([^']+)'/g).map((k) => k.slice(1, -1));
  assert.deepEqual([...states].sort(), ["active", "blocked", "pending_in", "pending_out"]);
  for (const st of states) assert.ok(!contactStatusWord(st).includes("_"), st);
  assert.equal(contactStatusWord("pending_in"), "asked you");
  assert.equal(contactStatusWord("pending_out"), "you asked");
  assert.deepEqual(states.filter(contactPill).sort(), ["blocked", "pending_in", "pending_out"]);
});
