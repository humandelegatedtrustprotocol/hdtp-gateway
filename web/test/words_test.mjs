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
import { fieldLabel, initialsOf, permLabel, statusWord, toneOf, toolAction, toolLabel, trustWord } from "../src/words.ts";

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
// portal/test/words.test.ts runs its verbatim copy of the module against these same cases.
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
