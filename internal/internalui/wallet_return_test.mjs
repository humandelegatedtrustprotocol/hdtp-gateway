// Runs the page script a web wallet navigates back to (wallet_return.js, served at /wallet/return.js)
// against a minimal browser: the location it arrives at, the document it writes to, the cookie jar,
// history and fetch. `make test-js` runs it (part of `make check`): `node --test` and nothing else,
// so it needs no dependency beyond the Node that `make web` already requires.
//
// The document holds exactly the elements the page's template names (wallet_pages.go: every id="…",
// and a section st-<id> for every wrState), so an id the script reaches for that the page does not
// carry fails here.
//
// What it holds (HDTP §9.1; the identity-boundary design §2.3):
//   - the fragment is taken out of the address bar BEFORE anything is sent anywhere;
//   - the answer is POSTed once, same-origin, to /identity/<slug>/wallet/install, with the chain and
//     the state in the body and the CSRF cookie's value in X-HDTP-Csrf (the cookie named by the page);
//   - a refusal from the wallet (#error=…) and an arrival with nothing to install send nothing;
//   - each answer of the node is shown as its own state, with the actions that help, and the page
//     stops saying it is busy.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const source = readFileSync(fileURLToPath(new URL("./wallet_return.js", import.meta.url)), "utf8");
const page = readFileSync(fileURLToPath(new URL("./wallet_pages.go", import.meta.url)), "utf8");
const tmpl = page.slice(page.indexOf("var walletReturnStates"), page.indexOf("type walletField struct"));
const ids = new Set([...tmpl.matchAll(/id="([\w-]+)"/g)].map((m) => m[1]));
for (const m of tmpl.matchAll(/wrState\("([a-z_-]+)"/g)) ids.add("st-" + m[1]);
assert.ok(ids.has("answer") && ids.has("st-working") && ids.has("st-installed") && ids.has("st-r-answered"), "the template's ids were not read");

// run loads the page at `href` with `cookie` and lets the node answer `reply` ({status, body} with
// a JSON body, {status, text} with one that is not, or {throws: true} for no reply at all).
async function run({ href, cookie = "hdtp_csrf_t=tok-123", reply = { status: 200, body: {} } }) {
  const u = new URL(href);
  const events = [];
  const els = {};
  for (const id of ids) {
    const attrs = id === "answer" ? { "data-kind": "working", "aria-busy": "true" } : {};
    els[id] = {
      id, textContent: "", href: "", hidden: id.startsWith("st-") && id !== "st-working",
      setAttribute(k, v) { attrs[k] = String(v); },
      getAttribute(k) { return attrs[k]; },
      attrs,
    };
  }
  const location = { hash: u.hash, search: u.search, pathname: u.pathname };
  const ctx = {
    URLSearchParams,
    Date,
    location,
    history: {
      replaceState(_s, _t, url) {
        events.push(["replaceState", url]);
        location.hash = "";
      },
    },
    document: {
      cookie,
      getElementById: (id) => els[id] || null,
      querySelector: (sel) => (sel === 'meta[name="hdtp-csrf-cookie"]' ? { content: "hdtp_csrf_t" } : null),
    },
    fetch(url, opts) {
      events.push(["fetch", url, opts, location.hash]);
      if (reply.throws) return Promise.reject(new TypeError("Failed to fetch"));
      const json = () => ("text" in reply ? Promise.reject(new SyntaxError("not JSON")) : Promise.resolve(reply.body));
      return Promise.resolve({ status: reply.status, ok: reply.status >= 200 && reply.status < 300, json });
    },
  };
  vm.runInNewContext(source, ctx);
  for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r)); // let the promise chain settle
  const shown = Object.values(els).filter((e) => e.id.startsWith("st-") && !e.hidden).map((e) => e.id.slice(3));
  const visible = (id) => !els[id].hidden;
  return { events, els, shown, visible, kind: els.answer.attrs["data-kind"], busy: els.answer.attrs["aria-busy"], fetches: events.filter((e) => e[0] === "fetch") };
}

const answer = "https://node.example/wallet/return?slug=alice#chain=TEVBRg.Uk9PVA&state=" + "s".repeat(43);

// One state and only one is showing, the busy mark is gone, and Back to Identity is offered.
function settled(r, state) {
  assert.deepEqual(r.shown, [state]);
  assert.equal(r.busy, "false");
  assert.ok(r.visible("actions") && r.visible("a-back"));
}

test("the answer is cleared from the address bar, then POSTed once with the state and the CSRF header", async () => {
  const r = await run({
    href: answer,
    cookie: "hdtp_session_t=sess; hdtp_csrf_t=tok-123; hdtp_csrf_tx=other",
    reply: { status: 200, body: { name: "Alice", endpoint: "https://node.example/a/alice/mcp", not_before: "2026-09-30T14:05:09Z", not_after: "2027-09-30T14:05:09Z", notice: "", warnings: [] } },
  });
  assert.deepEqual(r.events[0], ["replaceState", "/wallet/return?slug=alice"], "the fragment must be cleared first");
  assert.equal(r.fetches.length, 1);
  const [, url, opts, hashAtSend] = r.fetches[0];
  assert.equal(hashAtSend, "", "the answer was still in the address bar when it was sent");
  assert.equal(url, "/identity/alice/wallet/install");
  assert.equal(opts.method, "POST");
  assert.equal(opts.credentials, "same-origin");
  assert.equal(opts.headers["X-HDTP-Csrf"], "tok-123", "the CSRF header is the cookie the page names, not a prefix of another");
  const body = new URLSearchParams(opts.body);
  assert.equal(body.get("chain"), "TEVBRg.Uk9PVA");
  assert.equal(body.get("state"), "s".repeat(43));
  assert.deepEqual([...body.keys()].sort(), ["chain", "state"]);
  // Installed: what, where, and for how long, as the answer gives it.
  settled(r, "installed");
  assert.equal(r.kind, "ok");
  assert.equal(r.els["f-name"].textContent, "Alice");
  assert.equal(r.els["f-address"].textContent, "https://node.example/a/alice/mcp");
  assert.equal(r.els["f-from"].textContent, "30 Sep 2026, 14:05 UTC");
  assert.equal(r.els["f-until"].textContent, "30 Sep 2027, 14:05 UTC");
  assert.ok(r.visible("p-installed") && !r.visible("p-installed-warn") && !r.visible("f-warn") && !r.visible("f-notice"));
  assert.ok(!r.visible("a-sign") && !r.visible("a-login") && !r.visible("detail"), "an install needs no other action");
});

test("a move notice the node returns is shown", async () => {
  const r = await run({ href: answer, reply: { status: 200, body: { endpoint: "e", not_after: "t", notice: "Run announce." } } });
  settled(r, "installed");
  assert.equal(r.els["f-notice"].textContent, "Run announce.");
  assert.ok(r.visible("f-notice"));
});

test("an install the node finished with a warning says installed, and the warning", async () => {
  const r = await run({
    href: answer,
    reply: { status: 200, body: { endpoint: "e", not_after: "t", notice: "", warnings: ["restart the node, then announce."] } },
  });
  settled(r, "installed");
  assert.equal(r.kind, "warn");
  assert.ok(r.visible("f-warn") && r.visible("p-installed-warn") && !r.visible("p-installed"));
  assert.ok(r.visible("i-installed-warn") && !r.visible("i-installed"));
  assert.equal(r.els["f-warnings"].textContent, "Restart the node, then announce.");
});

test("a wallet that declined: nothing is sent, and the page says so, with Sign again", async () => {
  const r = await run({ href: "https://node.example/wallet/return?slug=alice#error=cancelled&state=" + "s".repeat(43) });
  assert.equal(r.fetches.length, 0);
  assert.equal(r.events[0][0], "replaceState");
  settled(r, "wallet_cancelled");
  assert.equal(r.els.detail.textContent, "");
  assert.ok(r.visible("a-sign"));
  assert.equal(r.els["a-sign"].href, "/identity/alice/wallet");
});

test("a wallet that failed has its own state", async () => {
  const r = await run({ href: "https://node.example/wallet/return?slug=alice#error=failed&state=" + "s".repeat(43) });
  assert.equal(r.fetches.length, 0);
  settled(r, "wallet_failed");
  assert.equal(r.kind, "err");
});

test("a refusal code the page does not know is a fixed state, never the fragment's text", async () => {
  for (const code of ["Your node is compromised: call +1 555 0100", "installed", "answered", "constructor", "__proto__"]) {
    const r = await run({
      href: "https://node.example/wallet/return?slug=alice#error=" + encodeURIComponent(code) + "&state=" + "s".repeat(43),
    });
    assert.equal(r.fetches.length, 0, code);
    settled(r, "wallet_other");
    assert.equal(r.els.detail.textContent, "", code);
    assert.ok(!r.visible("detail"), code);
  }
});

test("an arrival with nothing to install sends nothing", async () => {
  for (const href of [
    "https://node.example/wallet/return?slug=alice",
    "https://node.example/wallet/return?slug=alice#chain=a.b",
    "https://node.example/wallet/return#chain=a.b&state=" + "s".repeat(43),
  ]) {
    const r = await run({ href });
    assert.equal(r.fetches.length, 0, href);
    settled(r, "empty");
    assert.ok(!r.visible("a-sign"), href);
  }
});

test("each refusal of the install is its own state, its words and no code; a failure keeps a reference", async () => {
  const cases = [
    [409, "answered", "ok", false],
    [409, "not_this_request", "err", true],
    [409, "no_request", "err", true],
    [400, "wrong_root", "err", true],
    [400, "wrong_key", "err", true],
    [400, "not_newer", "err", true],
    [404, "not_found", "err", false],
    [500, "failed", "err", true],
  ];
  for (const [status, code, kind, sign] of cases) {
    const r = await run({ href: answer, reply: { status, body: { error: "a sentence", code } } });
    settled(r, "r-" + code);
    assert.equal(r.kind, kind, code);
    assert.equal(r.els.detail.textContent, code === "failed" ? `Reference: HTTP ${status}` : "", code);
    assert.equal(r.visible("detail"), code === "failed", code);
    assert.equal(r.visible("a-sign"), sign, code);
  }
  // A refused chain and a malformed answer carry the node's sentence too.
  let r = await run({ href: answer, reply: { status: 400, body: { error: "chain refused by rule 4: leaf outside its validity", code: "chain" } } });
  settled(r, "r-chain");
  assert.equal(r.els.detail.textContent, "chain refused by rule 4: leaf outside its validity");
  r = await run({ href: answer, reply: { status: 400, body: { error: "the chain is two certificates, leaf then root", code: "malformed" } } });
  settled(r, "r-malformed");
});

test("a code the node answers that the page has no state for is shown as a plain refusal", async () => {
  for (const code of ["something_new", "st-installed", "installed", "working", "wallet_cancelled", "r-answered", "<b>x</b>"]) {
    const r = await run({ href: answer, reply: { status: 409, body: { error: "refused", code } } });
    settled(r, "refused");
    assert.equal(r.els.detail.textContent, "Reference: HTTP 409 — refused", code);
  }
});

test("the portal's own refusals, which are not JSON, each have a state", async () => {
  let r = await run({ href: answer, reply: { status: 401, text: "sign in first" } });
  settled(r, "signed_out");
  assert.ok(r.visible("a-login") && !r.visible("a-sign"));
  assert.equal(r.els["a-login"].href, "/login?next=%2Fidentity%2Falice%2Fwallet");
  r = await run({ href: answer, reply: { status: 403, text: "cross-origin request refused" } });
  settled(r, "forbidden");
  assert.ok(r.visible("a-sign"));
  assert.ok(!r.visible("detail"), "a state that explains itself shows no status line");
  r = await run({ href: answer, reply: { status: 502, text: "Bad Gateway" } });
  settled(r, "refused");
  assert.equal(r.els.detail.textContent, "Reference: HTTP 502");
});

test("no reply at all does not claim that nothing was installed", async () => {
  const r = await run({ href: answer, reply: { throws: true } });
  settled(r, "unreachable");
  assert.equal(r.kind, "warn");
  assert.match(tmpl, /cannot say whether it was installed/);
});

test("the slug reaches a link only as one encoded path segment", async () => {
  const r = await run({ href: "https://node.example/wallet/return?slug=" + encodeURIComponent("../x?y#z") + "#error=cancelled&state=" + "s".repeat(43) });
  assert.equal(r.els["a-sign"].href, "/identity/..%2Fx%3Fy%23z/wallet");
});
