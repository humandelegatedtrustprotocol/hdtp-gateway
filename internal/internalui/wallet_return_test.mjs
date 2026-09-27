// Runs the page script a web wallet navigates back to (wallet_return.js, served at /wallet/return.js)
// against a minimal browser: the location it arrives at, the document it writes to, the cookie jar,
// history and fetch. `make test-js` runs it (part of `make check`): `node --test` and nothing else,
// so it needs no dependency beyond the Node that `make web` already requires.
//
// What it holds (PACT §9.1; the identity-boundary design §2.3):
//   - the fragment is taken out of the address bar BEFORE anything is sent anywhere;
//   - the answer is POSTed once, same-origin, to /identity/<slug>/wallet/install, with the chain and
//     the state in the body and the CSRF cookie's value in X-Pact-Csrf (the cookie named by the page);
//   - a refusal from the wallet (#error=…) and an arrival with nothing to install send nothing;
//   - each answer of the node is shown for what it is.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const source = readFileSync(fileURLToPath(new URL("./wallet_return.js", import.meta.url)), "utf8");

// run loads the page at `href` with `cookie` and lets the node answer `reply` ({status, body}).
async function run({ href, cookie = "pact_csrf_t=tok-123", reply = { status: 200, body: {} } }) {
  const u = new URL(href);
  const events = [];
  const out = { textContent: "Installing…", className: "" };
  const location = { hash: u.hash, search: u.search, pathname: u.pathname };
  const ctx = {
    URLSearchParams,
    location,
    history: {
      replaceState(_s, _t, url) {
        events.push(["replaceState", url]);
        location.hash = "";
      },
    },
    document: {
      cookie,
      getElementById: (id) => (id === "out" ? out : null),
      querySelector: (sel) => (sel === 'meta[name="pact-csrf-cookie"]' ? { content: "pact_csrf_t" } : null),
    },
    fetch(url, opts) {
      events.push(["fetch", url, opts, location.hash]);
      return Promise.resolve({ status: reply.status, ok: reply.status >= 200 && reply.status < 300, json: () => Promise.resolve(reply.body) });
    },
  };
  vm.runInNewContext(source, ctx);
  for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r)); // let the promise chain settle
  return { events, out, fetches: events.filter((e) => e[0] === "fetch") };
}

const answer = "https://node.example/wallet/return?slug=alice#chain=TEVBRg.Uk9PVA&state=" + "s".repeat(43);

test("the answer is cleared from the address bar, then POSTed once with the state and the CSRF header", async () => {
  const { events, fetches, out } = await run({
    href: answer,
    cookie: "pact_session_t=sess; pact_csrf_t=tok-123; pact_csrf_tx=other",
    reply: { status: 200, body: { endpoint: "https://node.example/a/alice/mcp", not_after: "2027-09-27T00:00:00Z", notice: "" } },
  });
  assert.deepEqual(events[0], ["replaceState", "/wallet/return?slug=alice"], "the fragment must be cleared first");
  assert.equal(fetches.length, 1);
  const [, url, opts, hashAtSend] = fetches[0];
  assert.equal(hashAtSend, "", "the answer was still in the address bar when it was sent");
  assert.equal(url, "/identity/alice/wallet/install");
  assert.equal(opts.method, "POST");
  assert.equal(opts.credentials, "same-origin");
  assert.equal(opts.headers["X-Pact-Csrf"], "tok-123", "the CSRF header is the cookie the page names, not a prefix of another");
  const body = new URLSearchParams(opts.body);
  assert.equal(body.get("chain"), "TEVBRg.Uk9PVA");
  assert.equal(body.get("state"), "s".repeat(43));
  assert.deepEqual([...body.keys()].sort(), ["chain", "state"]);
  assert.match(out.textContent, /^Installed: https:\/\/node\.example\/a\/alice\/mcp, valid until 2027-09-27T00:00:00Z\.$/);
  assert.equal(out.className, "ok");
});

test("a move notice the node returns is shown", async () => {
  const { out } = await run({ href: answer, reply: { status: 200, body: { endpoint: "e", not_after: "t", notice: "Run announce." } } });
  assert.match(out.textContent, /Run announce\.$/);
});

test("a wallet that did not sign: nothing is sent, and the page says so", async () => {
  const { events, fetches, out } = await run({ href: "https://node.example/wallet/return?slug=alice#error=cancelled&state=" + "s".repeat(43) });
  assert.equal(fetches.length, 0);
  assert.equal(events[0][0], "replaceState");
  assert.match(out.textContent, /did not sign \(cancelled\)/);
  assert.equal(out.className, "err");
});

test("an arrival with nothing to install sends nothing", async () => {
  for (const href of [
    "https://node.example/wallet/return?slug=alice",
    "https://node.example/wallet/return?slug=alice#chain=a.b",
    "https://node.example/wallet/return#chain=a.b&state=" + "s".repeat(43),
  ]) {
    const { fetches, out } = await run({ href });
    assert.equal(fetches.length, 0, href);
    assert.match(out.textContent, /Nothing to install/, href);
  }
});

test("each refusal of the node is shown for what it is", async () => {
  let r = await run({ href: answer, reply: { status: 401, body: {} } });
  assert.match(r.out.textContent, /sign in to this node's portal/);
  r = await run({ href: answer, reply: { status: 409, body: { error: "this answer is not for the request waiting here" } } });
  assert.equal(r.out.textContent, "Not installed: this answer is not for the request waiting here.");
  assert.equal(r.out.className, "err");
});
