// The Inbox's unread counts are the node's, counted at runtime from each conversation's read marker
// and capped (internal/internalui/messages_pages.go, UnreadCap): a conversation's row and the
// sidebar's Inbox chip draw them with CountChip, so a capped count reads "50+" and an exact one its
// number, the same shape and the same chip as PACT Cloud's (owner, 2026-10-01: "dont store the count
// but compute on runtime based on page size and how many of the page are actually unread"). Read
// from the source where it is wiring, because the portal has no DOM test harness.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { tallyLabel, tallyText } from "../src/words.ts";

const src = (p) => readFileSync(new URL(`../src/${p}`, import.meta.url), "utf8");

test("the shapes the node answers read as the chip shows them", () => {
  // UnreadCap is 50; one past it is answered as the cap, capped.
  assert.equal(tallyText({ count: 50, capped: true }), "50+");
  assert.equal(tallyLabel({ count: 50, capped: true }, "unread"), "more than 50 unread");
  assert.equal(tallyText({ count: 3, capped: false }), "3");
  assert.equal(tallyLabel({ count: 3, capped: false }, "unread"), "3 unread");
});

test("a conversation's row draws its count with CountChip, from the node's tally", () => {
  const view = src("views/messages.tsx");
  assert.match(view, /unread: Tally;/);
  assert.match(view, /\{tallyCount\(p\.unread\) > 0 && <CountChip n=\{p\.unread\} noun="unread" tone="ok" \/>\}/);
  // The shape it replaces: a raw number in a span, which could not say "50+".
  assert.doesNotMatch(view, /<span className="unread">\{p\.unread\}<\/span>/);
});

test("the sidebar's Inbox chip is the node's total, never a sum of the rows", () => {
  // The node stops the total at its cap (UnreadCap): the screenshot's 63 + 1 unread is answered as
  // { count: 50, capped: true }, and the chip says "50+", as PACT Cloud's does.
  assert.equal(tallyText({ count: 50, capped: true }), "50+");
  const app = src("app.tsx");
  // The cap is the answer's: the view neither sums nor caps.
  assert.doesNotMatch(app, /Math\.min\([^)]*unread|> ?50\b/);
  assert.match(app, /return d\.unread \?\? 0;/);
  assert.doesNotMatch(app, /reduce\(\(n, p\) => n \+ \(p\.unread/);
  // And a read made in the Inbox drops it at once.
  assert.match(app, /addEventListener\("pact:counts", onRead\)/);
});

test("showing a conversation marks it read through the newest message shown, and only when there is something to read", () => {
  const view = src("views/messages.tsx");
  assert.match(view, /if \(!sel \|\| selUnread === 0 \|\| through === 0 \|\| !visible\) return;/);
  // Coming back to a hidden page reads what is on screen: the effect runs again when visibility changes.
  assert.match(view, /\}, \[sel, selUnread, through, visible, load\]\);/);
  assert.match(view, /postForm\("\/messages\/read", \{ contact: sel, through: String\(through\) \}\)/);
  assert.match(view, /dispatchEvent\(new Event\("pact:counts"\)\)/);
});
