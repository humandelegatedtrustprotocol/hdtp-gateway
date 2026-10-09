// Deleting a conversation (node SPEC §7.9). The node's view is a conversation with a person, merging
// every thread with them, and the node answers which threads those are (`threads`,
// internal/internalui/messages_pages.go). Delete asks first, in words that say the contact keeps their
// copy, then deletes each of those threads through POST /threads/{id}/delete, the one operation the
// owner MCP's delete_thread runs too. Read from the source, because the portal has no DOM test harness.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const view = readFileSync(new URL("../src/views/messages.tsx", import.meta.url), "utf8");

test("Delete asks first and says the contact keeps their copy", () => {
  assert.match(view, /aria-label="Delete conversation"\n\s+confirm=\{`Delete your conversation with \$\{current\.label\}\? It is deleted here only: they keep their copy\.`\}/);
  assert.match(view, /\{\(d\.threads \?\? \[\]\)\.length > 0 && <Toolbar className="delete">/, "offered only for a conversation with threads to delete");
});

test("Delete deletes each thread the conversation merges, through the one operation", () => {
  assert.match(view, /for \(const id of d\?\.threads \?\? \[\]\) \{\n\s+const r = await postForm\(`\/threads\/\$\{encodeURIComponent\(id\)\}\/delete`, \{\}\);/);
  assert.match(view, /if \(!r\.ok && r\.status !== 404\) failed = true;/, "a thread already gone is not a failure; any other refusal is said");
});

test("a link is fetched for its message, so the file is recorded on it", () => {
  assert.match(view, /postForm\("\/media\/fetch", \{ message: id \}\)/);
  assert.doesNotMatch(view, /postForm\("\/media\/fetch", \{ url:/);
});
