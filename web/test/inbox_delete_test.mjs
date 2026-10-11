// Deleting a conversation (node SPEC §7.9). The node's view is a conversation with a person, merging
// every thread with them, and the node answers which threads those are (`threads`,
// internal/internalui/messages_pages.go). Delete asks first, in words that say the contact keeps their
// copy, then deletes each of those threads through POST /thread/delete, the one operation the
// owner MCP's delete_thread runs too. It is the contact panel's last section, set apart, and nowhere
// else (the owner, 2026-10-11: "move delete conversation button inside the right sidebar in chat").
// Read from the source, because the portal has no DOM test harness; the cloud's e2e/portal-layout.mjs
// presses it in a browser.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const view = readFileSync(new URL("../src/views/messages.tsx", import.meta.url), "utf8");

test("Delete asks first and says the contact keeps their copy", () => {
  assert.match(view, /<Button variant="danger" icon="trash"\n\s+confirm=\{`Delete your conversation with \$\{current\.label\}\? It is deleted here only: they keep their copy\.`\}\n\s+onClick=\{deleteConversation\}>Delete conversation<\/Button>/);
  assert.match(view, /end=\{\(d\.threads \?\? \[\]\)\.length > 0 && \(\n\s+<div className="panel-end">/, "offered only for a conversation with threads to delete");
});

test("Delete is the contact panel's last section, and one control", () => {
  // Handed to the panel as `end`, which it draws after every other section, removed contact or not.
  assert.match(view, /\{current && <ContactPanel fpr=\{current\.fingerprint\} label=\{current\.label\} removed=\{selRemoved\}/);
  assert.match(view, /<\/>\}\n\s+\{end\}\n\s+<\/aside>/, "end is the panel's last child");
  // Not in the conversation's header, nor anywhere else: one Delete, one confirm.
  const header = view.slice(view.indexOf('<div className="thread-h">'), view.indexOf('<div className="log"'));
  assert.ok(header.length > 0);
  assert.doesNotMatch(header, /trash|[Dd]elete/, "the header carries no Delete");
  assert.equal(view.match(/onClick=\{deleteConversation\}/g)?.length, 1);
  assert.equal(view.match(/Delete your conversation with/g)?.length, 1);
  // Reachable wherever the panel is: its toggle is in the header for every conversation, removed included.
  assert.match(view, /<\/div>\n\s+<div className="end">\n[^\n]*\n\s+<Toolbar className="details">/);
});

test("a deleted conversation leaves the panel for the list, as the cloud's does", () => {
  // A removed contact's row goes with its last thread, so staying put left a phone on a panel pane with
  // no panel: a blank page. Only a delete that went through moves; a refused one stays to say why.
  assert.match(view, /if \(failed\) setDeleteErr\("The conversation was not deleted in full\. Try again\."\);\n\s+else \{\n\s+setSel\(""\);\n\s+setPane\("list"\);\n\s+history\.replaceState\(null, "", "\/messages"\);\n\s+\}/);
});

test("a refused delete is said beside the button, in the same words", () => {
  assert.match(view, /if \(failed\) setDeleteErr\("The conversation was not deleted in full\. Try again\."\);/);
  assert.match(view, /<h3>Conversation<\/h3>\n\s+\{deleteErr && <Notice kind="err">\{deleteErr\}<\/Notice>\}/);
  assert.match(view, /setSel\(fpr\);\n\s+setDeleteErr\(""\);/, "another conversation does not inherit it");
});

test("Delete deletes each thread the conversation merges, through the one operation", () => {
  // The id travels in the form, never in the path: a contact chooses it, and a URL parser drops a
  // "." or ".." path segment before the request leaves the browser (encodeURIComponent keeps dots).
  assert.match(view, /for \(const id of d\?\.threads \?\? \[\]\) \{\n\s+const r = await postForm\("\/thread\/delete", \{ thread_id: id \}\);/);
  assert.doesNotMatch(view, /\/threads?\/\$\{/, "no thread id in a path");
  assert.match(view, /if \(!r\.ok && r\.status !== 404\) failed = true;/, "a thread already gone is not a failure; any other refusal is said");
});

test("a link is fetched for its message, so the file is recorded on it", () => {
  assert.match(view, /postForm\("\/media\/fetch", \{ message: id \}\)/);
  assert.doesNotMatch(view, /postForm\("\/media\/fetch", \{ url:/);
});
