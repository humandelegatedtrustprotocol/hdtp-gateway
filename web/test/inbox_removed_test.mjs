// A conversation whose contact was removed is listed by the node with the status "removed" and the
// label its threads kept, " · removed" after it (internal/internalui/labels.go, conversationLabel;
// conversations_removed_test.go holds the answer). The view shows it as a record: the messages, and
// no composer, no tools asked of their node, no pinned badge and no contact panel, since there is no
// contact. Read from the source where it is wiring, because the portal has no DOM test harness.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const view = readFileSync(new URL("../src/views/messages.tsx", import.meta.url), "utf8");

test("the view knows a removed or read-only conversation by the node's status", () => {
  assert.match(view, /const selStatus = \(d\?\.contacts \?\? \[\]\)\.find\(\(p\) => p\.fingerprint === sel\)\?\.status \?\? "";/);
  assert.match(view, /const selRemoved = selStatus === "removed";/);
  // Written to only while active: a request's or a blocked row's held conversation is read-only too.
  assert.match(view, /const selReadOnly = selStatus !== "" && selStatus !== "active";/);
});

test("nothing that writes to or calls the contact is offered unless the contact is active", () => {
  assert.match(view, /if \(!sel \|\| selReadOnly\) return;\n/, "the tools of a read-only conversation's node are not asked for");
  assert.match(view, /\{!selReadOnly && <><div className="composer">/, "no composer");
  assert.match(view, /\{!selReadOnly && toolsOpen && \(/, "no tool dock");
  assert.match(view, /\{!selReadOnly && <Badge tone="ok" title=\{`Their key is pinned/, "no pinned badge");
  assert.match(view, /\{selReadOnly && !selRemoved && <div className="foot-note">Not an active contact/, "a request's or blocked row's conversation says why");
  assert.match(view, /\{current && !selRemoved && <ContactPanel /, "no contact panel");
  assert.match(view, /\{selRemoved && <div className="foot-note">No longer a contact\./, "and it says why");
  // One composer, one panel: a second, ungated copy would undo the gate.
  assert.equal(view.match(/className="composer"/g)?.length, 1);
  assert.equal(view.match(/<ContactPanel /g)?.length, 1);
});
