// A conversation whose contact was removed is listed by the node with the status "removed" and the
// label its threads kept, " · removed" after it (internal/internalui/labels.go, conversationLabel;
// conversations_removed_test.go holds the answer). The view shows it as a record: the messages, and
// no composer, no tools asked of their node, no pinned badge and no contact panel, since there is no
// contact. Read from the source where it is wiring, because the portal has no DOM test harness.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const view = readFileSync(new URL("../src/views/messages.tsx", import.meta.url), "utf8");

test("the view knows a removed conversation by the node's status", () => {
  assert.match(view, /const selRemoved = \(d\?\.contacts \?\? \[\]\)\.find\(\(p\) => p\.fingerprint === sel\)\?\.status === "removed";/);
});

test("nothing that writes to, calls or shows the contact is offered for a removed conversation", () => {
  assert.match(view, /if \(!sel \|\| selRemoved\) return;\n/, "the tools of a removed contact's node are not asked for");
  assert.match(view, /\{!selRemoved && <><div className="composer">/, "no composer");
  assert.match(view, /\{!selRemoved && toolsOpen && \(/, "no tool dock");
  assert.match(view, /\{!selRemoved && <Badge tone="ok" title=\{`Their key is pinned/, "no pinned badge: nothing is pinned");
  assert.match(view, /\{current && !selRemoved && <ContactPanel /, "no contact panel");
  assert.match(view, /\{selRemoved && <div className="foot-note">No longer a contact\./, "and it says why");
  // One composer, one panel: a second, ungated copy would undo the gate.
  assert.equal(view.match(/className="composer"/g)?.length, 1);
  assert.equal(view.match(/<ContactPanel /g)?.length, 1);
});
