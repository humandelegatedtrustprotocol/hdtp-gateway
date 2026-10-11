// A conversation whose contact was removed is listed by the node with the status "removed" and the
// label its threads kept, " · removed" after it (internal/internalui/labels.go, conversationLabel;
// conversations_removed_test.go holds the answer). The view shows it as a record: the messages, and
// no composer, no tools asked of their node and no pinned badge; its panel says who they were and
// holds Delete, and reads and offers nothing of a contact, since there is none. Read from the source
// where it is wiring, because the portal has no DOM test harness.
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
  assert.match(view, /\{selRemoved && <div className="foot-note">No longer a contact\./, "and it says why");
  // One composer, one panel: a second, ungated copy would undo the gate.
  assert.equal(view.match(/className="composer"/g)?.length, 1);
  assert.equal(view.match(/<ContactPanel /g)?.length, 1);
});

test("a removed contact's panel reads nothing of a contact and offers only Delete", () => {
  assert.match(view, /<ContactPanel fpr=\{current\.fingerprint\} label=\{current\.label\} removed=\{selRemoved\}/);
  // No /api/contacts/{fpr} and no audit read: there is no contact, and a read that 404s left "Loading…".
  assert.match(view, /const load = useCallback\(\(\) => \{\n\s+if \(removed\) return;\n\s+getJSON<Contact>/);
  // Permissions, what they let you do, activity and the profile link are drawn for a contact only.
  const panel = view.slice(view.indexOf("function ContactPanel("), view.indexOf("function csrfCookie("));
  const from = panel.indexOf("{!removed && <>");
  const gated = panel.slice(from, panel.indexOf("\n      </>}", from));
  for (const part of ["What they may do here", "What they let you do there", "Recent activity", "Open full profile"]) {
    assert.ok(gated.includes(part), `${part} is drawn only for a contact`);
    assert.equal(panel.split(part).length, 2, `${part} once`);
  }
  assert.match(panel, /<small>\{removed \? "No longer a contact" :/);
});
