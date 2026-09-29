// The node's overview, held to its source: each tile is one field of GET /api/dashboard
// (internal/internalui/dashboard.go, whose Go test holds those fields to the store), and a certificate
// is the reader's own flags. web/src/overview.ts is shared with PACT Cloud's overview.
import { test } from "node:test";
import assert from "node:assert/strict";
import { certificateView, daysUntil, plural, shown, total } from "../src/overview.ts";
import { firstWaiting, needsAttention, tilesOf } from "../src/views/dashboard_model.ts";

const NOW = Date.parse("2026-09-29T12:00:00Z");
const posture = { mode: "direct", seal: "optional", client_cert: "preferred", tunnel: "", public_url: "https://node.example" };
const acct = (over) => ({ id: "a", slug: "a", display_name: "Alex", fingerprint: "sha256:a", contacts: 0, pending: 0, certificate: null, ...over });

test("identities is the number of identities the answer lists", () => {
  assert.equal(tilesOf({ posture, accounts: [acct({}), acct({ id: "b" })] }, NOW).identities, 2);
  assert.equal(tilesOf({ posture, accounts: null }, NOW).identities, 0);
});

test("contacts is the sum of each identity's `contacts`", () => {
  assert.equal(tilesOf({ posture, accounts: [acct({ contacts: 2 }), acct({ id: "b", contacts: 5 })] }, NOW).contacts, 7);
});

test("waiting is the sum of each identity's `pending`", () => {
  assert.equal(tilesOf({ posture, accounts: [acct({ pending: 1 }), acct({ id: "b", pending: 2 })] }, NOW).waiting, 3);
});

test("certificates counts the identities whose certificate is not current, by the reader's flags", () => {
  const due = { certified: true, served: true, not_after: "2026-10-10T00:00:00Z", renewal_due: true };
  const fine = { certified: true, served: true, not_after: "2027-03-01T00:00:00Z", renewal_due: false };
  const none = { certified: true, served: false, renewal_due: false };
  const unsigned = { certified: false, served: false, renewal_due: false };
  const d = { posture, accounts: [acct({ certificate: due }), acct({ certificate: fine }), acct({ certificate: none }), acct({ certificate: unsigned }), acct({ certificate: null })] };
  // due, none and unsigned; not the current one, and not the one no reader answered.
  assert.equal(tilesOf(d, NOW).attention, 3);
});

test("a certificate is said from its flags; only the days are derived", () => {
  assert.deepEqual(certificateView({ certified: true, served: true, not_after: "2026-10-09T12:00:00Z", renewal_due: true }, NOW),
    { tone: "warn", text: "renewal due · 10 days left", days: 10, until: "2026-10-09T12:00:00Z" });
  assert.equal(certificateView({ certified: true, served: true, not_after: "2027-01-01T00:00:00Z", renewal_due: false }, NOW).tone, "ok");
  // Thirty days out and the reader says it is not due: it is not due. The page does not know the window.
  assert.equal(certificateView({ certified: true, served: true, not_after: "2026-10-20T12:00:00Z", renewal_due: false }, NOW).tone, "ok");
  assert.equal(certificateView({ certified: true, served: false, renewal_due: false }, NOW).text, "no current certificate");
  // The reader's `served` is the word on it: dated or not, a leaf this host does not hold is not current.
  assert.equal(certificateView({ certified: true, served: false, not_after: "2027-01-01T00:00:00Z", renewal_due: false }, NOW).tone, "bad");
  assert.equal(certificateView({ certified: true, not_after: "2026-09-01T00:00:00Z", renewal_due: false, expired: true }, NOW).text, "certificate expired");
  assert.equal(certificateView({ certified: false, renewal_due: false }, NOW).tone, "warn");
  assert.equal(certificateView(null, NOW).tone, "neutral");
  assert.ok(needsAttention(certificateView({ certified: false, renewal_due: false }, NOW)));
  assert.equal(daysUntil("2026-09-30T11:59:59Z", NOW), 0);
});

test("a failed read is a failure, never a zero", () => {
  assert.equal(total([1, null, 2]), null);
  assert.equal(total([1, 2]), 3);
  assert.equal(total([]), 0);
  assert.equal(shown(null), "—");
  assert.equal(shown(0), "0");
});

test("the header's review opens the first identity with somebody waiting", () => {
  assert.equal(firstWaiting({ posture, accounts: [acct({}), acct({ id: "b", pending: 2 })] })?.id, "b");
  assert.equal(firstWaiting({ posture, accounts: [acct({})] }), null);
  assert.equal(plural(1, "request"), "1 request");
  assert.equal(plural(2, "request"), "2 requests");
});
