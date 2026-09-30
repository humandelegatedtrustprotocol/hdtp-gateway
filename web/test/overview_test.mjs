// The node's overview, held to its source: each tile is one field of GET /api/dashboard
// (internal/internalui/dashboard.go, whose Go test holds those fields to the store), and a certificate
// is the reader's own flags. web/src/overview.ts is shared with PACT Cloud's overview.
import { test } from "node:test";
import assert from "node:assert/strict";
import { certificateView, daysUntil, plural, shown, total } from "../src/overview.ts";
import { addressOf, needsAttention, needsOf, tilesOf } from "../src/views/dashboard_model.ts";

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
  // A pill holds the state's word; how long is the line beside it.
  assert.deepEqual(certificateView({ certified: true, served: true, not_after: "2026-10-09T12:00:00Z", renewal_due: true }, NOW),
    { tone: "warn", text: "renewal due", detail: "10 days left", days: 10, until: "2026-10-09T12:00:00Z" });
  assert.deepEqual(certificateView({ certified: true, served: true, not_after: "2027-01-01T00:00:00Z", renewal_due: false }, NOW),
    { tone: "ok", text: "valid", detail: "93 days left", days: 93, until: "2027-01-01T00:00:00Z" });
  assert.equal(certificateView({ certified: true, served: true, not_after: "2027-01-01T00:00:00Z", renewal_due: false }, NOW).tone, "ok");
  // Thirty days out and the reader says it is not due: it is not due. The page does not know the window.
  assert.equal(certificateView({ certified: true, served: true, not_after: "2026-10-20T12:00:00Z", renewal_due: false }, NOW).tone, "ok");
  assert.equal(certificateView({ certified: true, served: false, renewal_due: false }, NOW).text, "no current certificate");
  // The reader's `served` is the word on it: dated or not, a leaf this host does not hold is not current.
  assert.equal(certificateView({ certified: true, served: false, not_after: "2027-01-01T00:00:00Z", renewal_due: false }, NOW).tone, "bad");
  assert.equal(certificateView({ certified: true, not_after: "2026-09-01T00:00:00Z", renewal_due: false, expired: true }, NOW).text, "certificate expired");
  assert.deepEqual(certificateView({ certified: false, renewal_due: false }, NOW), { tone: "warn", text: "not signed yet", detail: null, days: null, until: null });
  assert.equal(certificateView(null, NOW).tone, "neutral");
  assert.ok(needsAttention(certificateView({ certified: false, renewal_due: false }, NOW)));
  assert.equal(daysUntil("2026-09-30T11:59:59Z", NOW), 0);
});

test("a leaf past its not_after is expired whatever the flags say", () => {
  // The node keeps a lapsed leaf `served` until its hourly retire sweep; peers refuse it already.
  const lapsed = { certified: true, served: true, not_after: "2026-09-29T11:00:00Z", renewal_due: true };
  assert.deepEqual(certificateView(lapsed, NOW), { tone: "bad", text: "certificate expired", detail: null, days: null, until: null });
  assert.equal(certificateView({ ...lapsed, not_after: "2026-09-29T12:00:00Z" }, NOW).text, "certificate expired");
  // A minute before, it is still due.
  assert.equal(certificateView({ ...lapsed, not_after: "2026-09-29T12:01:00Z" }, NOW).text, "renewal due");
  const d = { posture, accounts: [acct({ certificate: lapsed })] };
  assert.equal(needsOf(d, NOW)[0].tone, "bad");
});

test("a failed read is a failure, never a zero", () => {
  assert.equal(total([1, null, 2]), null);
  assert.equal(total([1, 2]), 3);
  assert.equal(total([]), 0);
  assert.equal(shown(null), "—");
  assert.equal(shown(0), "0");
  // A count is said in the reader's own grouping.
  assert.equal(shown(1284), (1284).toLocaleString());
});

test("what needs the owner: people waiting and certificates, each with how long where it matters", () => {
  const due = { certified: true, served: true, not_after: "2026-10-09T12:00:00Z", renewal_due: true };
  const d = { posture, accounts: [acct({ display_name: "Alex", certificate: due }), acct({ id: "b", display_name: "Bea", pending: 2 })] };
  assert.deepEqual(needsOf(d, NOW).map((n) => n.text), ["2 people waiting for Bea", "Alex: renewal due (10 days left)"]);
  assert.equal(plural(1, "request"), "1 request");
  assert.equal(plural(2, "request"), "2 requests");
  // Grouped as the tile under it is: never "12345 people" over a tile that reads "12,345".
  assert.equal(plural(12345, "person", "people"), `${shown(12345)} people`);
  assert.notEqual(shown(12345), "12345");
  const many = { posture, accounts: [acct({ display_name: "Bea", pending: 12345 })] };
  assert.deepEqual(needsOf(many, NOW).map((n) => n.text), [`${shown(12345)} people waiting for Bea`]);
});

test("a card says where its identity is reached after the node's own address, which the strip carries", () => {
  assert.equal(addressOf("https://node.example/alex", "https://node.example"), "/alex");
  assert.equal(addressOf("https://node.example/alex", "https://node.example/"), "/alex");
  // Another host is said whole; so is an endpoint when the node has no public address.
  assert.equal(addressOf("https://tunnel.example/alex", "https://node.example"), "https://tunnel.example/alex");
  assert.equal(addressOf("https://node.example/alex", ""), "https://node.example/alex");
  // A prefix of a longer host is not its address.
  assert.equal(addressOf("https://node.example.org/alex", "https://node.example"), "https://node.example.org/alex");
});
