// The audit page's ids said as names (web/src/audit_names.ts), run as it ships: `node --test` strips
// its types. PACT Cloud runs its verbatim copy of the module under its own suite too
// (portal/test/audit-names.test.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  actorOf, credentialOf, detailParts, eventActorOf, nameOf, namedIn, resourceParts, searchText, shortId,
} from "../src/audit_names.ts";

const dir = {
  owners: { "U-a5a64ea5-1b10-418f-853f-194929a91438": "Sumit Agrawal", "U-noname": "" },
  identities: { "acct-1": "sumit" },
  contacts: { "sha256:alina": "Alina", "sha256:blank": "" },
  keys: { "key-1": { name: "laptop agent" }, "key-2": { name: "old agent", revoked: true } },
  grants: { "grant-1": { name: "Claude" }, "client-9": { name: "Claude" } },
  passkeys: { "pk-1": "MacBook" },
};

test("each kind of id is said by its name, and keeps its id", () => {
  assert.deepEqual(nameOf("owner", "U-a5a64ea5-1b10-418f-853f-194929a91438", dir),
    { kind: "owner", id: "U-a5a64ea5-1b10-418f-853f-194929a91438", name: "Sumit Agrawal", state: "named" });
  assert.equal(nameOf("identity", "acct-1", dir).name, "sumit");
  assert.equal(nameOf("contact", "sha256:alina", dir).name, "Alina");
  assert.equal(nameOf("key", "key-1", dir).name, "laptop agent");
  assert.equal(nameOf("grant", "grant-1", dir).name, "Claude");
  assert.equal(nameOf("passkey", "pk-1", dir).name, "MacBook");
});

test("an id its list no longer holds is said as removed, with the id; never a bare id and never nothing", () => {
  const gone = nameOf("owner", "U-gone", dir);
  assert.deepEqual(gone, { kind: "owner", id: "U-gone", name: "removed owner", state: "gone" });
  assert.equal(nameOf("key", "key-9", dir).name, "deleted key");
  assert.equal(nameOf("identity", "acct-9", dir).name, "removed identity");
  assert.equal(nameOf("contact", "sha256:gone", dir).name, "former contact");
  assert.equal(nameOf("caller", "sha256:stranger", dir).name, "stranger");
  assert.equal(nameOf("grant", "grant-9", dir).name, "removed app");
  assert.equal(nameOf("passkey", "pk-9", dir).name, "removed passkey");
});

test("a revoked key is named and marked revoked", () => {
  assert.deepEqual(nameOf("key", "key-2", dir), { kind: "key", id: "key-2", name: "old agent", state: "revoked" });
});

test("a list the caller may not read is withheld, never 'removed'", () => {
  const withheld = { owners: null, contacts: null };
  assert.deepEqual(nameOf("owner", "U-x", withheld), { kind: "owner", id: "U-x", name: "an owner", state: "withheld" });
  assert.equal(nameOf("contact", "sha256:x", withheld).name, "a contact");
  // A kind this product has no list for (the node has no connected apps) is withheld too.
  assert.equal(nameOf("grant", "g", {}).state, "withheld");
});

test("a name that is empty is said as what it is, not as the id", () => {
  assert.equal(nameOf("owner", "U-noname", dir).name, "an owner");
  assert.equal(nameOf("contact", "sha256:blank", dir).name, "unnamed contact");
});

test("each actor kind", () => {
  // An owner, by id (the cloud); by kind alone (the node records no id).
  assert.equal(actorOf({ kind: "owner", id: "U-a5a64ea5-1b10-418f-853f-194929a91438" }, dir).name, "Sumit Agrawal");
  assert.deepEqual(actorOf({ kind: "owner", id: "" }, dir), { kind: "owner", id: "", name: "an owner", state: "withheld" });
  // A contact: by id, or from the locator's caller where the node leaves the id empty.
  assert.equal(actorOf({ kind: "contact", id: "sha256:alina" }, dir).name, "Alina");
  assert.equal(actorOf({ kind: "peer", id: "sha256:alina" }, dir).name, "Alina");
  assert.equal(actorOf({ kind: "contact", id: "", resource: "account:acct-1 caller:sha256:alina tool:x" }, dir).id, "sha256:alina");
  // A guest: a stranger's fingerprint, or nobody at all.
  assert.equal(actorOf({ kind: "guest", id: "sha256:stranger" }, dir).name, "stranger");
  assert.equal(actorOf({ kind: "guest", id: "anonymous" }, dir).name, "an anonymous caller");
  assert.equal(actorOf({ kind: "guest", id: "", resource: "caller:anonymous" }, dir).name, "an anonymous caller");
  // The owner's agent, by token kind.
  assert.equal(actorOf({ kind: "token", id: "" }, dir).name, "an agent");
  // The system, and the part of it that acted.
  assert.equal(actorOf({ kind: "system", id: "" }, dir).name, "the system");
  assert.equal(actorOf({ kind: "system", id: "expiry" }, dir).name, "the system (expiry)");
  assert.equal(actorOf({ kind: "", id: "" }, dir).name, "the system");
  // The command line, and an operator stored under the node's `cli` kind — told apart by the action.
  assert.equal(actorOf({ kind: "cli", id: "" }, dir).name, "the command line");
  const op = actorOf({ kind: "cli", id: "ops@pact-cloud.com", action: "operator.plan_set" }, dir);
  assert.deepEqual(op, { kind: "operator", id: "ops@pact-cloud.com", name: "PACT Cloud operator", state: "named" });
});

test("a workspace event's actor: an owner, an operator, the system", () => {
  assert.equal(eventActorOf("U-a5a64ea5-1b10-418f-853f-194929a91438", dir).name, "Sumit Agrawal");
  assert.equal(eventActorOf("U-gone", dir).name, "removed owner");
  const op = eventActorOf("operator:ops@pact-cloud.com", dir);
  assert.equal(op.kind, "operator");
  assert.equal(op.id, "operator:ops@pact-cloud.com");
  assert.equal(eventActorOf("system", dir).kind, "system");
});

test("a locator's ids become names; the rest stays as written", () => {
  const parts = resourceParts("account:acct-1 contact:sha256:alina tool:send_message", dir);
  assert.equal(parts.length, 3);
  assert.deepEqual(parts[0], { named: { kind: "identity", id: "acct-1", name: "sumit", state: "named" }, label: "account" });
  assert.equal(parts[1].named.name, "Alina");
  assert.deepEqual(parts[2], { text: "tool:send_message" });
  // What says something already is left alone; so is a node settings key, which is not a credential.
  assert.deepEqual(resourceParts("account:none caller:anonymous key:seal", dir), [
    { text: "account:none" }, { text: "caller:anonymous" }, { text: "key:seal" },
  ]);
  assert.equal(resourceParts("token:key-1 owner:U-gone", dir)[1].named.name, "removed owner");
  assert.deepEqual(resourceParts("", dir), []);
});

test("details: the credential a call came through, and the ids among the rest", () => {
  const parts = detailParts(JSON.stringify({ via: "api-key", credential: "api-key:key-1", owner_id: "U-gone", slug: "sumit" }), dir);
  assert.deepEqual(parts[0], { key: "via", text: "api-key" });
  assert.equal(parts[1].named.name, "laptop agent");
  assert.equal(parts[2].named.name, "removed owner");
  assert.deepEqual(parts[3], { key: "slug", text: "sumit" });
  assert.equal(credentialOf("oauth-grant:grant-1", dir).name, "Claude");
  assert.equal(credentialOf("passkey:x", dir), null);
  assert.deepEqual(detailParts("not json", dir), [{ key: "", text: "not json" }]);
  assert.deepEqual(detailParts("", dir), []);
});

test("the search matches a row by a name it resolves to AND by the raw id", () => {
  const actor = actorOf({ kind: "owner", id: "U-a5a64ea5-1b10-418f-853f-194929a91438" }, dir);
  const parts = resourceParts("account:acct-1 contact:sha256:alina", dir);
  const hay = searchText("7 owner U-a5a64ea5-1b10-418f-853f-194929a91438 contact_approve account:acct-1 contact:sha256:alina ok", [actor, ...namedIn(parts)]);
  for (const needle of ["sumit agrawal", "alina", "u-a5a64ea5", "sha256:alina", "contact_approve"]) {
    assert.ok(hay.includes(needle), needle);
  }
  assert.ok(!hay.includes("bharat"));
});

test("a long id is shortened for the line under a name; a short one is not", () => {
  assert.equal(shortId("U-a5a64ea5-1b10-418f-853f-194929a91438"), "U-a5a64ea5-1b1…a91438");
  assert.equal(shortId("key-1"), "key-1");
});
