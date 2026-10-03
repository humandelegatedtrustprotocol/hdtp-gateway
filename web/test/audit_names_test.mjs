// The audit page's ids said as names (web/src/audit_names.ts), run as it ships: `node --test` strips
// its types. BatonDeck runs its verbatim copy of the module under its own suite too
// (portal/test/audit-names.test.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  aboutParts, actorOf, credentialOf, detailLabel, detailParts, eventActorOf, kindSaid, nameBreaks, nameOf, namedIn, resolved, resourceParts, searchText, shortId, webhookHosts,
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
  // One label per fingerprint, whichever part of a row it sits in: the list cannot say whether a
  // fingerprint it does not hold was a contact once.
  assert.equal(nameOf("contact", "sha256:gone", dir).name, "not in your contacts");
  assert.equal(nameOf("caller", "sha256:gone", dir).name, nameOf("contact", "sha256:gone", dir).name);
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
  // The node writes no owner id: that is unrecorded, not withheld — upright, and never "you may not know".
  assert.deepEqual(actorOf({ kind: "owner", id: "" }, dir), { kind: "owner", id: "", name: "an owner", state: "unrecorded" });
  assert.ok(resolved(actorOf({ kind: "owner", id: "" }, dir)));
  assert.ok(!resolved(nameOf("owner", "U-x", { owners: null })));
  assert.ok(!resolved(nameOf("owner", "U-gone", dir)));
  // A contact: by id, or from the locator's caller where the node leaves the id empty.
  assert.equal(actorOf({ kind: "contact", id: "sha256:alina" }, dir).name, "Alina");
  assert.equal(actorOf({ kind: "peer", id: "sha256:alina" }, dir).name, "Alina");
  assert.equal(actorOf({ kind: "contact", id: "", resource: "account:acct-1 caller:sha256:alina tool:x" }, dir).id, "sha256:alina");
  // A guest: a stranger's fingerprint, or nobody at all.
  assert.equal(actorOf({ kind: "guest", id: "sha256:stranger" }, dir).name, "not in your contacts");
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
  // An operator's address is the one fact that says which of BatonDeck's people acted: in full.
  const op = actorOf({ kind: "cli", id: "ops-oncall@batondeck.com", action: "operator.plan_set" }, dir);
  assert.deepEqual(op, { kind: "operator", id: "ops-oncall@batondeck.com", name: "BatonDeck · ops-oncall@batondeck.com", state: "named" });
  assert.equal(actorOf({ kind: "cli", id: "", action: "operator.plan_set" }, dir).name, "a BatonDeck operator");
});

test("a workspace event's actor: an owner, an operator, the system", () => {
  assert.equal(eventActorOf("U-a5a64ea5-1b10-418f-853f-194929a91438", dir).name, "Sumit Agrawal");
  assert.equal(eventActorOf("U-gone", dir).name, "removed owner");
  const op = eventActorOf("operator:ops@batondeck.com", dir);
  assert.equal(op.kind, "operator");
  assert.equal(op.id, "ops@batondeck.com");
  assert.equal(op.name, "BatonDeck · ops@batondeck.com");
  assert.equal(eventActorOf("system", dir).kind, "system");
});

test("a locator's ids become names; the rest stays as written", () => {
  const parts = resourceParts("account:acct-1 contact:sha256:alina tool:send_message", dir);
  assert.equal(parts.length, 3);
  assert.deepEqual(parts[0], { named: { kind: "identity", id: "acct-1", name: "sumit", state: "named" }, label: "account" });
  assert.equal(parts[1].named.name, "Alina");
  // The rest is a labelled value; an opaque id is marked so the page shortens it and offers a copy.
  assert.deepEqual(parts[2], { key: "tool", text: "send_message" });
  assert.deepEqual(resourceParts("invite:inv-72dfec84-1b10-418f", dir), [{ key: "invite", text: "inv-72dfec84-1b10-418f", id: true }]);
  // An address is an address (node.go writes a settings change as url:<its URL>).
  assert.deepEqual(resourceParts("url:https://agent.example.com/hdtp", dir), [{ key: "url", url: "https://agent.example.com/hdtp" }]);
  // What says something already is said in words; a node settings key is a value, not a credential.
  assert.deepEqual(resourceParts("account:none caller:anonymous key:seal", dir), [
    { text: "no identity" }, { text: "an anonymous caller" }, { key: "setting", text: "seal" },
  ]);
  assert.equal(resourceParts("token:key-1 owner:U-gone", dir)[1].named.name, "removed owner");
  assert.deepEqual(resourceParts("", dir), []);
});

test("details: the credential a call came through is provenance, said apart; the ids among the rest are named", () => {
  const said = detailParts(JSON.stringify({ via: "api-key", credential: "api-key:key-1", owner_id: "U-gone", slug: "other" }), dir);
  assert.equal(said.via, "api-key");
  assert.equal(said.credential.name, "laptop agent");
  assert.equal(said.parts[0].named.name, "removed owner");
  assert.deepEqual(said.parts[1], { key: "slug", text: "other" });
  assert.equal(credentialOf("oauth-grant:grant-1", dir).name, "Claude");
  assert.equal(credentialOf("passkey:x", dir), null);
  assert.deepEqual(detailParts("not json", dir).parts, [{ key: "", text: "not json" }]);
  assert.deepEqual(detailParts("", dir), { parts: [], via: "", credential: null });
});

test("details: the workspace's own id is not said on its own chain", () => {
  const said = detailParts(JSON.stringify({ tenant: "t-37deae72-97b2-b525-5adc-aee72945c791", jurisdiction: "eu", kek_version: 2 }), dir);
  assert.deepEqual(said.parts, [{ key: "jurisdiction", text: "eu" }, { key: "kek_version", text: "2" }]);
  assert.equal(detailLabel("kek_version"), "key version");
  assert.equal(detailLabel("account"), "identity");
});

test("details: an event's `id` is what its kind says — an agent key, a webhook — and a list of identities is named", () => {
  // apikey.minted as keys.ts writes it: the id, the key's own name, its scopes and its identities.
  const minted = detailParts(JSON.stringify({ id: "key-1", name: "laptop agent", scopes: ["identity:read", "message:send"], identity_ids: ["acct-1", "acct-9"] }), dir, "apikey.minted");
  assert.deepEqual(minted.parts[0], { key: "key", named: { kind: "key", id: "key-1", name: "laptop agent", state: "named" } });
  // The key's name is said once: by the named id, not again as `name`.
  assert.ok(!minted.parts.some((p) => p.key === "name"));
  assert.deepEqual(minted.parts[1], { key: "scopes", items: ["identity:read", "message:send"] });
  assert.deepEqual(minted.parts[2].items.map((n) => n.name), ["sumit", "removed identity"]);
  assert.equal(detailParts(JSON.stringify({ id: "key-2" }), dir, "apikey.revoked").parts[0].named.state, "revoked");
  // A webhook is named by its address's host, from the answer's own webhook.created.
  const hosts = webhookHosts([
    { kind: "webhook.created", details: JSON.stringify({ id: "wh-1", url: "https://hooks.example.com/hdtp/in", events: [] }) },
    { kind: "webhook.deleted", details: JSON.stringify({ id: "wh-1" }) },
    { kind: "webhook.created", details: "not json" },
  ]);
  assert.deepEqual(hosts, { "wh-1": "hooks.example.com" });
  assert.equal(detailParts(JSON.stringify({ id: "wh-1" }), dir, "webhook.deleted", hosts).parts[0].named.name, "hooks.example.com");
  // One outside the window is an id, shortened with its copy, never a raw uuid said as a name.
  assert.deepEqual(detailParts(JSON.stringify({ id: "wh-2" }), dir, "webhook.deleted", hosts).parts[0], { key: "webhook", text: "wh-2", id: true });
  // webhook.created carries its address: the id beside it would say it twice.
  const created = detailParts(JSON.stringify({ id: "wh-1", url: "https://hooks.example.com/hdtp/in", events: ["message.received"] }), dir, "webhook.created", hosts);
  assert.deepEqual(created.parts.map((p) => p.key), ["url", "events"]);
  assert.equal(created.parts[0].url, "https://hooks.example.com/hdtp/in");
  // Any other event's `id` names nothing this page knows: an id, short, with its copy.
  assert.deepEqual(detailParts(JSON.stringify({ id: "x-1" }), dir, "session.revoked").parts[0], { key: "id", text: "x-1", id: true });
});

test("details: instants, booleans and lists are said as a person reads them", () => {
  const said = detailParts(JSON.stringify({ vacated_until: 1793292354344, previous_accepted_until: 1793292354, required: true, events: ["a", "b"], expires_at: "2026-10-01T00:00:00Z" }), dir);
  assert.deepEqual(said.parts, [
    { key: "vacated_until", at: 1793292354344 },
    { key: "previous_accepted_until", at: 1793292354000 },
    { key: "required", text: "yes" },
    { key: "events", items: ["a", "b"] },
    { key: "expires_at", at: Date.parse("2026-10-01T00:00:00Z") },
  ]);
  // A number that is not an instant stays a number.
  assert.deepEqual(detailParts(JSON.stringify({ sessions: 3 }), dir).parts, [{ key: "sessions", text: "3" }]);
});

test("details: what the row already names is said once", () => {
  // oauth.grant_created carries the app's id and its name.
  const grant = detailParts(JSON.stringify({ client_id: "client-9", client_name: "Claude", via: "portal" }), dir, "oauth.grant_created");
  assert.deepEqual(grant.parts.map((p) => p.key), ["client_id"]);
  // identity.created: the slug beside the identity it names.
  assert.deepEqual(detailParts(JSON.stringify({ account_id: "acct-1", slug: "sumit" }), dir).parts.map((p) => p.key), ["account_id"]);
  // A deleted identity is said by the slug the same row carries.
  const gone = detailParts(JSON.stringify({ account_id: "acct-15", slug: "agent-15" }), dir);
  assert.deepEqual(gone.parts, [{ key: "account_id", named: { kind: "identity", id: "acct-15", name: "agent-15 (removed)", state: "gone" } }]);
});

test("what a row is about leaves out the page's own identity and the actor", () => {
  const actor = actorOf({ kind: "contact", id: "", resource: "account:acct-1 caller:sha256:alina tool:x" }, dir);
  const parts = resourceParts("account:acct-1 caller:sha256:alina tool:x", dir);
  assert.deepEqual(aboutParts(parts, "acct-1", actor), [{ key: "tool", text: "x" }]);
  // Another identity's account is said; so is a contact who is not the actor.
  const other = resourceParts("account:acct-9 contact:sha256:alina", dir);
  assert.equal(aboutParts(other, "acct-1", actorOf({ kind: "owner", id: "" }, dir)).length, 2);
  // An anonymous caller is the actor too, said in words in both places: once is enough.
  const anon = "account:acct-1 caller:anonymous";
  assert.deepEqual(aboutParts(resourceParts(anon, dir), "acct-1", actorOf({ kind: "guest", id: "", resource: anon }, dir)), []);
  // With no identity selected, nothing is taken for "here".
  assert.equal(aboutParts(resourceParts("account:acct-1", dir), "", actorOf({ kind: "system", id: "" }, dir)).length, 1);
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

test("a long id is shortened to its head and tail; a fingerprint loses its scheme; a short one is not", () => {
  assert.equal(shortId("U-a5a64ea5-1b10-418f-853f-194929a91438"), "U-a5a64e…a91438");
  assert.equal(shortId("sha256:QTWqncG4QqZT3qhGkD3blb-4xaEMUEp_oW4QvDHR_fA"), "QTWqncG4…DHR_fA");
  assert.equal(shortId("sha256:short"), "short");
  assert.equal(shortId("key-1"), "key-1");
});

test("a locator's `why:` is one value, the rest of the locator, as every emitter writes it last", () => {
  // internal/public/decide.go, identity_state_unreadable: an error's message, spaces and all.
  assert.deepEqual(resourceParts("account:acct-1 why:store: read identity: sql: database is locked (5) (SQLITE_BUSY)", dir), [
    { named: { kind: "identity", id: "acct-1", name: "sumit", state: "named" }, label: "account" },
    { key: "why", text: "store: read identity: sql: database is locked (5) (SQLITE_BUSY)" },
  ]);
  // decide.go, contact_new_address: a contact, an address, then why.
  assert.deepEqual(resourceParts("account:acct-1 contact:sha256:alina endpoint:https://alina.example/hdtp why:returned after removal", dir).slice(1), [
    { named: { kind: "contact", id: "sha256:alina", name: "Alina", state: "named" }, label: "contact" },
    { key: "endpoint", url: "https://alina.example/hdtp" },
    { key: "why", text: "returned after removal" },
  ]);
  // tools.go why(nil) and send.go whyFailed(nil).
  assert.deepEqual(resourceParts("caller:sha256:alina why:unknown", dir)[1], { key: "why", text: "unknown" });
  assert.equal(detailLabel("why"), "reason");
  // A `why` inside another value is not the token.
  assert.deepEqual(resourceParts("tool:somewhy:x", dir), [{ key: "tool", text: "somewhy:x" }]);
});

test("a locator's `key:` is a leaf key by its fingerprint, and otherwise the node's setting", () => {
  // The cloud's account_leaf_key_retired writes `account:<id> key:<kid>`, the kid being the core's fingerprint.
  const kid = "sha256:QTWqncG4QqZT3qhGkD3blb-4xaEMUEp_oW4QvDHR_fA";
  assert.deepEqual(resourceParts(`account:acct-1 key:${kid}`, dir)[1], { key: "leaf key", text: kid, id: true });
  // The node's settings_save: `key:tunnel value:<it>`, `key:preset:<name> perms:<list>`.
  assert.deepEqual(resourceParts("key:tunnel value:https://t.example", dir), [{ key: "setting", text: "tunnel" }, { key: "value", url: "https://t.example" }]);
  assert.deepEqual(resourceParts("key:preset:work perms:a,b", dir)[0], { key: "setting", text: "preset:work" });
});

test("details: an id the directory cannot name is short with a copy, never a whole uuid; a short one is text", () => {
  // Real emitters: admin/routes.ts (operator.note_added), billing/promo.ts, hostnames/saas.ts, teams/invitations.ts.
  for (const [key, v] of [["note_id", "on_d6089d6c-1295-ad5f-b7d7-ae771c0ad821"], ["promo_id", "pc_51b6076e-8f0c-4c1e-9a3b-7d2e1f408359"],
    ["saas_id", "0f8d3b2a-6c1e-4f7a-9b5d-2e4c6a8f1b3d"], ["invitation_id", "invitation_01J8ZK4Q7M2X9V3B6N5C1D0E8F"]]) {
    assert.deepEqual(detailParts(JSON.stringify({ [key]: v }), dir).parts, [{ key, text: v, id: true }], key);
  }
  // The confirmation an owner-MCP act was approved under (api/v1/record.ts provenanceOf).
  assert.equal(detailParts(JSON.stringify({ confirmation: "Zm9vYmFyYmF6cXV4cXV1eGNvcmdl" }), dir).parts[0].id, true);
  // billing.checkout_opened's plan: its id is its name.
  assert.deepEqual(detailParts(JSON.stringify({ plan_id: "team" }), dir).parts, [{ key: "plan_id", text: "team" }]);
  // The ids the directory names stay named.
  assert.equal(detailParts(JSON.stringify({ owner_id: "U-a5a64ea5-1b10-418f-853f-194929a91438" }), dir).parts[0].named.name, "Sumit Agrawal");
});

test("a name the page made up says its kind; only a chosen name takes the quiet kind note", () => {
  assert.equal(kindSaid(nameOf("owner", "U-a5a64ea5-1b10-418f-853f-194929a91438", dir)), false);
  assert.equal(kindSaid(nameOf("key", "key-2", dir)), false); // revoked, still its chosen name
  // "deleted key", "not in your contacts", "a key" (withheld), "an owner" (unrecorded): the kind is in the name.
  assert.equal(kindSaid(nameOf("key", "key-gone", dir)), true);
  assert.equal(kindSaid(nameOf("contact", "sha256:gone", dir)), true);
  assert.equal(kindSaid(nameOf("key", "key-1", { ...dir, keys: null })), true);
  assert.equal(kindSaid(nameOf("owner", "", dir)), true);
  assert.equal(kindSaid(actorOf({ kind: "system", id: "expiry" }, dir)), true);
});

test("a name breaks between words, after an address's @, after a handle's underscores; only a piece too long for a column anywhere", () => {
  const pieces = (n) => nameBreaks(n).map((run) => run.map((p) => p.text));
  // The owner's own example: 'priya.raman@shailka.c' / 'om' was a break inside the domain.
  assert.deepEqual(pieces("priya.raman@shailka.com"), [["priya.raman@", "shailka.com"]]);
  assert.deepEqual(pieces("deepwiki_research_assistant_eu_west_production"), [["deepwiki_", "research_", "assistant_", "eu_", "west_", "production"]]);
  assert.deepEqual(pieces("Research Agent (EU)"), [["Research"], [" "], ["Agent"], [" "], ["(EU)"]]);
  assert.deepEqual(pieces("Dr. Konstantin"), [["Dr."], [" "], ["Konstantin"]]);
  // Every piece put back together is the name, whatever it is.
  for (const n of ["priya.raman@shailka.com", "a  b", "x_", "@", "Maximiliano Alessandro Bartholomew-Featherstonehaugh"]) {
    assert.equal(nameBreaks(n).flat().map((p) => p.text).join(""), n);
  }
  assert.ok(nameBreaks("Maximiliano Bartholomew-Featherstonehaugh").flat().every((p) => !p.long));
  const long = nameBreaks("Wolfeschlegelsteinhausenbergerdorff").flat();
  assert.deepEqual(long.map((p) => p.long), [true]);
});
