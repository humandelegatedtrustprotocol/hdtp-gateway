// The audit trail's ids, said as the names a person knows them by.
//
// A row records WHO acted and WHAT it touched by id — an owner's id, a key's id, a contact's
// fingerprint, an identity's account id — because the trail has to stay verifiable: the id is
// what the row's hash covers and what an investigation quotes. An id is not what a person reads,
// though (the owner, 2026-09-29: "U-a5a64ea5-… is completely not a good user experience"). So the
// audit answer carries a directory beside its rows (`names`), and this module turns each id into
// a name and keeps the id one step away: the view shows the name, and the id in its tooltip and
// its secondary line, copyable.
//
// ONE module for both portals: the node's (web/src) and PACT Cloud's (portal/src, copied verbatim
// by the cloud's gateway/scripts/harvest.sh). Pure — no imports — so both portals' tests run it
// as it is, the node's with `node --test` and the cloud's with vitest.
//
// Three states an id can be in, and they are never confused:
//   - named: the directory has it;
//   - gone: the directory for its kind was answered and does not have it — the owner was removed,
//     the key deleted, the contact is no longer one;
//   - withheld: the directory for its kind was not answered (`null`), because the caller may not
//     read that list. Saying "removed" there would be a claim the page cannot make.

/** One credential's entry: its name, and whether it was revoked (a revoked key still names its rows). */
export type Entry = { name: string; revoked?: boolean };

/**
 * The names an audit answer carries, one map per kind of id, keyed by the id as the rows write it.
 * A kind the caller may not read is `null`; a kind this product does not have is absent.
 */
export type Directory = {
  /** Owner id → display name (or email where they gave no name). Only the workspace's or node's current owners. */
  owners?: Record<string, string> | null;
  /** Account id → the identity's name. */
  identities?: Record<string, string> | null;
  /** Fingerprint → the contact's name (the owner's petname first). Only fingerprints the rows mention. */
  contacts?: Record<string, string> | null;
  /** Key or token id → its name. Revoked ones are kept: their rows still name them. */
  keys?: Record<string, Entry> | null;
  /** Connected app (OAuth grant) id, and the app's client id → the app's name. */
  grants?: Record<string, Entry> | null;
  /** Passkey id → its tag. */
  passkeys?: Record<string, string> | null;
};

export type Kind = "owner" | "identity" | "contact" | "caller" | "key" | "grant" | "passkey" | "operator" | "system" | "agent" | "cli" | "anonymous";

/** One id, said. `id` is the raw value the row carries ("" when the row carries none). */
export type Named = {
  kind: Kind;
  id: string;
  name: string;
  state: "named" | "revoked" | "gone" | "withheld";
};

/** What each kind is called when the page cannot say which one. */
const SOME: Record<Kind, string> = {
  owner: "an owner", identity: "an identity", contact: "a contact", caller: "a caller",
  key: "a key", grant: "a connected app", passkey: "a passkey", operator: "an operator",
  system: "the system", agent: "an agent", cli: "the command line", anonymous: "an anonymous caller",
};

/** What each kind is called when the list was read and no longer holds it. */
const GONE: Record<Kind, string> = {
  owner: "removed owner", identity: "removed identity", contact: "former contact", caller: "stranger",
  key: "deleted key", grant: "removed app", passkey: "removed passkey", operator: "an operator",
  system: "the system", agent: "an agent", cli: "the command line", anonymous: "an anonymous caller",
};

/** The directory map that answers a kind, or undefined when the product has none. */
function mapOf(kind: Kind, dir: Directory): Record<string, string | Entry> | null | undefined {
  switch (kind) {
    case "owner": return dir.owners;
    case "identity": return dir.identities;
    case "contact": case "caller": return dir.contacts;
    case "key": return dir.keys;
    case "grant": return dir.grants;
    case "passkey": return dir.passkeys;
    default: return undefined;
  }
}

/** One id of a known kind, looked up. */
export function nameOf(kind: Kind, id: string, dir: Directory): Named {
  if (!id) return { kind, id, name: SOME[kind], state: "withheld" };
  const map = mapOf(kind, dir);
  if (!map) return { kind, id, name: SOME[kind], state: "withheld" };
  if (!Object.prototype.hasOwnProperty.call(map, id)) return { kind, id, name: GONE[kind], state: "gone" };
  const hit = map[id];
  if (typeof hit === "string") {
    return { kind, id, name: hit.trim() || (kind === "contact" || kind === "caller" ? "unnamed contact" : SOME[kind]), state: "named" };
  }
  return { kind, id, name: hit.name.trim() || SOME[kind], state: hit.revoked ? "revoked" : "named" };
}

/**
 * The actor of a chain row: its kind, its id, and — where the row carries no id but its locator
 * names the caller (the node writes `caller:<fpr>` and an empty actor id) — the caller from there.
 *
 * `action` decides one case: the platform stores an operator as the node's `cli` kind (the Go
 * store's CHECK has no `operator`), so a row is an operator's by its `operator.` action, never by
 * its kind (gateway/src/audit/chain.ts says why).
 */
export function actorOf(row: { kind: string; id: string; action?: string; resource?: string }, dir: Directory): Named {
  const kind = row.kind || "system";
  const id = row.id;
  if (row.action?.startsWith("operator.")) return { kind: "operator", id, name: operatorName(id), state: "named" };
  switch (kind) {
    case "owner": return nameOf("owner", id, dir);
    case "contact": case "peer": return nameOf("contact", id || callerIn(row.resource ?? ""), dir);
    case "guest": {
      const fpr = id || callerIn(row.resource ?? "");
      // Nobody is not an id: there is nothing to verify or copy.
      if (!fpr || fpr === "anonymous") return { kind: "anonymous", id: "", name: SOME.anonymous, state: "named" };
      return nameOf("caller", fpr, dir);
    }
    // The owner's agent, through a bearer token. The node records the kind and not which token.
    case "token": return id ? nameOf("key", id, dir) : { kind: "agent", id, name: SOME.agent, state: "named" };
    case "cli": return { kind: "cli", id, name: "the command line", state: "named" };
    case "operator": return { kind: "operator", id, name: operatorName(id), state: "named" };
    // A system row's id names the part of the system that wrote it, which its name says.
    default: return { kind: "system", id: "", name: systemName(id), state: "named" };
  }
}

/**
 * The actor of a workspace event, which is one string: an owner id, `operator:<email>`, or
 * `system` (gateway/src/audit/org-events.ts).
 */
export function eventActorOf(actor: string, dir: Directory): Named {
  if (actor.startsWith("operator:")) {
    const email = actor.slice("operator:".length);
    return { kind: "operator", id: actor, name: operatorName(email), state: "named" };
  }
  if (actor === "system" || actor === "") return { kind: "system", id: "", name: "the system", state: "named" };
  return nameOf("owner", actor, dir);
}

/** An operator is one of PACT Cloud's own people: said so, with their address as the id. */
function operatorName(email: string): string {
  return email ? "PACT Cloud operator" : SOME.operator;
}

/** A system row's id names the part of the system that wrote it (`expiry`, `move`, `repair`…). */
function systemName(id: string): string {
  return id && id !== "system" ? `the system (${id.replace(/_/g, " ")})` : "the system";
}

/** The caller a locator names (`… caller:<fpr> …`), or "". */
function callerIn(resource: string): string {
  for (const t of resource.split(/\s+/)) if (t.startsWith("caller:")) return t.slice("caller:".length);
  return "";
}

/** A locator's parts: each `kind:id` that names something with a name, looked up; the rest as written. */
export type Part = { text: string } | { named: Named; label: string };

/** Locator prefixes whose value is an id this directory can name, and the kind each one is. */
const LOCATORS: Record<string, Kind> = {
  account: "identity", contact: "contact", peer: "contact", caller: "caller",
  owner: "owner", token: "key", passkey: "passkey",
};

/**
 * A row's `resource` (`account:<id> contact:<fpr> tool:send_message`), as parts: the ids a person
 * would not recognise become names; the rest stay as they are written. `account:none` and
 * `caller:anonymous` say something already and are left alone.
 */
export function resourceParts(resource: string, dir: Directory): Part[] {
  if (!resource) return [];
  const out: Part[] = [];
  for (const token of resource.split(/\s+/).filter(Boolean)) {
    const at = token.indexOf(":");
    const prefix = at > 0 ? token.slice(0, at) : "";
    const value = at > 0 ? token.slice(at + 1) : "";
    const kind = LOCATORS[prefix];
    if (!kind || !value || value === "none" || value === "anonymous") {
      out.push({ text: token });
      continue;
    }
    out.push({ named: nameOf(kind, value, dir), label: prefix });
  }
  return out;
}

/** A details bag's members that are ids, and the kind each is. `credential` is `<kind>:<id>`. */
const DETAIL_IDS: Record<string, Kind> = {
  owner_id: "owner", account_id: "identity", grant_id: "grant", client_id: "grant", key_id: "key",
};

/** One member of a details bag: a name where it is an id, the value as text where not. */
export type Detail = { key: string; text: string } | { key: string; named: Named };

/**
 * A details bag (JSON text written by the platform from an allow-list), as members. The door and
 * the credential that carried a call (`via`, `credential`: `api-key:<id>` or `oauth-grant:<id>`)
 * name the key or the app; the ids among the rest are named too. Rendered as text, never markup.
 */
export function detailParts(json: string, dir: Directory): Detail[] {
  if (!json) return [];
  let o: unknown;
  try {
    o = JSON.parse(json);
  } catch {
    return [{ key: "", text: json }];
  }
  if (o === null || typeof o !== "object" || Array.isArray(o)) return [{ key: "", text: json }];
  const out: Detail[] = [];
  for (const [key, v] of Object.entries(o as Record<string, unknown>)) {
    if (v === null || v === undefined || v === "") continue;
    const value = typeof v === "string" ? v : String(v);
    if (key === "credential" && typeof v === "string") {
      const cred = credentialOf(v, dir);
      out.push(cred ? { key, named: cred } : { key, text: value });
      continue;
    }
    const kind = DETAIL_IDS[key];
    out.push(kind && typeof v === "string" ? { key, named: nameOf(kind, v, dir) } : { key, text: value });
  }
  return out;
}

/** `api-key:<id>` or `oauth-grant:<id>`, the credential a call came through; null for anything else. */
export function credentialOf(credential: string, dir: Directory): Named | null {
  if (credential.startsWith("api-key:")) return nameOf("key", credential.slice("api-key:".length), dir);
  if (credential.startsWith("oauth-grant:")) return nameOf("grant", credential.slice("oauth-grant:".length), dir);
  return null;
}

/**
 * What the search box matches for a row: its own text (ids, action, outcome) AND every name it
 * resolves to, so a person can find a row by who it was about or by the id an investigation quotes.
 */
export function searchText(raw: string, named: Array<Named | null | undefined>): string {
  const names = named.filter((n): n is Named => Boolean(n)).map((n) => n.name);
  return `${raw} ${names.join(" ")}`.toLowerCase();
}

/** Every Named among a row's parts: the actor, the locator's, the details'. */
export function namedIn(parts: Array<Part | Detail>): Named[] {
  const out: Named[] = [];
  for (const p of parts) if ("named" in p) out.push(p.named);
  return out;
}

/** An id short enough for a table's secondary line; the whole of it is in the tooltip and the copy. */
export function shortId(id: string): string {
  if (id.length <= 22) return id;
  return `${id.slice(0, 14)}…${id.slice(-6)}`;
}
