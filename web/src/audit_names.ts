// The audit trail's ids, said as the names a person knows them by.
//
// A row records WHO acted and WHAT it touched by id — an owner's id, a key's id, a contact's
// fingerprint, an identity's account id — because the trail has to stay verifiable: the id is
// what the row's hash covers and what an investigation quotes. An id is not what a person reads,
// though (the owner, 2026-09-29: "U-a5a64ea5-… is completely not a good user experience"). So the
// audit answer carries a directory beside its rows (`names`), and this module turns each id into
// a name. The view shows the name alone, with the id in its tooltip and a copy button; only a
// name the page could not resolve shows its id, short, because there the id is the one handle.
//
// ONE module for both portals: the node's (web/src) and PACT Cloud's (portal/src, copied verbatim
// from the node commit its portal/HARVESTED file records, held to it by the cloud's
// gateway/scripts/check-harvested.mjs). Pure — no imports — so both portals' tests run it as it
// is, the node's with `node --test` and the cloud's with vitest.
//
// Four states an id can be in, and they are never confused:
//   - named: the directory has it;
//   - gone: the directory for its kind was answered and does not have it — the owner was removed,
//     the key deleted, the contact is not one (any longer, or ever: the page cannot tell which);
//   - withheld: the directory for its kind was not answered (`null`), because the caller may not
//     read that list. Saying "removed" there would be a claim the page cannot make;
//   - unrecorded: the row carries no id at all. The node writes none for an owner (its audit sink
//     records the kind and not which owner), so "an owner" there is all the row says — which is
//     not the same as "you may not read which owner", and is not shown as if it were.

/** One credential's entry: its name, and whether it was revoked (a revoked key still names its rows). */
export type Entry = { name: string; revoked?: boolean };

/**
 * The names an audit answer carries, one map per kind of id, keyed by the id as the rows write it.
 * A kind the caller may not read is `null`; a kind this product does not have is absent.
 */
export type Directory = {
  /**
   * Owner id → the name they go by. Only current owners. The node answers display names; the cloud,
   * for one who gave none, their email to a workspace admin and "a member" to anyone else.
   */
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

export type Kind = "owner" | "identity" | "contact" | "caller" | "key" | "grant" | "passkey" | "webhook" | "operator" | "system" | "agent" | "cli" | "anonymous";

/** One id, said. `id` is the raw value the row carries ("" when the row carries none). */
export type Named = {
  kind: Kind;
  id: string;
  name: string;
  state: "named" | "revoked" | "gone" | "withheld" | "unrecorded";
};

/** What each kind is called when the page cannot say which one. */
const SOME: Record<Kind, string> = {
  owner: "an owner", identity: "an identity", contact: "a contact", caller: "a caller",
  key: "a key", grant: "a connected app", passkey: "a passkey", webhook: "a webhook", operator: "a PACT Cloud operator",
  system: "the system", agent: "an agent", cli: "the command line", anonymous: "an anonymous caller",
};

/**
 * What each kind is called when the list was read and does not hold it. A fingerprint the contact
 * list does not hold reads the same whichever part of a row it sits in: whether it was a contact
 * once is not something the list can say.
 */
const GONE: Record<Kind, string> = {
  owner: "removed owner", identity: "removed identity", contact: "not in your contacts", caller: "not in your contacts",
  key: "deleted key", grant: "removed app", passkey: "removed passkey", webhook: "a webhook", operator: SOME.operator,
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
  if (!id) return { kind, id, name: SOME[kind], state: "unrecorded" };
  const map = mapOf(kind, dir);
  if (!map) return { kind, id, name: SOME[kind], state: "withheld" };
  if (!Object.prototype.hasOwnProperty.call(map, id)) return { kind, id, name: GONE[kind], state: "gone" };
  const hit = map[id];
  if (typeof hit === "string") {
    return { kind, id, name: hit.trim() || (kind === "contact" || kind === "caller" ? "unnamed contact" : SOME[kind]), state: "named" };
  }
  return { kind, id, name: hit.name.trim() || SOME[kind], state: hit.revoked ? "revoked" : "named" };
}

/** Whether a name says who it is, so its id need not be shown beside it. */
export function resolved(n: Named): boolean {
  return n.state === "named" || n.state === "revoked" || n.state === "unrecorded";
}

/**
 * Whether a name says its own kind already, so a quiet "owner" or "key" after it would say it twice.
 * Every name the page makes up says it ("deleted key", "removed owner", "not in your contacts", "an
 * owner"), and so do the kinds whose names are the kind ("the system", "PACT Cloud · …"); only a
 * name somebody chose ("Priya", "CI runner") leaves the kind unsaid.
 */
export function kindSaid(n: Named): boolean {
  if (n.state !== "named" && n.state !== "revoked") return true;
  return ["system", "cli", "anonymous", "operator", "agent"].includes(n.kind);
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
  if (row.action?.startsWith("operator.")) return operatorOf(id);
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
    case "cli": return { kind: "cli", id, name: SOME.cli, state: "named" };
    case "operator": return operatorOf(id);
    // A system row's id names the part of the system that wrote it, which its name says.
    default: return { kind: "system", id: "", name: systemName(id), state: "named" };
  }
}

/**
 * The actor of a workspace event, which is one string: an owner id, `operator:<email>`, or
 * `system` (gateway/src/audit/org-events.ts).
 */
export function eventActorOf(actor: string, dir: Directory): Named {
  if (actor.startsWith("operator:")) return operatorOf(actor);
  if (actor === "system" || actor === "") return { kind: "system", id: "", name: "the system", state: "named" };
  return nameOf("owner", actor, dir);
}

/**
 * An operator is one of PACT Cloud's own people, and their address is the one fact that says which
 * (Terms §14 is about exactly that), so it is said in full, never shortened: "PACT Cloud ·
 * ops@pact-cloud.com". The id is the address, without the `operator:` the event writes.
 */
function operatorOf(raw: string): Named {
  const email = raw.startsWith("operator:") ? raw.slice("operator:".length) : raw;
  return { kind: "operator", id: email, name: email ? `PACT Cloud · ${email}` : SOME.operator, state: "named" };
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

/**
 * A locator's parts: each `kind:id` that names something with a name, looked up; the rest as a
 * labelled value (`tool` send_message, `invite` inv-7f3a…) or, where a token says something
 * already, as words.
 */
export type Part =
  | { named: Named; label: string }
  | { key: string; text: string; id?: boolean }
  | { key: string; url: string }
  | { text: string };

/** Locator prefixes whose value is an id this directory can name, and the kind each one is. */
const LOCATORS: Record<string, Kind> = {
  account: "identity", contact: "contact", peer: "contact", caller: "caller",
  owner: "owner", token: "key", passkey: "passkey",
};

/** The prefixes whose value is an opaque id, shown short with a copy button rather than in full. */
const OPAQUE = new Set(["invite", "media", "thread", "request", "msg", "segment"]);

/**
 * A row's `resource` (`account:<id> contact:<fpr> tool:send_message`), as parts: the ids a person
 * would not recognise become names; the rest are labelled values. `caller:anonymous` and
 * `account:none` say something already, and are said in words.
 */
export function resourceParts(resource: string, dir: Directory): Part[] {
  if (!resource) return [];
  const out: Part[] = [];
  // `why:` is free text — an error's message, a reason — and every emitter writes it last
  // (internal/public/tools.go why, internal/node/send.go whyFailed, decide.go's
  // identity_state_unreadable and contact_new_address, refresh.go, node.go, agentanswered.go): the
  // rest of the locator is its one value, never a run of tokens.
  const whyAt = resource.search(/(^|\s)why:/);
  const head = whyAt < 0 ? resource : resource.slice(0, whyAt);
  const why = whyAt < 0 ? null : resource.slice(whyAt).trim().slice("why:".length).trim();
  for (const token of head.split(/\s+/).filter(Boolean)) {
    const at = token.indexOf(":");
    const prefix = at > 0 ? token.slice(0, at) : "";
    const value = at > 0 ? token.slice(at + 1) : "";
    if (!prefix || !value) {
      out.push({ text: token });
      continue;
    }
    if (prefix === "caller" && value === "anonymous") {
      out.push({ text: SOME.anonymous });
      continue;
    }
    if (prefix === "account" && value === "none") {
      out.push({ text: "no identity" });
      continue;
    }
    // `key:` is two things. The cloud's account_leaf_key_retired writes the retired leaf's key by its
    // fingerprint (`sha256:…`, what the core names every key by); the node's settings_save writes the
    // name of the setting it changed (`key:tunnel`, `key:preset:…`).
    if (prefix === "key") {
      out.push(value.startsWith("sha256:") ? { key: "leaf key", text: value, id: true } : { key: "setting", text: value });
      continue;
    }
    const kind = LOCATORS[prefix];
    if (kind) out.push({ named: nameOf(kind, value, dir), label: prefix });
    else if (/^https?:\/\//.test(value)) out.push({ key: prefix, url: value });
    else out.push({ key: prefix, text: value, ...(OPAQUE.has(prefix) ? { id: true } : {}) });
  }
  if (why !== null) out.push(why ? { key: "why", text: why } : { text: "why:" });
  return out;
}

/**
 * What a row is about, less what the row already says elsewhere: the identity whose trail this is
 * (`here`, its account id — every row of an identity's trail names its own account first, and on
 * that identity's page the part only repeats the title), and the actor itself (an inbound call's
 * `caller:` IS its actor, which the Who column names). The row, its search text and its export
 * keep every part; only what is drawn is less.
 */
export function aboutParts(parts: Part[], here: string, actor: Named): Part[] {
  return parts.filter((p) => {
    // `caller:anonymous`, said in words, is the anonymous actor the Who column already names.
    if ("text" in p && !("key" in p)) return p.text !== actor.name;
    if (!("named" in p)) return true;
    if (p.named.kind === "identity" && here && p.named.id === here) return false;
    if (actor.id && p.named.id === actor.id) return false;
    return true;
  });
}

/** A details bag's members that are ids, and the kind each is. `credential` is `<kind>:<id>`. */
const DETAIL_IDS: Record<string, Kind> = {
  owner_id: "owner", account_id: "identity", grant_id: "grant", client_id: "grant",
};

/**
 * What a details key, or a locator's prefix, is called on the page, where its own name is a
 * column's and not a person's.
 */
const DETAIL_LABELS: Record<string, string> = {
  owner_id: "owner", account_id: "identity", grant_id: "app", client_id: "app", client_name: "app",
  identity_ids: "identities", kek_version: "key version", slug: "identity",
  account: "identity", token: "key", peer: "contact", why: "reason",
};

/** A details key or a locator prefix as a label: its own word where it has one, else with spaces. */
export function detailLabel(key: string): string {
  return DETAIL_LABELS[key] ?? key.replace(/_/g, " ");
}

/**
 * One member of a details bag, as the page draws it: a name where it is an id, a time where it is
 * an instant, a list, an address, or text. `via` and `credential` are the call's provenance, which
 * the page says last ("via portal", "via Claude Desktop"), never as fields among the rest.
 */
export type Detail =
  | { key: string; text: string; id?: boolean }
  | { key: string; named: Named }
  | { key: string; at: number }
  | { key: string; items: Array<string | Named> }
  | { key: string; url: string };

/** A details bag, split: what the event says, and the door and credential it came through. */
export type Said = { parts: Detail[]; via: string; credential: Named | null };

/** The details members that are provenance, said once, after the rest. */
const PROVENANCE = new Set(["via", "credential"]);

/** Members that repeat what the page already says: the workspace's own id, on its own chain. */
const HIDDEN = new Set(["tenant"]);

/**
 * The instant a details member holds, in ms, or null. A member is an instant by its name
 * (`…_until`, `…_at`, `until`, `at`); the platform writes milliseconds, a few writers seconds, and
 * the two are told apart by size (a seconds value this large would be the year 5138).
 */
function instantOf(key: string, v: unknown): number | null {
  if (!/(^|_)(until|at)$/.test(key)) return null;
  if (typeof v === "number" && Number.isFinite(v) && v > 0) return v > 1e11 ? v : v * 1000;
  if (typeof v === "string" && /^\d{4}-\d\d-\d\dT/.test(v)) {
    const ms = Date.parse(v);
    return Number.isNaN(ms) ? null : ms;
  }
  return null;
}

/**
 * A details bag (JSON text written by the platform from an allow-list), said. `kind` is the event's
 * kind, which decides what an `id` is: an agent key's on `apikey.*`, a webhook's on `webhook.*`.
 * A webhook is named by its address's host where the answer itself carries it (`webhook.created`
 * writes `url`; `webhooks` is that id → host, gathered by the page from the same answer). Anything
 * the row already names (an app's name beside its id, an identity's slug beside it) is said once.
 * Rendered as text, never markup.
 */
export function detailParts(json: string, dir: Directory, kind = "", webhooks: Record<string, string> = {}): Said {
  const said: Said = { parts: [], via: "", credential: null };
  if (!json) return said;
  let o: unknown;
  try {
    o = JSON.parse(json);
  } catch {
    said.parts.push({ key: "", text: json });
    return said;
  }
  if (o === null || typeof o !== "object" || Array.isArray(o)) {
    said.parts.push({ key: "", text: json });
    return said;
  }
  const bag = o as Record<string, unknown>;
  const out: Detail[] = [];
  for (const [key, v] of Object.entries(bag)) {
    if (v === null || v === undefined || v === "" || HIDDEN.has(key)) continue;
    if (PROVENANCE.has(key)) {
      if (key === "via" && typeof v === "string") said.via = v;
      if (key === "credential" && typeof v === "string") said.credential = credentialOf(v, dir) ?? { kind: "key", id: v, name: "a credential", state: "withheld" };
      continue;
    }
    if (key === "id" && typeof v === "string") {
      if (kind.startsWith("apikey.")) out.push({ key: "key", named: nameOf("key", v, dir) });
      else if (kind.startsWith("webhook.")) {
        // The address itself is on the row: the id would only say it again.
        if (typeof bag.url === "string") continue;
        const host = webhooks[v];
        out.push(host ? { key: "webhook", named: { kind: "webhook", id: v, name: host, state: "named" } } : { key: "webhook", text: v, id: true });
      } else out.push({ key: "id", text: v, id: true });
      continue;
    }
    if (key === "identity_ids" && Array.isArray(v)) {
      out.push({ key, items: v.map((x) => nameOf("identity", String(x), dir)) });
      continue;
    }
    const at = instantOf(key, v);
    if (at !== null) {
      out.push({ key, at });
      continue;
    }
    if (Array.isArray(v)) {
      out.push({ key, items: v.map((x) => (typeof x === "string" ? x : JSON.stringify(x))) });
      continue;
    }
    if (typeof v === "boolean") {
      out.push({ key, text: v ? "yes" : "no" });
      continue;
    }
    if (typeof v === "string" && /^https?:\/\//.test(v)) {
      out.push({ key, url: v });
      continue;
    }
    const idKind = DETAIL_IDS[key];
    if (idKind && typeof v === "string") {
      const n = nameOf(idKind, v, dir);
      // An identity since deleted is said by the slug the same row carries, where it carries one.
      const slug = typeof bag.slug === "string" ? bag.slug : "";
      out.push({ key, named: idKind === "identity" && n.state === "gone" && slug ? { ...n, name: `${slug} (removed)` } : n });
      continue;
    }
    // Any other id the directory cannot name — an operator's note, a promo, a hostname's Cloudflare
    // id, an invitation, the confirmation an act was approved under — is said short with a copy
    // button, never as a whole uuid; one short enough to read whole (a plan's id, `team`) is text.
    if (typeof v === "string" && (key === "confirmation" || key.endsWith("_id"))) {
      out.push(v.length > ID_WHOLE ? { key, text: v, id: true } : { key, text: v });
      continue;
    }
    out.push({ key, text: typeof v === "string" ? v : typeof v === "object" ? JSON.stringify(v) : String(v) });
  }
  // Said once: a value that is the name of something the same row already names.
  const names = new Set(out.flatMap((p) => ("named" in p ? [p.named.name] : [])));
  for (const p of out) if ("named" in p && p.named.state === "gone" && p.named.name.endsWith(" (removed)")) names.add(p.named.name.slice(0, -" (removed)".length));
  said.parts = out.filter((p) => !("text" in p && !("id" in p && p.id) && names.has(p.text)));
  return said;
}

/**
 * The webhooks an answer's own events name, id → the host of their address: `webhook.created`
 * writes both, and every later event about that webhook writes only its id.
 */
export function webhookHosts(events: ReadonlyArray<{ kind: string; details: string }>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const e of events) {
    if (e.kind !== "webhook.created") continue;
    try {
      const d = JSON.parse(e.details) as { id?: unknown; url?: unknown };
      if (typeof d.id === "string" && typeof d.url === "string") out[d.id] = new URL(d.url).host;
    } catch {
      // A details bag that is not JSON, or an address that is not a URL, names nothing.
    }
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
  for (const p of parts) {
    if ("named" in p) out.push(p.named);
    else if ("items" in p) for (const x of p.items) if (typeof x !== "string") out.push(x);
  }
  return out;
}

/**
 * An id short enough to sit in a line of text: its head and tail, with the whole of it in the
 * tooltip and the copy. A fingerprint loses its `sha256:` first — seven of its characters say only
 * which hash, and every fingerprint here is that one.
 */
export function shortId(id: string): string {
  const bare = id.startsWith("sha256:") ? id.slice("sha256:".length) : id;
  if (bare.length <= ID_WHOLE) return bare;
  return `${bare.slice(0, 8)}…${bare.slice(-6)}`;
}

/** The longest id said whole: `shortId` leaves one this long as it is. */
const ID_WHOLE = 16;

/** A piece of a name longer than this cannot sit on a line of its own in a table's column; only such a piece breaks anywhere. */
const LONGEST_PIECE = 20;

/**
 * A name as the runs of it a line may break between, each run a list of pieces: a name with spaces
 * breaks between its words (and, as a browser does, after a hyphen); an address only after its `@`
 * (never inside `priya.raman` or `shailka.com`); a handle or a snake_case name after its underscores
 * and dots. A piece with a stretch longer than any column gives it is marked `long`, and only that
 * piece may break anywhere — so one 60-letter name neither breaks an ordinary name mid-word nor
 * pushes its column off the page. Whitespace runs come back as they are.
 */
export function nameBreaks(name: string): Array<Array<{ text: string; long: boolean }>> {
  return name.split(/(\s+)/).filter((r) => r !== "").map((run) => {
    const pieces = /\s/.test(run) ? [run] : run.includes("@") ? run.split(/(?<=@)(?=.)/) : run.split(/(?<=[._])(?=.)/);
    // A hyphen is a place a line breaks already, so the length that matters is between hyphens.
    return pieces.map((text) => ({ text, long: !/\s/.test(text) && text.split(/(?<=-)/).some((x) => x.length > LONGEST_PIECE) }));
  });
}
