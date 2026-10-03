// The data plane. Reads are GET /api/*; writes go to the ORIGINAL form
// endpoints — the ones that are CSRF-gated, account-scoped and audited — as
// application/x-www-form-urlencoded, exactly as the server-rendered forms did.
// The account travels in the body (or the query for reads), never in the
// address bar.

// This node's cookie tag, learned from /api/session. Two nodes on one host share
// a cookie jar — cookies are scoped by host and path, never by port — so the
// browser may hold several `hdtp_csrf_*` entries and only one is ours. Picking
// the wrong one fails every mutation's double-submit check.
let cookieTag = "";

export function csrf(): string {
  const jar = document.cookie.split("; ");
  const want = cookieTag ? "hdtp_csrf_" + cookieTag + "=" : "";
  const hit =
    (want ? jar.find((c) => c.startsWith(want)) : undefined) ??
    // Before the first /api/session, or on a node with no tag: any csrf cookie.
    jar.find((c) => c.startsWith("hdtp_csrf"));
  return hit?.split("=").slice(1).join("=") ?? "";
}

// The selected account. Module state + a subscription, so the picker in the
// shell and every view agree without threading props through the tree.
let account = localStorage.getItem("hdtp.account") ?? "";
const accountListeners = new Set<() => void>();

export function currentAccount(): string {
  return account;
}
export function setAccount(id: string) {
  account = id;
  try {
    localStorage.setItem("hdtp.account", id);
  } catch {
    /* storage may be unavailable; the choice just doesn't persist */
  }
  accountListeners.forEach((f) => f());
}
export function onAccountChange(f: () => void): () => void {
  accountListeners.add(f);
  return () => accountListeners.delete(f);
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/**
 * A failed read, said for a person: the status and the error code the node answered
 * (`{"error":"store"}` is the store failing), never the raw body.
 */
export function failureOf(e: unknown): string {
  if (!(e instanceof ApiError)) return e instanceof Error && e.message ? e.message : String(e);
  let code = "";
  try {
    const body: unknown = JSON.parse(e.message);
    if (body && typeof body === "object" && typeof (body as { error?: unknown }).error === "string") code = (body as { error: string }).error;
  } catch {
    code = e.message.trim().slice(0, 120);
  }
  return `The node answered ${e.status}${code ? ` (${code})` : ""}.`;
}

export async function getJSON<T>(path: string, params?: Record<string, string>): Promise<T> {
  const q = new URLSearchParams(params);
  if (account && !q.has("account")) q.set("account", account);
  const qs = q.toString();
  const res = await fetch(path + (qs ? "?" + qs : ""), { headers: { Accept: "application/json" } });
  if (!res.ok) throw new ApiError(res.status, await res.text());
  return res.json();
}

// postForm submits to one of the write endpoints. A 303 is success (fetch
// follows it; the final response may be HTML or JSON and the caller re-fetches
// its data either way). The redirect's final URL carries the notices the old
// pages showed (?added=, ?err=, ?new=), so it is returned for the caller to read.
export async function postForm(
  path: string,
  fields: Record<string, string | undefined>,
): Promise<{ ok: boolean; url: URL; status: number; body: string }> {
  const body = new URLSearchParams();
  body.set("csrf", csrf());
  if (account) body.set("account", account);
  for (const [k, v] of Object.entries(fields)) if (v !== undefined) body.set(k, v);
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "X-HDTP-Csrf": csrf() },
    body: body.toString(),
  });
  return { ok: res.ok, url: new URL(res.url), status: res.status, body: await res.text() };
}

export type Session = {
  signed_in: boolean;
  cookie_tag?: string;
  // No login_required: SPEC §8.3 requires a session on every bind, so the only
  // question is whether we have one — and, before any passkey exists, whether
  // the node still needs claiming.
  needs_setup: boolean;
  accounts: { id: string; slug: string; display_name: string; fingerprint: string }[];
};

let lastSession: Session | null = null;
const sessionListeners = new Set<(s: Session) => void>();
// Views that change what the session says (creating an identity, installing a leaf)
// call fetchSession afterwards; the shell subscribes so the switcher and the
// selected identity follow without a reload.
export function onSessionChange(f: (s: Session) => void): () => void {
  sessionListeners.add(f);
  return () => sessionListeners.delete(f);
}
// The display name of the identity being acted as, for views that label "you".
export function accountName(): string {
  return lastSession?.accounts.find((a) => a.id === account)?.display_name ?? "You";
}

export async function fetchSession(): Promise<Session> {
  const s = await getJSON<Session>("/api/session");
  lastSession = s;
  cookieTag = s.cookie_tag ?? "";
  // Keep the selection honest: if the stored account is not one this owner may
  // act as, fall back to the first offered.
  if (s.accounts.length > 0 && !s.accounts.some((a) => a.id === account)) {
    setAccount(s.accounts[0].id);
  }
  sessionListeners.forEach((f) => f(s));
  return s;
}

export type LiveEvent = { kind: "message" | "request" | "pending" | "delivery"; account_id: string; thread_id?: string; contact_fpr?: string; status?: string };

// Live updates: the /events stream names each event by kind. `onmessage` only
// ever fired for the unnamed default, so deliveries and requests went unseen;
// every kind is listened to, and the payload is passed along for callers that
// care which contact it was about.
const KINDS: LiveEvent["kind"][] = ["message", "request", "pending", "delivery"];
export function subscribe(onEvent: (e?: LiveEvent) => void): () => void {
  const q = account ? "?account=" + encodeURIComponent(account) : "";
  const es = new EventSource("/events" + q);
  for (const k of KINDS) {
    es.addEventListener(k, (ev) => {
      let parsed: LiveEvent | undefined;
      try { parsed = JSON.parse((ev as MessageEvent).data); } catch { /* payload-less event */ }
      onEvent(parsed);
    });
  }
  return () => es.close();
}
