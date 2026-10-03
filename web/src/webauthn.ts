// The WebAuthn ceremonies, ported byte-for-byte in SEMANTICS from the inline
// scripts the server-rendered pages shipped: same endpoints, same base64url
// handling, same query-string passthrough for the setup token.
import { csrf } from "./api";

const b64u = (s: string) =>
  Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const b64 = (b: ArrayBuffer) =>
  btoa(String.fromCharCode(...new Uint8Array(b)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

export async function passkeyLogin(): Promise<void> {
  const begin = await fetch("/login/begin", { method: "POST", headers: { "X-HDTP-Csrf": csrf() } });
  if (!begin.ok) throw new Error("no passkeys are registered on this node");
  const { ceremony, options } = await begin.json();
  const o = options.publicKey;
  o.challenge = b64u(o.challenge);
  if (o.allowCredentials) o.allowCredentials.forEach((c: { id: unknown }) => (c.id = b64u(c.id as string)));
  const cred = (await navigator.credentials.get({ publicKey: o })) as PublicKeyCredential;
  const resp = cred.response as AuthenticatorAssertionResponse;
  const body = {
    id: cred.id,
    rawId: b64(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64(resp.clientDataJSON),
      authenticatorData: b64(resp.authenticatorData),
      signature: b64(resp.signature),
      userHandle: resp.userHandle ? b64(resp.userHandle) : null,
    },
  };
  const fin = await fetch("/login/finish?ceremony=" + encodeURIComponent(ceremony), {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-HDTP-Csrf": csrf() },
    body: JSON.stringify(body),
  });
  if (!fin.ok) throw new Error("that passkey was not accepted");
}

export async function passkeyRegister(tag: string): Promise<void> {
  // location.search carries the one-time setup token; the server validates it
  // on begin and consumes it on finish (SPEC §8.6).
  const begin = await fetch("/setup/begin" + location.search, {
    method: "POST",
    headers: { "X-HDTP-Csrf": csrf() },
  });
  if (!begin.ok) throw new Error("setup is closed on this node, or this address cannot register passkeys");
  const { ceremony, options } = await begin.json();
  const o = options.publicKey;
  o.challenge = b64u(o.challenge);
  o.user.id = b64u(o.user.id);
  if (o.excludeCredentials) o.excludeCredentials.forEach((c: { id: unknown }) => (c.id = b64u(c.id as string)));
  const cred = (await navigator.credentials.create({ publicKey: o })) as PublicKeyCredential;
  const resp = cred.response as AuthenticatorAttestationResponse;
  const body = {
    id: cred.id,
    rawId: b64(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64(resp.clientDataJSON),
      attestationObject: b64(resp.attestationObject),
    },
  };
  const q = new URLSearchParams(location.search);
  q.set("ceremony", ceremony);
  q.set("tag", tag || "this device");
  const fin = await fetch("/setup/finish?" + q.toString(), {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-HDTP-Csrf": csrf() },
    body: JSON.stringify(body),
  });
  if (!fin.ok) throw new Error("that passkey was not accepted — try again, or check the node logs");
}
