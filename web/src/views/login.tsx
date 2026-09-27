import { useState } from "react";
import { passkeyLogin } from "../webauthn";
import { Brand, Button, Notice, Toolbar, type Note } from "../ui";

export function Login() {
  const [msg, setMsg] = useState<Note | null>(null);
  return (
    <main className="center">
      <div className="brandline"><Brand /></div>
      <h1>Sign in</h1>
      <p>Use the passkey you registered for this node.</p>
      <Toolbar>
        <Button
          onClick={async () => {
            setMsg({ kind: "ok", text: "Waiting for your device…" });
            try {
              await passkeyLogin();
              location.href = returnPath();
            } catch (e) {
              setMsg({ kind: "err", text: String(e instanceof Error ? e.message : e) });
            }
          }}
        >
          Sign in with a passkey
        </Button>
      </Toolbar>
      {/* The ceremony reports into #msg: progress as a muted line, a failure as
          a notice — both under the one id the setup harness reads. */}
      <div id="msg">
        {msg && (msg.kind === "err" ? <Notice kind="err">{msg.text}</Notice> : <p className="muted">{msg.text}</p>)}
      </div>
    </main>
  );
}

// returnPath is where sign-in goes on to: the page that sent the person here (`?next=`, set by a
// server-rendered page such as /identity/<slug>/wallet), when it is a path on this portal, and the
// dashboard otherwise. "//host" and "/\\host" are another site to a browser, so they are refused.
function returnPath(): string {
  const next = new URLSearchParams(location.search).get("next") ?? "";
  return next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\") ? next : "/";
}
