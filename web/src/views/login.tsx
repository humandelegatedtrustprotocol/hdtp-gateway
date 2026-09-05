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
              location.href = "/";
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
