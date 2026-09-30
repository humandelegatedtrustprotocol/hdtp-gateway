import { useState } from "react";
import { passkeyRegister } from "../webauthn";
import { Brand, Button, Field, HelpTip, Notice, Toolbar, type Note } from "../ui";

export function Setup() {
  const [tag, setTag] = useState("this device");
  const [msg, setMsg] = useState<Note | null>(null);
  return (
    <main className="center">
      <div className="brandline"><Brand /></div>
      <h1>Set up this node</h1>
      <p>
        This registers the first owner passkey. Until one exists, anyone who can reach this page can
        claim the node — so do it now, on the device you will use.
      </p>
      <p className="muted">
        The passkey is bound to this address.
        <HelpTip label="About the passkey's address">
          The passkey is bound to the address in your browser's address bar. If you later move the portal
          to a different hostname you will need to register again (<code>passkey reset-wizard</code> mints
          a fresh link).
        </HelpTip>
      </p>
      <Field label="Name this passkey" id="tag">
        <input type="text" maxLength={64} value={tag} onChange={(e) => setTag(e.target.value)} />
      </Field>
      <Toolbar>
        {/* The harness and the QA tools drive this page by id (#tag, #go, #msg).
            Button does not type `id`, so it rides its rest-spread onto the element. */}
        <Button {...{ id: "go" }}
          onClick={async () => {
            setMsg({ kind: "ok", text: "Waiting for your device…" });
            try {
              await passkeyRegister(tag);
              setMsg({ kind: "ok", text: "Registered. Opening your node…" });
              location.href = "/";
            } catch (e) {
              setMsg({ kind: "err", text: String(e instanceof Error ? e.message : e) });
            }
          }}
        >
          Register a passkey
        </Button>
      </Toolbar>
      <div id="msg">
        {msg && (msg.kind === "err" ? <Notice kind="err">{msg.text}</Notice> : <p className="muted">{msg.text}</p>)}
      </div>
    </main>
  );
}
