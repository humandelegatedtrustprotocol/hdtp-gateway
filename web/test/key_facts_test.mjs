// An identity's two keys are drawn by one piece, KeyFacts (glance.tsx, shared with PACT Cloud's portal),
// with what each key IS in its `?` rather than in words beside it — the owner (2026-10-01): "show text
// that tells whether its to be replaced when renewal or its a root, these in `?` icon than inline. show
// key just there if required". Read from the source, because the portal has no DOM test harness; the
// cloud's portal-layout suite opens the tips in a browser.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";

const src = (p) => readFileSync(new URL(`../src/${p}`, import.meta.url), "utf8");

test("each key's row carries a `?` that says what the key is, and no inline words", () => {
  const glance = src("glance.tsx");
  assert.match(glance, /\{root && <><dt>Root<\/dt><dd><IdText id=\{root\} \/><HelpTip label="About the root">\s*Your identity: what your contacts pin\. A renewal never changes it\./);
  assert.match(glance, /\{kid && <><dt>Host key<\/dt><dd><IdText id=\{kid\} \/><HelpTip label="About the host key">\s*This host's key, certified under your root\. Every renewal replaces it/);
  // The shape it exists to catch: the words back inline, beside the id.
  for (const f of ["glance.tsx", "views/card.tsx", "views/identity.tsx"]) {
    assert.doesNotMatch(src(f), /what contacts pin<\/span>|which a renewal replaces<\/span>|Host key · /);
  }
  assert.match('<dd><IdText id={kid} /><span className="muted"> — this node\'s key, which a renewal replaces</span></dd>', /which a renewal replaces<\/span>/);
});

test("the keys are drawn by KeyFacts on the card page and the Identity page, and in no other view", () => {
  assert.match(src("views/card.tsx"), /<KeyFacts root=\{d\.root_fingerprint\} kid=\{d\.kid\} \/>/);
  // The node's account fingerprint IS this node's key: the card names it as its kid (contacts.FactsOf).
  assert.match(src("views/identity.tsx"), /<dl className="facts"><KeyFacts root=\{a\.root_fingerprint\} kid=\{a\.fingerprint\} \/><\/dl>/);
  const views = readdirSync(new URL("../src/views/", import.meta.url)).filter((f) => f.endsWith(".tsx"));
  assert.deepEqual(views.filter((f) => src(`views/${f}`).includes("<KeyFacts ")).sort(), ["card.tsx", "identity.tsx"]);
  assert.deepEqual(views.filter((f) => /<dt>(Root|Host key)<\/dt>/.test(src(`views/${f}`))), []);
});
