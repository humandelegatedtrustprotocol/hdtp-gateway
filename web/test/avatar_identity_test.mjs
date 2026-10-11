// An avatar's colour is its identity's, not its name's: two contacts named bob, an old root and a new
// one, wear two colours. Two holds, both on the sources as they ship (make test-js has no
// node_modules, so nothing here renders React):
//   - ui.tsx's Avatar picks its fill from `identity`: its `const slot = …` expression is read out of
//     the source and evaluated against words.ts avatarSlot;
//   - every <Avatar under src/ is given an `identity`, or is your own (a bare `me`).
// BatonDeck holds its harvested copy of the portal the same way (portal/test/avatar-identity.test.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { avatarSlot } from "../src/words.ts";

const SRC = fileURLToPath(new URL("../src/", import.meta.url));
const ui = readFileSync(join(SRC, "ui.tsx"), "utf8");

const OLD_BOB = "sha256:FLuPe1CufTrRXVcZXWF90_SOg9q4ZLPUgcgwCNtCVr8";
const NEW_BOB = "sha256:ghGuwv0kg4zBw-6LDmEGGSE60BIevaZlcf8kMJNa6VU";

/** Avatar's slot as ui.tsx computes it: its one `const slot = …;`, run with words.ts avatarSlot. */
function slotOf(source) {
  const body = /export function Avatar\([\s\S]*?\n\}\n/.exec(source)?.[0];
  assert.ok(body, "ui.tsx has no `export function Avatar(`");
  const fills = Number(/const AVATAR_FILLS = (\d+);/.exec(source)?.[1]);
  assert.ok(fills > 0, "ui.tsx has no `const AVATAR_FILLS = N;`");
  const slots = [...body.matchAll(/const slot = ([^;]+);/g)];
  assert.equal(slots.length, 1, "Avatar has no single `const slot = …;` to hold");
  const expr = slots[0][1];
  return (props) => vm.runInNewContext(expr, { name: props.name, identity: props.identity, me: props.me, avatarSlot, AVATAR_FILLS: fills });
}

test("Avatar's fill follows the identity, not the name", () => {
  const slot = slotOf(ui);
  assert.notEqual(slot({ name: "bob", identity: OLD_BOB }), slot({ name: "bob", identity: NEW_BOB }), "two roots named bob: two fills");
  assert.equal(slot({ name: "bob", identity: OLD_BOB }), slot({ name: "Robert", identity: OLD_BOB }), "one root, two names: one fill");
  assert.ok(slot({ name: "bob", identity: OLD_BOB }) >= 0);
  assert.equal(slot({ name: "bob" }), -1, "no identity: the neutral fill");
  assert.equal(slot({ name: "bob", identity: OLD_BOB, me: true }), -1, "your own: the ink");
});

test("an Avatar keyed by its name is refused", () => {
  const byName = ui.replace(/avatarSlot\(identity \?\? ""/, 'avatarSlot(name ?? ""');
  assert.notEqual(byName, ui, "the mutation did not apply: Avatar's slot expression changed shape");
  const slot = slotOf(byName);
  assert.equal(slot({ name: "bob", identity: OLD_BOB }), slot({ name: "bob", identity: NEW_BOB }));
});

/** Every `<Avatar …>` tag in a source, whole: braces are followed, so `=>` or `a > b` inside a prop does not end it. */
function avatarTags(text) {
  const tags = [];
  for (const m of text.matchAll(/<Avatar\b/g)) {
    let depth = 0;
    let i = m.index + m[0].length;
    for (; i < text.length; i++) {
      const c = text[i];
      if (c === "{") depth++;
      else if (c === "}") depth--;
      else if (c === ">" && depth === 0) break;
    }
    tags.push(text.slice(m.index, i + 1));
  }
  return tags;
}

/** The tags under src/ given neither an `identity={…}` nor a bare `me`. */
function bareAvatars(files) {
  const bare = [];
  for (const [f, text] of files) {
    for (const tag of avatarTags(text)) {
      const attrs = tag.replace(/\{(?:[^{}]|\{[^{}]*\})*\}/g, "{}");
      if (!/\sidentity=\{/.test(attrs) && !/\sme(?=[\s/>])/.test(attrs)) bare.push(`${f}: ${tag}`);
    }
  }
  return bare;
}

const tsx = readdirSync(SRC, { recursive: true }).filter((f) => f.endsWith(".tsx")).map((f) => [relative(SRC, join(SRC, f)), readFileSync(join(SRC, f), "utf8")]);

test("every avatar of somebody else is given its identity", () => {
  assert.deepEqual(bareAvatars(tsx), []);
  // The scan reads what it says it reads: it found the avatars there are, the people list's among them.
  const found = tsx.flatMap(([, text]) => avatarTags(text));
  assert.equal(found.length, tsx.reduce((n, [, text]) => n + text.split("<Avatar").length - 1, 0));
  assert.ok(found.length >= 8, `only ${found.length} <Avatar tags found under src/`);
  assert.ok(found.includes("<Avatar name={x.label} identity={x.fingerprint} />"), "the people list's avatar was not among those found");
});

test("an avatar of somebody else without an identity is refused, and `me={…}` is not your own", () => {
  const people = tsx.find(([f]) => f === join("views", "people.tsx"));
  assert.ok(people, "no views/people.tsx");
  const dropped = people[1].replace("<Avatar name={x.label} identity={x.fingerprint} />", "<Avatar name={x.label} />");
  assert.notEqual(dropped, people[1]);
  assert.deepEqual(bareAvatars([["views/people.tsx", dropped]]), ["views/people.tsx: <Avatar name={x.label} />"]);
  assert.equal(bareAvatars([["x.tsx", "<Avatar name={n} me={a === b} />"]]).length, 1);
  assert.equal(bareAvatars([["x.tsx", "<Avatar me name={n} />"]]).length, 0);
  assert.equal(bareAvatars([["x.tsx", "<Avatar name={n} onClick={() => a > b} />"]]).length, 1);
});
