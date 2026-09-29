// A link on an identity's card is about THAT identity: every one selects it before it lands. The
// Certificate button once had no onClick, and on a node with two identities it opened whichever
// certificate was selected — another identity's, with another expiry. Read from the view's source,
// because the portal has no DOM test harness; the card is one JSX element and every `to` in it is
// either a count's (`to: "…"`) or a button's (`to="…"`).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const src = readFileSync(new URL("../src/views/dashboard.tsx", import.meta.url), "utf8");

/** The `<IdentityCard …/>` element's source: up to the `/>` that closes it, outside every `{…}`. */
export function cardOf(source) {
  const at = source.indexOf("<IdentityCard ");
  assert.ok(at >= 0, "the overview renders no IdentityCard");
  let depth = 0;
  for (let i = at; i < source.length; i++) {
    const ch = source[i];
    if (ch === "{") depth++;
    else if (ch === "}") depth--;
    else if (depth === 0 && ch === "/" && source[i + 1] === ">") return source.slice(at, i + 2);
  }
  throw new Error("the IdentityCard element does not close");
}

/** Each line of the card that links somewhere and does not select the card's identity. */
export function unselected(card) {
  return card.split("\n").filter((l) => /\bto(=|: )"/.test(l) && !/onClick(=\{|: )pickThis/.test(l)).map((l) => l.trim());
}

test("every link on an identity's card selects that identity", () => {
  const card = cardOf(src);
  assert.ok((card.match(/\bto(=|: )"/g) ?? []).length >= 3, "the card's links were not found; this test reads nothing");
  assert.deepEqual(unselected(card), []);
  // The shape it exists to catch.
  assert.equal(unselected('footer={<Button variant="quiet" to="/identity" icon="key">Certificate</Button>}').length, 1);
});
