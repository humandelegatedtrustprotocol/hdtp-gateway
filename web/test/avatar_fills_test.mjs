// An avatar's fills: brand.css's --av-N tokens, as many as ui.tsx's Avatar picks among, each dark enough
// for white initials in both themes, and no colour written into ui.tsx. tools/kit.mjs check runs this
// hold on every commit (make test-js); here it is run against the files as they are, and against each
// way it must refuse them.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { avatarProblems, tokensOf } from "../tools/kit.mjs";

const WEB = join(dirname(fileURLToPath(import.meta.url)), "..");
const ui = readFileSync(join(WEB, "src/ui.tsx"), "utf8");
const brand = readFileSync(join(WEB, "src/brand.css"), "utf8");
const light = tokensOf(brand, /\/\* palette:light \*\/\s*:root\s*\{([^}]*)\}/);
const dark = { ...light, ...tokensOf(brand, /\/\* palette:dark \*\/\s*@media \(prefers-color-scheme: dark\)\s*\{\s*:root\s*\{([^}]*)\}/) };

test("the avatar fills hold: one token per fill ui.tsx picks among, white initials readable on each", () => {
  assert.deepEqual(avatarProblems(ui, light, dark), []);
});

test("a fill too light for white initials is refused, in the theme it is too light in", () => {
  const got = avatarProblems(ui, light, { ...dark, "av-3": "#C9A7F5" });
  assert.equal(got.length, 1);
  assert.match(got[0], /^dark: avatar fill --av-3 #C9A7F5: white initials are 2\.03 : 1/);
});

test("more fills picked than there are tokens is refused", () => {
  assert.match(avatarProblems(ui.replace(/const AVATAR_FILLS = \d+/, "const AVATAR_FILLS = 11"), light, dark).join("\n"), /picks among 11 avatar fills/);
});

test("a literal colour in ui.tsx is refused", () => {
  assert.match(avatarProblems(ui.replace("background: `var(--av-", "background: \"#AB5309\" ?? `var(--av-"), light, dark).join("\n"), /carries #AB5309/);
});

test("an avatar not filled from the tokens is refused", () => {
  assert.match(avatarProblems(ui.replace("`var(--av-${slot + 1})`", "undefined"), light, dark).join("\n"), /does not fill an avatar from the --av-N tokens/);
});
