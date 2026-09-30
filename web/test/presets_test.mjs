// The permission presets' grid (web/src/preset_grid.tsx), its arithmetic (web/src/presets.ts), run as it
// ships: `node --test` strips its types. PACT Cloud's portal carries both files byte for byte (its
// scripts/check-harvested.mjs), so this is the rule for both portals' grids.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { cellLabel, presetColumns, samePerms, withPerm } from "../src/presets.ts";

const VOCAB = ["message.text", "message.media", "status.view", "calendar.availability", "calendar.book"];

test("the columns are the vocabulary, then what a preset holds that the vocabulary lacks", () => {
  // Five presets, five columns: the columns come from the data, in the vocabulary's order.
  assert.deepEqual(presetColumns(VOCAB, [{ name: "basic", perms: ["message.text"] }, { name: "muted", perms: [] }]), VOCAB);
  // A preset holding an integration's permission gets a column for it, or its row's next save drops it.
  assert.deepEqual(
    presetColumns(VOCAB, [{ name: "desk", perms: ["integration.github", "message.text", "integration.github"] }, { name: "x", perms: ["integration.slack"] }]),
    [...VOCAB, "integration.github", "integration.slack"],
  );
  // No vocabulary: the presets alone decide, and a repeated name is one column.
  assert.deepEqual(presetColumns(["a", "a"], [{ name: "p", perms: ["b", "a"] }]), ["a", "b"]);
});

test("a checkbox is named by its preset and its permission", () => {
  assert.equal(cellLabel("family", "Media & files"), "family: Media & files");
});

test("a row's switches, and whether they changed", () => {
  assert.deepEqual(withPerm(["message.text"], "status.view", true), ["message.text", "status.view"]);
  assert.deepEqual(withPerm(["message.text", "status.view"], "message.text", false), ["status.view"]);
  // Switched on twice is on once.
  assert.deepEqual(withPerm(["message.text"], "message.text", true), ["message.text"]);
  assert.ok(samePerms(["a", "b"], ["b", "a"]));
  assert.ok(!samePerms(["a", "b"], ["a"]));
  assert.ok(!samePerms(["a"], ["a", "b"]));
  assert.ok(!samePerms(["a", "c"], ["a", "b"]));
});

test("the grid draws a real, named checkbox per cell and the scope id behind each column's tip", () => {
  const src = readFileSync(new URL("../src/preset_grid.tsx", import.meta.url), "utf8");
  assert.match(src, /<input type="checkbox"[^>]*aria-label=\{cellLabel\(r\.name, label\(c\)\)\}/);
  assert.match(src, /<HelpTip label=\{`About \$\{label\(c\)\}`\}>[^<]*<code>\{c\}<\/code>/);
  // Its columns are its caller's, never a list of its own (the comments may name one as an example).
  const code = src.replace(/^\s*\/\/.*$/gm, "").replace(/\/\*\*[\s\S]*?\*\//g, "");
  assert.doesNotMatch(code, /message\.text|calendar\.book/);
});
