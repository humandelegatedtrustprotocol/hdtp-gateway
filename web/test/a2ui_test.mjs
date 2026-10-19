// The portal's A2UI renderer (web/src/a2ui.tsx) and the node's owner catalog
// (internal/services/asks/catalog.go) are two copies of one list of components: every component the
// node accepts on a surface is one the card draws, and the card draws no component the node refuses.
// Column is the root, drawn as the card itself through its children.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const goSrc = readFileSync(new URL("../../internal/services/asks/catalog.go", import.meta.url), "utf8");
const tsSrc = readFileSync(new URL("../src/a2ui.tsx", import.meta.url), "utf8");

function catalog() {
  const at = goSrc.indexOf("var catalog = []component{");
  assert.ok(at >= 0, "catalog.go declares no catalog");
  const block = goSrc.slice(at, goSrc.indexOf("\n}\n", at));
  return [...block.matchAll(/^\t\{name: "(\w+)"/gm)].map((m) => m[1]);
}

test("the card draws every component of the node's catalog, and only those", () => {
  const node = catalog();
  // The control: the catalog was read, the six components and the root among them.
  assert.ok(node.length >= 7 && node.includes("Column") && node.includes("TextField"), `read ${node.join(" ")}`);
  const drawn = [...tsSrc.matchAll(/case "(\w+)":/g)].map((m) => m[1]);
  assert.deepEqual([...drawn].sort(), node.filter((n) => n !== "Column").sort());
  assert.match(tsSrc, /comps\.get\("root"\)/, "the card draws the root's children");
});
