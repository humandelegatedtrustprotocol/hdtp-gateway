// The portal's A2UI renderer (web/src/a2ui.tsx) and the node's owner catalog
// (internal/services/asks/catalog.go) are two copies of one list of components: every component the
// node accepts on a surface is one the card draws, and the card draws no component the node refuses.
// Column is the root, drawn as the card itself through its children.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const goSrc = readFileSync(new URL("../../internal/services/asks/catalog.go", import.meta.url), "utf8");
const tsSrc = readFileSync(new URL("../src/a2ui.tsx", import.meta.url), "utf8");

function block() {
  const at = goSrc.indexOf("var catalog = []component{");
  assert.ok(at >= 0, "catalog.go declares no catalog");
  return goSrc.slice(at, goSrc.indexOf("\n}\n", at));
}

function catalog() {
  return [...block().matchAll(/^\t\{name: "(\w+)"/gm)].map((m) => m[1]);
}

// Each component's props, as the catalog lists them.
function props() {
  const out = {};
  for (const part of block().split(/^\t\{name: /m).slice(1)) {
    const name = part.match(/^"(\w+)"/)[1];
    out[name] = [...part.matchAll(/\{name: "(\w+)", kind:/g)].map((m) => m[1]);
  }
  return out;
}

// The props the card does not read, and why: a ChoicePicker here is mutually exclusive alone.
const unread = new Set(["ChoicePicker.variant"]);

test("the card draws every component of the node's catalog, and only those", () => {
  const node = catalog();
  // The control: the catalog was read, the six components and the root among them.
  assert.ok(node.length >= 7 && node.includes("Column") && node.includes("TextField"), `read ${node.join(" ")}`);
  const drawn = [...tsSrc.matchAll(/case "(\w+)":/g)].map((m) => m[1]);
  assert.deepEqual([...drawn].sort(), node.filter((n) => n !== "Column").sort());
  assert.match(tsSrc, /comps\.get\("root"\)/, "the card draws the root's children");
});

test("the card reads every prop the catalog gives a component, but those it names as unread", () => {
  const all = props();
  // The control: the props were read, KeyValue's items among them.
  assert.deepEqual(all.KeyValue, ["items"]);
  assert.ok(all.ChoicePicker.includes("options") && all.Button.includes("action"), JSON.stringify(all));
  for (const [comp, list] of Object.entries(all)) {
    for (const p of list) {
      if (unread.has(`${comp}.${p}`)) continue;
      // A component's props are read off c, the root's (the Column) off root.
      const reader = comp === "Column" ? "root\\?" : "c";
      assert.ok(new RegExp(`\\b${reader}\\.${p}\\b`).test(tsSrc), `the card never reads ${comp}.${p}`);
    }
  }
});

test("the card answers with A2UI's client-to-server action, its context read from the data model", () => {
  assert.match(tsSrc, /version: "v0\.9\.1"/);
  assert.match(tsSrc, /action: \{ name: b\.action\?\.event\.name, surfaceId: surface\.id, sourceComponentId: b\.id, timestamp: [^,]+, context \}/);
  assert.match(tsSrc, /postForm\(`\/asks\/\$\{encodeURIComponent\(ask\.id\)\}\/answer`, \{ message \}\)/);
});

test("the card knows a ready reply by the event the node gives it, and posts it as it stands", () => {
  const node = goSrc.match(/const ReplyEvent = "(\w+)"/);
  assert.ok(node, "catalog.go declares no ReplyEvent");
  assert.equal(tsSrc.match(/const REPLY = "(\w+)"/)?.[1], node[1]);
  assert.match(tsSrc, /if \(c\.action\?\.event\.name === REPLY\)[\s\S]{0,400}onClick=\{\(\) => press\(c\)\}/);
});
