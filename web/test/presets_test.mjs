// The permission presets' grid (web/src/preset_grid.tsx), its arithmetic (web/src/presets.ts), run as it
// ships: `node --test` strips its types. BatonDeck's portal carries both files byte for byte (its
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

// ---- A row saves itself (presetAutosave): owner, 2026-10-01, "replace the per-row Save button with
// autosave, using a loader". The rig's clock and save are the test's (autosave_rig.mjs).
import { AUTOSAVE } from "../src/presets.ts";
import { rig } from "./autosave_rig.mjs";

const TWO = () => [{ name: "basic", perms: ["message.text"] }, { name: "family", perms: [] }];

test("a burst of ticks is one save, sent when the ticks stop", () => {
  const r = rig(TWO());
  r.rows.toggle("basic", "status.view", true);
  r.tick(AUTOSAVE.debounceMs - 100);
  r.rows.toggle("basic", "message.media", true);
  r.tick(AUTOSAVE.debounceMs - 100);
  r.rows.toggle("basic", "status.view", false);
  // The row changed at once, and nothing has been sent while the ticks kept coming.
  assert.deepEqual(r.perms("basic"), ["message.text", "message.media"]);
  assert.equal(r.rows.state("basic").phase, "waiting");
  assert.equal(r.calls.length, 0);
  r.tick(AUTOSAVE.debounceMs);
  assert.equal(r.calls.length, 1);
  assert.deepEqual(r.calls[0], { ...r.calls[0], name: "basic", perms: ["message.text", "message.media"] });
});

test("a burst that ends where it started sends nothing", () => {
  const r = rig(TWO());
  r.rows.toggle("basic", "status.view", true);
  r.rows.toggle("basic", "status.view", false);
  r.tick(AUTOSAVE.debounceMs * 3);
  assert.equal(r.calls.length, 0);
  assert.equal(r.rows.state("basic").phase, "idle");
});

test("while its save is out the row is saving and a tick does nothing; then the check, the words and the Undo", async () => {
  const r = rig(TWO());
  r.rows.toggle("basic", "status.view", true);
  r.tick(AUTOSAVE.debounceMs);
  assert.equal(r.rows.state("basic").phase, "saving");
  // The grid disables the row's checkboxes on `saving` (preset_grid.tsx, held below); a tick that
  // arrives anyway changes nothing and starts no second save.
  r.rows.toggle("basic", "message.media", true);
  assert.deepEqual(r.perms("basic"), ["message.text", "status.view"]);
  r.tick(AUTOSAVE.debounceMs * 2);
  assert.equal(r.calls.length, 1);
  r.calls[0].ok();
  await r.settle();
  assert.deepEqual(r.rows.state("basic"), { phase: "saved", undo: ["message.text"], error: null });
  assert.deepEqual(r.perms("basic"), ["message.text", "status.view"]);
  // The check goes after AUTOSAVE.savedMs; the Undo stays to AUTOSAVE.undoMs.
  r.tick(AUTOSAVE.savedMs);
  assert.deepEqual(r.rows.state("basic"), { phase: "idle", undo: ["message.text"], error: null });
  r.tick(AUTOSAVE.undoMs - AUTOSAVE.savedMs);
  assert.equal(r.rows.state("basic").undo, null);
});

test("Undo puts the row back as it was before the save, and saves that at once", async () => {
  const r = rig(TWO());
  r.rows.toggle("basic", "status.view", true);
  r.tick(AUTOSAVE.debounceMs);
  r.calls[0].ok();
  await r.settle();
  r.rows.undo("basic");
  assert.deepEqual(r.perms("basic"), ["message.text"]);
  assert.equal(r.calls.length, 2);
  assert.deepEqual(r.calls[1].perms, ["message.text"]);
  assert.equal(r.rows.state("basic").phase, "saving");
  r.calls[1].ok();
  await r.settle();
  assert.deepEqual(r.saved[0].perms, ["message.text"]);
  assert.equal(r.rows.state("basic").phase, "saved");
});

test("a refused save puts the row back as it is saved and keeps the reason until the row's next tick", async () => {
  const r = rig(TWO());
  r.rows.toggle("basic", "status.view", true);
  r.tick(AUTOSAVE.debounceMs);
  const why = new Error("Could not save the basic preset: the node answered 500.");
  r.calls[0].no(why);
  await r.settle();
  assert.deepEqual(r.perms("basic"), ["message.text"]);
  assert.deepEqual(r.rows.state("basic"), { phase: "idle", undo: null, error: why });
  r.rows.toggle("basic", "message.media", true);
  assert.equal(r.rows.state("basic").error, null);
});

test("saves go one at a time, in the order they came due", async () => {
  const r = rig(TWO());
  r.rows.toggle("basic", "status.view", true);
  r.tick(100);
  r.rows.toggle("family", "message.text", true);
  r.tick(AUTOSAVE.debounceMs);
  // family came due while basic's save was out: it waits for basic's answer.
  assert.deepEqual(r.calls.map((c) => c.name), ["basic"]);
  assert.equal(r.rows.state("family").phase, "waiting");
  r.calls[0].ok();
  await r.settle();
  assert.deepEqual(r.calls.map((c) => c.name), ["basic", "family"]);
});

test("a row that is not saved yet (a new preset) is a draft only, and forget drops it", () => {
  const r = rig(TWO());
  r.rows.toggle("New preset", "message.text", true);
  r.tick(AUTOSAVE.debounceMs * 3);
  assert.equal(r.calls.length, 0);
  assert.deepEqual(r.perms("New preset"), ["message.text"]);
  r.rows.forget("New preset");
  assert.deepEqual(r.perms("New preset"), []);
  // A deleted row's pending save is dropped with it.
  r.rows.toggle("family", "message.text", true);
  r.rows.forget("family");
  r.tick(AUTOSAVE.debounceMs * 3);
  assert.equal(r.calls.length, 0);
});

test("the grid disables a saving row, marks it, and says a refusal under it", () => {
  const src = readFileSync(new URL("../src/preset_grid.tsx", import.meta.url), "utf8");
  assert.match(src, /<input type="checkbox"[^>]*disabled=\{saving\}/);
  assert.match(src, /const saving = st\.phase === "saving";/);
  assert.match(src, /<SaveMark phase=\{st\.phase\} what=\{r\.name\} onUndo=\{st\.undo \? \(\) => autosave\.undo\(r\.name\) : undefined\} \/>/);
  assert.match(src, /\{st\.error !== null && \(\s*<tr className="pg-fail">/);
  const mark = readFileSync(new URL("../src/save_mark.tsx", import.meta.url), "utf8");
  // The live region is there before its words; the words are "Saved <preset>".
  assert.match(mark, /<span className="sr-only" role="status" aria-live="polite">\{phase === "saved" \? `Saved \$\{what\}` : ""\}<\/span>/);
  assert.match(mark, /\{phase === "saving" && <Spinner label=\{`Saving \$\{what\}`\} \/>\}/);
  assert.match(mark, /icon="undo" aria-label=\{`Undo \$\{what\}`\}/);
});

test("the node's Settings: no Save button on a preset's row, Delete still asks first, a new preset still waits for its Add", () => {
  const src = readFileSync(new URL("../src/views/settings.tsx", import.meta.url), "utf8");
  const presets = src.slice(src.indexOf("function Presets("), src.indexOf("function StorageForm"));
  assert.doesNotMatch(presets, />Save</);
  assert.match(presets, /confirm=\{`Delete the \$\{p\.name\} preset\? Contacts wearing it keep their switches\.`\} onClick=\{\(\) => del\(p\.name\)\}/);
  assert.match(presets, /<Button onClick=\{add\} busy=\{adding\} disabled=\{!newName\.trim\(\)\}>Add preset<\/Button>/);
  // One save path: the hook's, through the node's POST; a refusal is thrown, never drawn as saved.
  assert.match(presets, /usePresetAutosave\(presets, async \(name, perms\) => \{\s*const a = await put\(name, perms\);\s*if \(!a\.page\) throw new Error/);
});
