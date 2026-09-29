// The stylesheet's rules that a page's layout depends on, read from the sheet itself. PACT Cloud's
// portal carries the same sheet (harvested) and holds its copy to the same rules.
//
//   - A pill never breaks onto two lines (the owner, 2026-09-29: "envelope invalid chip in new line in
//     chip"): no rule whose subject is `.pill` sets `white-space` to anything but `nowrap`. A pill holds
//     a status word; what does not fit in one goes in a line beside it. This replaces the rule held
//     before it (internalui's TestAPillInATableNeverBreaksInsideAWord), that a pill in a table "breaks
//     between words or not at all": between words is what the owner then saw, and rejected.
//   - Only the Inbox is a column that fills the window. Any other wide page as a flex column with
//     `min-height:0` squeezes each table's scroll box to what the chips above it leave (the owner:
//     "audit log table too tight"), so no `main.wide` rule but the Inbox's may make it one.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("../src/style.css", import.meta.url), "utf8");

/** Every rule as [selector, declarations], at-rule bodies included, comments removed. */
export function rules(sheet) {
  const body = sheet.replace(/\/\*[\s\S]*?\*\//g, "");
  const out = [];
  for (const m of body.matchAll(/([^{}@;]+)\{([^{}]*)\}/g)) out.push([m[1].trim(), m[2]]);
  return out;
}

/** The declared value of `prop` in a declaration block, or null. */
function value(decls, prop) {
  for (const d of decls.split(";")) {
    const at = d.indexOf(":");
    if (at > 0 && d.slice(0, at).trim() === prop) return d.slice(at + 1).trim();
  }
  return null;
}

/** The selectors in a list whose subject (last compound) carries `cls`. */
function subjects(list, cls) {
  return list.split(",").map((s) => s.trim()).filter((s) => {
    const last = s.split(/[\s>+~]+/).filter(Boolean).pop() ?? "";
    return new RegExp(`\\.${cls}(?![\\w-])`).test(last);
  });
}

export function pillsThatWrap(sheet) {
  return rules(sheet).filter(([sel, decls]) => subjects(sel, "pill").length > 0 && (value(decls, "white-space") ?? "nowrap") !== "nowrap").map(([sel]) => sel);
}

export function widePagesAsColumns(sheet) {
  return rules(sheet).filter(([sel, decls]) => sel.split(",").some((s) => /main\.wide(?![\w-])/.test(s) && !s.includes(":has(.inbox)"))
    && (value(decls, "display") === "flex" || value(decls, "min-height") === "0")).map(([sel]) => sel);
}

test("no rule lets a pill wrap", () => {
  assert.deepEqual(pillsThatWrap(css), []);
  // The check sees the rules it exists for: the two that made pills wrap in a cell and on a card.
  assert.deepEqual(pillsThatWrap("td .pill{white-space:normal;word-break:keep-all}.gl-id .cert .pill{white-space:normal}.pill{white-space:nowrap}"),
    ["td .pill", ".gl-id .cert .pill"]);
  assert.deepEqual(pillsThatWrap("@container (max-width:40rem){.x .pill{white-space:pre-wrap}}"), [".x .pill"]);
});

test("only the Inbox makes a wide page a column", () => {
  assert.deepEqual(widePagesAsColumns(css), []);
  assert.deepEqual(widePagesAsColumns("main.wide{max-width:none;padding:0;flex:1;display:flex;flex-direction:column;min-height:0}main.wide:has(.inbox){display:flex;min-height:0}"),
    ["main.wide"]);
});
