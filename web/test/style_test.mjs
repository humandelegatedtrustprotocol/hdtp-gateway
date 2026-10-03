// The stylesheet's rules that a page's layout depends on, read from the sheet itself. BatonDeck's
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
//   - Every text field is styled as one (the owner's screenshot of 2026-09-30: "Pick your name." drew
//     its inputs as the browser's boxes, because they had no `type` and the sheet named types). Each
//     rule that styles `input[type="text"]` names, in the same context, every input the browser draws
//     as a text field, an input with no `type` first. The fields a page actually draws are held by the
//     cloud's e2e/layout/field-style.mjs, in a browser.
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

/**
 * The sheet's rules in source order, each with the width range its @media wraps it in ([min, max] px;
 * Infinity when open). Nested blocks narrow the range. Rules inside anything but a width @media (a
 * container query, a reduced-motion or colour-scheme query) are kept out: they do not decide a column.
 */
export function rulesByWidth(sheet) {
  const body = sheet.replace(/\/\*[\s\S]*?\*\//g, "");
  const out = [];
  const stack = [];
  let i = 0;
  let head = "";
  for (; i < body.length; i++) {
    const ch = body[i];
    if (ch === "{") {
      const sel = head.trim();
      head = "";
      if (sel.startsWith("@")) {
        const at = stack.length ? stack[stack.length - 1] : { min: 0, max: Infinity, other: false };
        const min = /min-width:\s*(\d+)px/.exec(sel), max = /max-width:\s*(\d+)px/.exec(sel);
        const widthOnly = /^@media\s*(\((min|max)-width:\s*\d+px\)\s*(and\s*)?)+$/.test(sel);
        stack.push({ min: min ? Math.max(at.min, +min[1]) : at.min, max: max ? Math.min(at.max, +max[1]) : at.max, other: at.other || !widthOnly, at: true });
        continue;
      }
      const end = body.indexOf("}", i);
      const at = stack.length ? stack[stack.length - 1] : { min: 0, max: Infinity, other: false };
      if (!at.other) out.push({ sel, decls: body.slice(i + 1, end), min: at.min, max: at.max });
      i = end;
      continue;
    }
    if (ch === "}") { stack.pop(); head = ""; continue; }
    head += ch;
  }
  return out;
}

/** The last value `prop` is given for exactly `selector` among the rules that apply at `width`. */
export function lastAt(sheet, selector, prop, width) {
  let v = null;
  for (const r of rulesByWidth(sheet)) {
    if (width < r.min || width > r.max) continue;
    if (!r.sel.split(",").map((s) => s.trim()).includes(selector)) continue;
    const got = value(r.decls, prop);
    if (got !== null) v = got;
  }
  return v;
}

test("on a phone the Inbox is one column, whatever the panel and focus say", () => {
  // Every class combination that sets the inbox's columns: at 390 each must end at one column, or the
  // phone draws three 300px panes in a 390px screen (M-F1). And that column is minmax(0,1fr), not 1fr:
  // 1fr's floor is the pane's widest line, and a long slug in the Inbox's header made the list wider
  // than the phone, New and every preview's end off the screen (2026-10-01).
  for (const sel of [".inbox", ".inbox.panel-off", ".inbox.focus"]) {
    assert.equal(lastAt(css, sel, "grid-template-columns", 390), "minmax(0,1fr)", `${sel} at 390`);
  }
  // Between a phone and PANEL_BESIDE the panel is a drawer over the conversation, never a column;
  // from there up a desktop keeps three.
  assert.equal(lastAt(css, ".inbox", "grid-template-columns", 1100), "300px minmax(0,1fr)");
  assert.equal(lastAt(css, ".inbox", "grid-template-columns", 1440), "300px minmax(0,1fr) 320px");
  // On a phone the panel pane shows even with the panel kept closed beside a thread.
  assert.equal(lastAt(css, '.inbox[data-pane="panel"] .panel', "display", 390), "flex");
  // The evaluator sees what it exists for: a later ≤1180 rule re-imposing columns on a phone.
  const old = ".inbox{grid-template-columns:a}@media (max-width:900px){.inbox{grid-template-columns:1fr}}@media (max-width:1180px){.inbox{grid-template-columns:b}}";
  assert.equal(lastAt(old, ".inbox", "grid-template-columns", 390), "b");
  assert.equal(lastAt("@container (max-width:40rem){.inbox{grid-template-columns:c}}.inbox{grid-template-columns:d}", ".inbox", "grid-template-columns", 390), "d");
});

test("between a phone and PANEL_BESIDE the contact panel is a drawer, and the Inbox opens without it there", () => {
  // As a third column at 1100 it left the conversation 252px (M-F2). The drawer's range and the width
  // each Inbox opens the panel from are one number: PANEL_BESIDE in messages.tsx is the drawer's max + 1.
  const beside = Number(/const PANEL_BESIDE = (\d+);/.exec(readFileSync(new URL("../src/views/messages.tsx", import.meta.url), "utf8"))?.[1]);
  assert.ok(beside > 900, `PANEL_BESIDE is ${beside}`);
  for (const w of [901, 1100, 1280, beside - 1]) {
    assert.equal(lastAt(css, ".inbox .panel", "position", w), "absolute", `the panel at ${w}`);
    assert.equal(lastAt(css, ".inbox", "grid-template-columns", w), "300px minmax(0,1fr)", `the columns at ${w}`);
    assert.equal(lastAt(css, ".panel .back", "display", w), "inline-flex", `the drawer's close at ${w}`);
  }
  for (const w of [beside, 1440]) {
    assert.equal(lastAt(css, ".inbox .panel", "position", w), null, `the panel at ${w} is a column`);
    assert.equal(lastAt(css, ".panel .back", "display", w), "none", `no close button beside the conversation at ${w}`);
  }
  assert.equal(lastAt(css, ".inbox .panel", "position", 390), null, "a phone's panel is a pane of its own");
});

test("on a phone nothing pins itself over the page, and what fills a row is said in less", () => {
  // The Exposure save bar was 590px of an 844px phone, pinned over the list it saves (S-F10).
  assert.equal(lastAt(css, ".card.sticky", "position", 390), "static");
  assert.equal(lastAt(css, ".card.sticky", "position", 1440), "sticky");
  // The composer's foot-note took five lines under the box on a phone (S-F7).
  assert.equal(lastAt(css, ".thread .foot-note", "display", 390), "none");
  assert.notEqual(lastAt(css, ".thread .foot-note", "display", 1440), "none");
  // Twelve action chips were five rows before the first entry (S-F4): a phone gets two selects instead.
  assert.equal(lastAt(css, ".chip-pick", "display", 1440), "none");
  assert.equal(lastAt(css, ".chips.has-picks .chip-pick", "display", 390), "inline-block");
  assert.equal(lastAt(css, ".chips.has-picks .chip.picked", "display", 390), "none");
  assert.equal(lastAt(css, ".chips.phone-pick", "display", 390), "none");
  assert.equal(lastAt(css, ".chips.phone-pick", "display", 1440), null);
  // A tab bar wider than a phone scrolls rather than running off it (S-F9); the + sheet's tiles line up
  // by their tops (S-C3).
  assert.equal(lastAt(css, ".tabs", "overflow-x", 390), "auto");
  assert.equal(lastAt(css, ".plusmenu", "align-items", 1440), "start");
});

// A good state is quiet (the design review: 'ok' in the brand accent read as one family with the amber of
// 'pending', so a trail of successes read as a page of warnings). Colour is for waiting and refused.
test("an ok pill is not coloured, and online is not the brand's orange beside away's amber", () => {
  const ok = rules(css).filter(([sel]) => sel.split(",").map((x) => x.trim()).includes(".pill.ok"));
  assert.ok(ok.length > 0, "no .pill.ok rule");
  for (const [, d] of ok) {
    for (const prop of ["background", "color"]) {
      const v = value(d, prop) ?? "";
      assert.ok(!/accent|amber|red/.test(v), `.pill.ok ${prop}: ${v}`);
    }
  }
  const online = rules(css).filter(([sel]) => sel === ".dot.online").map(([, d]) => value(d, "background"));
  const away = rules(css).filter(([sel]) => sel === ".dot.away").map(([, d]) => value(d, "background"));
  assert.ok(online.length > 0 && away.length > 0);
  for (const v of online) assert.ok(!/accent|amber/.test(v), `.dot.online: ${v}`);
  // Its colour is set for both themes.
  const tokens = rules(css).filter(([sel, d]) => sel === ":root" && value(d, "--online"));
  assert.equal(tokens.length, 2, "--online is set for light and for dark");
});

test("a number column's cells and heading are right-aligned together", () => {
  const num = rules(css).filter(([sel, d]) => /\btd\.num\b/.test(sel) && /\bth\.num\b/.test(sel) && value(d, "text-align") === "right");
  assert.ok(num.length > 0, "no rule aligns td.num and th.num right");
});

test("the presets' grid is a grid on a screen and wrapping chips on a phone", () => {
  // A screen: the head shows, each cell is a bare checkbox (the permission's name is the column's), and
  // a grid wider than the page scrolls in its own box (.table-wrap), not the page.
  assert.equal(lastAt(css, ".preset-grid > table > thead", "display", 1280), null);
  assert.equal(lastAt(css, ".preset-grid .pg-chip-t", "display", 1280), "none");
  assert.equal(lastAt(css, ".table-wrap", "overflow-x", 1280), "auto");
  // A phone: no head, each preset a card of chips that wrap, each chip saying its permission and
  // standing one line high.
  assert.equal(lastAt(css, ".preset-grid > table > thead", "display", 390), "none");
  assert.equal(lastAt(css, ".preset-grid > table > tbody > tr", "display", 390), "flex");
  assert.equal(lastAt(css, ".preset-grid > table > tbody > tr", "flex-wrap", 390), "wrap");
  assert.equal(lastAt(css, ".preset-grid .pg-chip-t", "display", 390), "inline");
  assert.equal(lastAt(css, ".preset-grid .pg-chip", "white-space", 390), "nowrap");
  // A row's buttons are ui.tsx's Actions with `inline`: a row of their own width beside the preset's
  // name on a phone, where every other row of actions is a full-width stack.
  assert.equal(lastAt(css, ".acts", "flex-direction", 390), "column-reverse");
  assert.equal(lastAt(css, ".acts.inline", "flex-direction", 390), "row");
  assert.equal(lastAt(css, ".acts.inline", "width", 390), "auto");
  // The phone's rules end at 480: at 481 it is the grid again.
  assert.equal(lastAt(css, ".preset-grid .pg-chip-t", "display", 481), "none");
});

/** Every input the browser draws as a text field, as a selector: no `type` is type text. */
export const TEXT_FIELDS = [':not([type])', '[type="text"]', '[type="number"]', '[type="password"]', '[type="url"]',
  '[type="email"]', '[type="search"]', '[type="tel"]', '[type="datetime-local"]'];

test("every rule for a text field names every text field, an input with no type among them", () => {
  let seen = 0;
  for (const [sel] of rules(css)) {
    const list = sel.split(",").map((s) => s.trim());
    for (const s of list) {
      const at = s.lastIndexOf('input[type="text"]');
      if (at < 0 || at + 'input[type="text"]'.length !== s.length) continue;
      seen++;
      const ctx = s.slice(0, at);
      const missing = TEXT_FIELDS.filter((t) => !list.includes(`${ctx}input${t}`));
      assert.deepEqual(missing, [], `${JSON.stringify(sel.slice(0, 80))} misses ${missing.join(" ")}`);
    }
  }
  // The control: the sheet's base rule, its phone rule and the schema form's were all read.
  assert.ok(seen >= 3, `only ${seen} text-field rules were found`);
});
