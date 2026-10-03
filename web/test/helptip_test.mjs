// The help tip (src/help.tsx, its rules src/helptip.ts, its looks style.css's `.tip-*`): the one `?`
// both portals put beside a short line, with the longer explanation behind it. What it must do, held
// here without a browser (BatonDeck's e2e/portal-layout.mjs holds the same in Chrome):
//   - open on hover, on focus and on a click or tap; close on Escape, on a press outside, on blur;
//   - a second click or tap closes it, even while it still has focus (the phone's tap-to-toggle);
//   - stay inside a 320px viewport, flipping above its button when there is no room below;
//   - be reachable by keyboard and named to a screen reader (a real button, aria-describedby);
//   - move nothing on the page when it opens (fixed, portalled; a button of one size).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { TIP_CLOSED, tipOpen, tipPlace, tipReduce } from "../src/helptip.ts";
import { rules } from "./style_test.mjs";

const run = (...events) => events.reduce(tipReduce, TIP_CLOSED);

test("hover, focus and click each open the tip", () => {
  assert.equal(tipOpen(TIP_CLOSED), false);
  assert.equal(tipOpen(run("enter")), true, "hover");
  assert.equal(tipOpen(run("focus")), true, "focus");
  assert.equal(tipOpen(run("click")), true, "click");
});

test("leaving, blurring, Escape and a press outside close it", () => {
  assert.equal(tipOpen(run("enter", "leave")), false, "leave");
  assert.equal(tipOpen(run("focus", "blur")), false, "blur");
  assert.equal(tipOpen(run("focus", "enter", "escape")), false, "Escape while focused and hovered");
  assert.equal(tipOpen(run("click", "outside")), false, "outside a pinned tip");
  assert.equal(tipOpen(run("click", "blur")), false, "tabbing away from a pinned tip");
});

test("a tap opens and a second tap closes, though the button keeps focus", () => {
  // A tap focuses the button, then clicks it.
  const once = run("focus", "click");
  assert.equal(tipOpen(once), true);
  assert.equal(tipOpen(tipReduce(once, "click")), false);
  // Keyboard: Tab opens, Enter pins, Enter closes, Escape after that stays closed.
  assert.equal(tipOpen(run("focus", "click", "click", "escape")), false);
});

test("a click keeps open what hover showed; Escape does not stick past the next open", () => {
  assert.equal(tipOpen(run("enter", "click", "leave")), true, "pinned by the click");
  assert.equal(tipOpen(run("focus", "escape", "blur", "focus")), true, "focus again after Escape");
  assert.equal(tipOpen(run("enter", "escape", "leave", "enter")), true, "hover again after Escape");
});

test("the popover stays inside a 320px viewport, flipping above when there is no room below", () => {
  const view = { width: 320, height: 568 };
  const tip = { width: 304, height: 120 }; // max-width: calc(100vw - 16px)
  for (const x of [0, 40, 150, 290, 302]) {
    for (const y of [10, 200, 520]) {
      const anchor = { left: x, right: x + 18, top: y, bottom: y + 18 };
      const p = tipPlace(anchor, tip, view);
      assert.ok(p.left >= 8 && p.left + tip.width <= view.width - 8, `left ${p.left} at x=${x}`);
      assert.ok(p.top >= 8 && p.top + tip.height <= view.height - 8, `top ${p.top} at y=${y}`);
      if (y === 520) assert.equal(p.side, "above", "no room below the button");
      if (y === 10) assert.equal(p.side, "below");
    }
  }
  // A narrow tip sits centred on its button.
  const c = tipPlace({ left: 150, right: 168, top: 100, bottom: 118 }, { width: 100, height: 40 }, view);
  assert.equal(c.left, 109);
});

const src = readFileSync(new URL("../src/help.tsx", import.meta.url), "utf8");

test("the tip is a real button that names its popover to a screen reader", () => {
  assert.match(src, /<button\b[^>]*\btype="button"/, "a button that never submits the form it sits in");
  assert.match(src, /<button\b[^>]*\baria-describedby=\{id\}/, "the button is described by the popover");
  assert.match(src, /<span\b[^>]*\bid=\{id\}[^>]*\brole="tooltip"/, "the popover carries the id and the tooltip role");
  assert.match(src, /hidden=\{!open\}/, "the popover is in the document while closed, hidden");
  assert.match(src, /e\.key === "Escape"\) send\("escape"\)/, "Escape closes it");
  assert.match(src, /onFocus=\{\(\) => send\("focus"\)\}/, "focus opens it");
  assert.match(src, /onClick=\{\(\) => send\("click"\)\}/, "a click or tap toggles it");
  assert.match(src, /pointerType !== "mouse"/, "hover is a mouse's; a tap is a click");
  assert.match(src, /createPortal\(/, "portalled, so no scroll box clips it");
});

test("opening the tip moves nothing: a fixed popover, a button of one size, the theme's colours", () => {
  const sheet = rules(readFileSync(new URL("../src/style.css", import.meta.url), "utf8"));
  const decl = (sel) => sheet.filter(([s]) => s === sel).map(([, d]) => d).join(";");
  assert.match(decl(".tip-pop"), /position:fixed/);
  assert.match(decl(".tip-pop"), /max-width:min\([^;]*calc\(100vw - 16px\)\)/);
  assert.match(decl("button.tip-btn"), /width:18px/);
  assert.match(decl("button.tip-btn"), /height:18px/);
  // The open state changes colour only, never size.
  const open = decl('button.tip-btn:hover,button.tip-btn[aria-expanded="true"]');
  assert.ok(open && !/width|height|padding|margin|border-width|font/.test(open.replace(/border-color/g, "")), open);
  // Both themes: every colour is a token brand.css redefines for dark.
  for (const d of [decl(".tip-pop"), decl("button.tip-btn"), open]) {
    for (const m of d.matchAll(/(?:^|;)\s*(color|background|border(?:-color)?)\s*:\s*([^;]+)/g)) {
      assert.ok(/var\(--/.test(m[2]) || m[2] === "none", `${m[1]}:${m[2]} is not a theme token`);
    }
  }
});
