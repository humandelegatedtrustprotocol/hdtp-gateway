// A rig for presets.ts's presetAutosave, run with no DOM: a clock the test moves, and a save that
// answers when the test says. Kept beside presets_test.mjs; BatonDeck's portal/test/preset-grid.test.ts
// drives the same module the same way.
import { presetAutosave } from "../src/presets.ts";

export function rig(saved) {
  let now = 0;
  const due = [];
  const clock = {
    set: (fn, ms) => { const h = { at: now + ms, fn }; due.push(h); return h; },
    clear: (h) => { const i = due.indexOf(h); if (i >= 0) due.splice(i, 1); },
  };
  const calls = [];
  const r = {
    saved,
    calls,
    redraws: 0,
    /** Move the clock by `ms`, firing whatever came due, in order. */
    tick(ms) {
      const end = now + ms;
      for (;;) {
        due.sort((a, b) => a.at - b.at);
        const h = due[0];
        if (!h || h.at > end) break;
        due.shift();
        now = h.at;
        h.fn();
      }
      now = end;
    },
    /** Let the answered saves' callbacks run. */
    settle: () => new Promise((res) => setTimeout(res, 0)),
  };
  r.rows = presetAutosave({
    saved: () => r.saved,
    save: (name, perms) => new Promise((resolve, reject) => {
      calls.push({ name, perms: [...perms], ok: (next) => { r.saved = next ?? r.saved.map((p) => (p.name === name ? { name, perms: [...perms] } : p)); resolve(); }, no: reject });
    }),
    changed: () => { r.redraws++; },
    clock,
  });
  r.perms = (name) => r.rows.perms(name, r.saved);
  return r;
}
